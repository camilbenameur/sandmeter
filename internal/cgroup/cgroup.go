// Package cgroup manages cgroup v2 groups for sandboxed commands.
//
// One Group holds one sandbox. Limits are written when the group is created,
// the command is started inside it with clone3(CLONE_INTO_CGROUP) so it never
// runs outside the limits, and Kill/Remove tear it down without races.
package cgroup

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/camilbenameur/sandmeter/sandbox"
)

// DefaultParent is the cgroup under which sandbox groups are created.
const DefaultParent = "/sys/fs/cgroup/sandmeter"

const (
	cpuPeriod = 100000
	// The kernel rejects a cpu.max quota under 1ms.
	minQuota = 1000
	// maxQuota mirrors the kernel's MAX_BW (2^44 - 1 microseconds).
	maxQuota = 1<<44 - 1

	pollInterval = 5 * time.Millisecond
	rmdirRetries = 20
	rmdirDelay   = 10 * time.Millisecond
)

// controllers are the ones a sandbox group needs.
var controllers = []string{"cpu", "memory", "pids"}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// Group is one cgroup v2 directory.
type Group struct {
	Path string
	// Notes are caveats found while setting limits, such as missing swap accounting.
	Notes []string

	rmdir func(string) error // nil means unix.Rmdir; tests replace it
}

// EnsureParent creates path if needed and enables the cpu, memory and pids
// controllers for the groups below it. path becomes a pure parent: the
// "no internal processes" rule means it must hold no process itself.
func EnsureParent(path string) (err error) {
	merr := os.Mkdir(path, 0o755)
	if merr != nil && !errors.Is(merr, fs.ErrExist) {
		return fmt.Errorf("create cgroup parent: %w", merr)
	}
	if merr == nil {
		// Do not leave an empty cgroup behind when a later check fails.
		defer func() {
			if err != nil {
				_ = unix.Rmdir(path)
			}
		}()
	}
	// The controllers must be delegated by path's own parent first, otherwise
	// path has no cgroup.controllers to hand down.
	if err := enableControllers(filepath.Dir(path)); err != nil {
		return err
	}
	procs, err := readFile(path, "cgroup.procs")
	if err != nil {
		return err
	}
	if strings.TrimSpace(procs) != "" {
		return fmt.Errorf("cgroup %s holds processes and cannot be a parent of controlled groups", path)
	}
	return enableControllers(path)
}

// enableControllers adds the missing controllers of the list to dir's
// cgroup.subtree_control, after checking the kernel offers them.
func enableControllers(dir string) error {
	avail, err := readFile(dir, "cgroup.controllers")
	if err != nil {
		return err
	}
	have := strings.Fields(avail)
	var missing []string
	for _, c := range controllers {
		if !contains(have, c) {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("cgroup controllers %s not available in %s (cgroup.controllers: %q); "+
			"on a systemd host delegate them or run from a unit with Delegate=yes",
			strings.Join(missing, ", "), dir, strings.TrimSpace(avail))
	}
	cur, err := readFile(dir, "cgroup.subtree_control")
	if err != nil {
		return err
	}
	enabled := strings.Fields(cur)
	var add []string
	for _, c := range controllers {
		if !contains(enabled, c) {
			add = append(add, "+"+c)
		}
	}
	if len(add) == 0 {
		return nil
	}
	if err := writeFile(dir, "cgroup.subtree_control", strings.Join(add, " ")); err != nil {
		return fmt.Errorf("enable controllers in %s: %w", dir, err)
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// New creates the group parent/name and applies the limits. It fails if the
// group already exists, so two sandboxes never share one by accident.
func New(parent, name string, l sandbox.Limits) (*Group, error) {
	return newGroup(parent, name, l, func(p string) error { return os.Mkdir(p, 0o755) }, nil)
}

func newGroup(parent, name string, l sandbox.Limits, mkdir, rmdir func(string) error) (*Group, error) {
	if !nameRE.MatchString(name) || name == "." || name == ".." {
		return nil, fmt.Errorf("invalid cgroup name %q: want [A-Za-z0-9_.-]{1,64} other than \".\" and \"..\"", name)
	}
	if err := validateLimits(l); err != nil {
		return nil, err
	}
	g := &Group{Path: filepath.Join(parent, name), rmdir: rmdir}
	if err := mkdir(g.Path); err != nil {
		return nil, fmt.Errorf("create cgroup %s: %w", g.Path, err)
	}
	if err := g.applyLimits(l); err != nil {
		if rerr := g.removeDir(); rerr != nil {
			err = fmt.Errorf("%w (cleanup also failed: %v)", err, rerr)
		}
		return nil, err
	}
	return g, nil
}

func validateLimits(l sandbox.Limits) error {
	switch {
	case l.CPU < 0 || math.IsNaN(l.CPU) || math.IsInf(l.CPU, 0):
		return fmt.Errorf("invalid cpu limit %v", l.CPU)
	case l.MemoryBytes < 0:
		return fmt.Errorf("invalid memory limit %d", l.MemoryBytes)
	case l.PIDs < 0:
		return fmt.Errorf("invalid pids limit %d", l.PIDs)
	}
	_, err := cpuMax(l.CPU)
	return err
}

// cpuMax formats the cpu.max value for a number of cores.
func cpuMax(cpu float64) (string, error) {
	if cpu == 0 {
		return fmt.Sprintf("max %d", cpuPeriod), nil
	}
	// Rounding first keeps 0.07 cores from becoming 7001 because of float error.
	if cpu*cpuPeriod > maxQuota {
		return "", fmt.Errorf("cpu limit %v is too large (kernel maximum is %d microseconds of quota per period)", cpu, int64(maxQuota))
	}
	quota := int64(math.Ceil(math.Round(cpu*cpuPeriod*1e3) / 1e3))
	if quota < minQuota {
		return "", fmt.Errorf("cpu limit %v is below the kernel minimum of %v cores", cpu, float64(minQuota)/cpuPeriod)
	}
	return fmt.Sprintf("%d %d", quota, cpuPeriod), nil
}

func (g *Group) applyLimits(l sandbox.Limits) error {
	cpu, err := cpuMax(l.CPU)
	if err != nil {
		return err
	}
	if err := writeFile(g.Path, "cpu.max", cpu); err != nil {
		return err
	}

	mem := "max"
	if l.MemoryBytes > 0 {
		mem = strconv.FormatInt(l.MemoryBytes, 10)
	}
	if err := writeFile(g.Path, "memory.max", mem); err != nil {
		return err
	}
	if l.MemoryBytes > 0 {
		// Without this, a process over the limit could spill into swap and
		// escape the cap. The file is absent when swap accounting is off.
		err := writeFile(g.Path, "memory.swap.max", "0")
		if errors.Is(err, fs.ErrNotExist) {
			g.Notes = append(g.Notes, "memory.swap.max not available: swap accounting is off, swap use is not limited")
		} else if err != nil {
			return err
		}
	}
	// One OOM victim would leave the rest of a half-dead sandbox running.
	if err := writeFile(g.Path, "memory.oom.group", "1"); err != nil {
		return err
	}

	pids := "max"
	if l.PIDs > 0 {
		pids = strconv.FormatInt(l.PIDs, 10)
	}
	return writeFile(g.Path, "pids.max", pids)
}

// Open returns a handle for SysProcAttr{UseCgroupFD: true, CgroupFD: int(f.Fd())}.
// The caller closes it once the child has started.
func (g *Group) Open() (*os.File, error) {
	fd, err := unix.Open(g.Path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open cgroup %s: %w", g.Path, err)
	}
	return os.NewFile(uintptr(fd), g.Path), nil
}

// Stats reads the counters of the group. Files that only exist on newer
// kernels (memory.peak, pids.peak, pids.events) read as zero when absent.
func (g *Group) Stats() (sandbox.CgroupStats, error) {
	var st sandbox.CgroupStats
	var err error

	if st.MemoryPeakBytes, err = optionalInt(g.Path, "memory.peak"); err != nil {
		return st, err
	}
	if st.PIDsPeak, err = optionalInt(g.Path, "pids.peak"); err != nil {
		return st, err
	}
	mem, err := readFlat(g.Path, "memory.events")
	if err != nil {
		return st, err
	}
	st.OOMKills = mem["oom_kill"]
	cpu, err := readFlat(g.Path, "cpu.stat")
	if err != nil {
		return st, err
	}
	st.CPUUsageUsec = cpu["usage_usec"]
	pe, err := readFlat(g.Path, "pids.events")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return st, err
	}
	st.PIDsMaxHits = pe["max"]
	return st, nil
}

// optionalInt reads a single-integer file, returning 0 if the kernel lacks it.
func optionalInt(dir, name string) (int64, error) {
	v, err := readInt(dir, name)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	return v, err
}

// Kill kills every process of the group and waits until it is empty or ctx ends.
// A group that no longer exists counts as already killed.
func (g *Group) Kill(ctx context.Context) error {
	if _, err := os.Stat(g.Path); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	// cgroup.kill (Linux 5.14) is atomic: nothing can fork away from it.
	// Older kernels get a best-effort loop over cgroup.procs.
	manual := false
	if err := writeFile(g.Path, "cgroup.kill", "1"); err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		manual = true
	}
	return waitUnpopulated(ctx, g.Path, pollInterval, manual)
}

// waitUnpopulated polls cgroup.events until the group holds no process.
// With manual set it also sends SIGKILL to the listed processes on every pass.
func waitUnpopulated(ctx context.Context, dir string, every time.Duration, manual bool) error {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if manual {
			killProcs(dir)
		}
		ev, err := readFlat(dir, "cgroup.events")
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil // removed under us
			}
			return err
		}
		v, ok := ev["populated"]
		if !ok {
			return fmt.Errorf("cgroup.events of %s has no populated key", dir)
		}
		if v == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for cgroup %s to empty: %w", dir, ctx.Err())
		case <-t.C:
		}
	}
}

func killProcs(dir string) {
	s, err := readFile(dir, "cgroup.procs")
	if err != nil {
		return
	}
	for _, f := range strings.Fields(s) {
		// pid 0 and negatives would signal our own process group.
		if pid, err := strconv.Atoi(f); err == nil && pid > 0 {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}

// Remove kills the group's processes and deletes the directory.
func (g *Group) Remove(ctx context.Context) error {
	if err := g.Kill(ctx); err != nil {
		return err
	}
	return retryRemove(ctx, g.removeDir, rmdirRetries, rmdirDelay)
}

func (g *Group) removeDir() error {
	rm := g.rmdir
	if rm == nil {
		rm = unix.Rmdir
	}
	if err := rm(g.Path); err != nil {
		return fmt.Errorf("remove cgroup %s: %w", g.Path, err)
	}
	return nil
}

// retryRemove retries on EBUSY: right after the last process exits the
// kernel may still be releasing it, and rmdir fails for a short moment.
// A directory that is already gone is success, so Remove is idempotent.
func retryRemove(ctx context.Context, rm func() error, tries int, delay time.Duration) error {
	var err error
	for i := 0; i < tries; i++ {
		err = rm()
		if err == nil || errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if !errors.Is(err, unix.EBUSY) {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w (context: %v)", err, ctx.Err())
		case <-time.After(delay):
		}
	}
	return err
}
