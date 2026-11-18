//go:build integration && linux

package kernelfacts

import (
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Reading the host: small files, owners, commands, and the state a run of
// the tests must leave as it found it.

// kernelRelease is the release string every fact carries.
var kernelRelease = sync.OnceValue(func() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "unknown (" + err.Error() + ")"
	}
	return unix.ByteSliceToString(u.Release[:])
})

// corePattern is the setting K7 replaces for a moment.
const corePattern = "/proc/sys/kernel/core_pattern"

// readTrim reads a small file without its surrounding white space.
func readTrim(path string) (string, error) {
	b, err := os.ReadFile(path)
	return strings.TrimSpace(string(b)), err
}

// readOr reads a small file for a detail. An unreadable file becomes a note
// that says so, never an empty string that would read as a value.
func readOr(path string) string {
	s, err := readTrim(path)
	if err != nil {
		return "unreadable (" + errnoName(err) + ")"
	}
	return s
}

// contentOf returns the exact content of a small file, or the errno.
func contentOf(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return errnoName(err)
	}
	return string(b)
}

// exists reports whether a path can be seen with lstat.
func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// ownerOf prints the owner of a path as "uid:gid", or the errno.
func ownerOf(path string) string {
	fi, err := os.Lstat(path)
	if err != nil {
		return errnoName(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	return fmt.Sprintf("%d:%d", st.Uid, st.Gid)
}

// fill grows one file until the kernel refuses or most bytes are written.
// It returns the bytes written and what stopped it.
func fill(path string, most int64) (int64, string) {
	f, err := os.Create(path)
	if err != nil {
		return 0, "create: " + errnoName(err)
	}
	defer f.Close()
	chunk := make([]byte, 64<<10)
	for i := range chunk {
		chunk[i] = byte(i) // not a hole, not all zeroes
	}
	var written int64
	for written < most {
		n, err := f.Write(chunk)
		written += int64(n)
		if err != nil {
			return written, errnoName(err)
		}
	}
	return written, "no error"
}

// commandOutput runs a command for a detail: its output, or what went wrong.
func commandOutput(name string, args ...string) string {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Sprintf("%s failed: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out))
}

// firstLine runs a command and keeps the first line of what it prints.
func firstLine(name string, args ...string) string {
	line, _, _ := strings.Cut(commandOutput(name, args...), "\n")
	return line
}

// Details are sentences: these print the usual "nothing went wrong".

// orOK prints a step result where "" means success.
func orOK(s string) string {
	if s == "" {
		return "ok"
	}
	return s
}

// orNothing prints a difference where "" means none.
func orNothing(s string) string {
	if s == "" {
		return "nothing"
	}
	return s
}

// errOrOK prints an error where nil means success.
func errOrOK(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

// valueOr prints a value, or why there is none.
func valueOr(value string, err error) string {
	if err != nil {
		return "not readable: " + errnoName(err)
	}
	return value
}

// since is the time elapsed, in milliseconds.
func since(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1000
}

// millis prints a duration in milliseconds with one decimal.
func millis(d time.Duration) string {
	return fmt.Sprintf("%.1f ms", float64(d.Microseconds())/1000)
}

// loopNames lists the loop devices that exist, attached or not.
func loopNames() []string {
	paths, _ := filepath.Glob("/sys/block/loop*")
	var out []string
	for _, p := range paths {
		out = append(out, filepath.Base(p))
	}
	return out
}

// boundLoops lists the loop devices that have a backing file.
func boundLoops() map[string]string {
	out := map[string]string{}
	paths, _ := filepath.Glob("/sys/block/loop*/loop/backing_file")
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue // released while we were looking
		}
		out[filepath.Base(filepath.Dir(filepath.Dir(p)))] = strings.TrimSpace(string(b))
	}
	return out
}

// helpersNow lists the processes that run this test binary, other than the
// test process itself. Namespaces live as long as a process is in them, so
// an empty list also means that no namespace of a test survives.
func helpersNow() string {
	self, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return "cannot read /proc/self/exe: " + err.Error()
	}
	var out []string
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		if exe, err := os.Readlink(filepath.Join("/proc", e.Name(), "exe")); err != nil || exe != self {
			continue
		}
		cmdline, _ := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		out = append(out, fmt.Sprintf("pid %d (%s)", pid, strings.ReplaceAll(strings.TrimRight(string(cmdline), "\x00"), "\x00", " ")))
	}
	return strings.Join(out, "; ")
}

// mntNamespaceMembers lists the processes whose mount namespace is the
// given one ("mnt:[4026532301]").
func mntNamespaceMembers(link string) []int {
	var out []int
	entries, _ := os.ReadDir("/proc")
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if l, err := os.Readlink(filepath.Join("/proc", e.Name(), "ns", "mnt")); err == nil && l == link {
			out = append(out, pid)
		}
	}
	return out
}

// watchedSysctls are the settings a test of this package writes, or would
// write if a mechanism of the design leaked into the host.
var watchedSysctls = []string{
	"kernel/core_pattern",
	"net/ipv4/ip_forward",
	"fs/inotify/max_user_instances",
	"user/max_user_namespaces",
	"user/max_inotify_instances",
}

// hostState is what TestMain records before the first test: everything a
// test could leave behind in the host.
type hostState struct {
	mounts  string
	cgroups []string          // groups directly under the root
	subtree string            // cgroup.subtree_control of the root
	loops   map[string]string // attached loop devices and their backing files
	sysctls map[string]string
}

func rootCgroups() []string {
	entries, _ := os.ReadDir(cgroupRoot)
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	slices.Sort(out)
	return out
}

func snapshotHost() hostState {
	st := hostState{
		mounts:  mountinfoText(),
		cgroups: rootCgroups(),
		subtree: readOr(filepath.Join(cgroupRoot, "cgroup.subtree_control")),
		loops:   boundLoops(),
		sysctls: map[string]string{},
	}
	for _, name := range watchedSysctls {
		st.sysctls[name] = readOr("/proc/sys/" + name)
	}
	return st
}

// settled gives a difference a few seconds to go away: the kernel finishes
// some releases (a mount, a loop device) after the process that held them
// is gone.
func settled(diff func() string) string {
	var d string
	poll(3*time.Second, func() bool {
		d = diff()
		return d == ""
	})
	return d
}

// The comparisons below come in two forms: one that looks now, and one that
// first gives the kernel a few seconds (settled).

// mountsDiff says how the mount table of the host differs from the snapshot.
func (base hostState) mountsDiff() string {
	return settled(func() string { return lineDiff(base.mounts, mountinfoText()) })
}

// cgroupsDiff is cgroupsDiffNow once things had time to settle.
func (base hostState) cgroupsDiff(afterTeardown bool) string {
	return settled(func() string { return base.cgroupsDiffNow(afterTeardown) })
}

// cgroupsDiffNow says which groups appeared or went under the root. While
// the tests run, the parent group of this run may exist, with nothing in
// it; after the teardown it may not.
//
// The controllers the root hands down are not part of the verdict: a
// transient unit with Delegate=yes, which K4 starts, makes systemd turn
// controllers on and off there on its own schedule. subtreeNote reports
// them, and removeCgParent answers for the ones this run enabled itself.
func (base hostState) cgroupsDiffNow(afterTeardown bool) string {
	own := ownCgroupName()
	var out []string
	now := rootCgroups()
	if i := slices.Index(now, own); i >= 0 {
		now = slices.Delete(now, i, i+1)
		if afterTeardown {
			out = append(out, "left behind: "+filepath.Join(cgroupRoot, own))
		}
		left, _ := filepath.Glob(filepath.Join(cgroupRoot, own, "*", "cgroup.procs"))
		for _, p := range left {
			out = append(out, "left behind: "+filepath.Dir(p))
		}
	}
	if d := lineDiff(strings.Join(base.cgroups, "\n"), strings.Join(now, "\n")); d != "" {
		out = append(out, "groups under the root: "+d)
	}
	return strings.Join(out, "; ")
}

// subtreeNote says how the controllers the root hands down differ from the
// snapshot, for a detail. It is not a verdict (see cgroupsDiffNow).
func (base hostState) subtreeNote() string {
	now := readOr(filepath.Join(cgroupRoot, "cgroup.subtree_control"))
	if now == base.subtree {
		return "unchanged"
	}
	return fmt.Sprintf("went from %q to %q", base.subtree, now)
}

// loopsDiff is loopsDiffNow once things had time to settle.
func (base hostState) loopsDiff() string { return settled(base.loopsDiffNow) }

// loopsDiffNow says which loop devices gained or lost a backing file.
func (base hostState) loopsDiffNow() string {
	now := boundLoops()
	var out []string
	for _, name := range slices.Sorted(maps.Keys(now)) {
		if was, ok := base.loops[name]; !ok {
			out = append(out, fmt.Sprintf("%s is now attached to %s", name, now[name]))
		} else if was != now[name] {
			out = append(out, fmt.Sprintf("%s was attached to %s, is attached to %s", name, was, now[name]))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(base.loops)) {
		if _, ok := now[name]; !ok {
			out = append(out, fmt.Sprintf("%s was attached to %s, is detached", name, base.loops[name]))
		}
	}
	return strings.Join(out, "; ")
}

// sysctlsDiff says which watched setting changed.
func (base hostState) sysctlsDiff() string {
	var out []string
	for _, name := range watchedSysctls {
		if now := readOr("/proc/sys/" + name); now != base.sysctls[name] {
			out = append(out, fmt.Sprintf("%s: was %q, is %q", name, base.sysctls[name], now))
		}
	}
	return strings.Join(out, "; ")
}

// strayHelpers is helpersNow once the helpers had time to go.
func strayHelpers() string { return settled(helpersNow) }
