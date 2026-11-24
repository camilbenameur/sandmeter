//go:build integration && linux

package kernelfacts

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Cgroup v2: reading its files, and building the layout of the design
// under a parent group that belongs to this run.

// cgroupRoot is where the design expects the unified hierarchy.
const cgroupRoot = "/sys/fs/cgroup"

// wantControllers are the controllers of a session group.
var wantControllers = []string{"cpu", "memory", "pids"}

// haveCgroup2 reports whether the unified hierarchy is mounted where the
// design expects it.
func haveCgroup2() bool {
	var st unix.Statfs_t
	return unix.Statfs(cgroupRoot, &st) == nil && st.Type == unix.CGROUP2_SUPER_MAGIC
}

// ownCgroup is the cgroup v2 path of this process.
func ownCgroup() (string, error) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			return p, nil
		}
	}
	return "", fmt.Errorf("no cgroup v2 entry in /proc/self/cgroup: %q", b)
}

// cgFields reads a cgroup file as white-space separated words.
func cgFields(dir, file string) []string {
	b, _ := os.ReadFile(filepath.Join(dir, file))
	return strings.Fields(string(b))
}

// cgFlat reads a flat-keyed cgroup file ("max 3") as "max=3,forkfail=0", or
// "absent" when this kernel does not have the file.
func cgFlat(dir, file string) string {
	b, err := os.ReadFile(filepath.Join(dir, file))
	if errors.Is(err, fs.ErrNotExist) {
		return "absent"
	}
	if err != nil {
		return "unreadable (" + errnoName(err) + ")"
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		out = append(out, strings.Join(strings.Fields(line), "="))
	}
	return strings.Join(out, ",")
}

// cgCounter reads one key of a flat-keyed cgroup file, 0 when it is absent.
func cgCounter(dir, file, key string) int64 {
	b, _ := os.ReadFile(filepath.Join(dir, file))
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == key {
			n, _ := strconv.ParseInt(f[1], 10, 64)
			return n
		}
	}
	return 0
}

// cgInt reads a single-number cgroup file.
func cgInt(dir, file string) (int64, error) {
	s, err := readTrim(filepath.Join(dir, file))
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(s, 10, 64)
}

// cgWrite writes a value to a cgroup file. The file is opened without
// O_CREAT, so that one this kernel does not have answers ENOENT and not
// the refusal to create it.
func cgWrite(dir, file, value string) error {
	f, err := os.OpenFile(filepath.Join(dir, file), os.O_WRONLY, 0)
	if err == nil {
		_, err = f.Write([]byte(value))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		return fmt.Errorf("write %q to %s of %s: %w", value, file, dir, err)
	}
	return nil
}

// cgProcs lists the processes of one group, as the test's pid namespace
// numbers them.
func cgProcs(dir string) []int {
	var out []int
	for _, f := range cgFields(dir, "cgroup.procs") {
		if pid, err := strconv.Atoi(f); err == nil {
			out = append(out, pid)
		}
	}
	return out
}

// missingControllers lists which of cpu, memory and pids a group lacks.
func missingControllers(dir string) []string {
	have := cgFields(dir, "cgroup.controllers")
	var missing []string
	for _, c := range wantControllers {
		if !slices.Contains(have, c) {
			missing = append(missing, c)
		}
	}
	return missing
}

// cgEnable hands cpu, memory and pids down to the children of dir.
func cgEnable(dir string) error {
	have := cgFields(dir, "cgroup.subtree_control")
	for _, c := range wantControllers {
		if slices.Contains(have, c) {
			continue
		}
		if err := cgWrite(dir, "cgroup.subtree_control", "+"+c); err != nil {
			return fmt.Errorf("%w (cgroup.controllers there: %q)", err, cgFields(dir, "cgroup.controllers"))
		}
	}
	return nil
}

// cgRemove kills what is in a group and removes it. A group that is not
// there is removed already.
func cgRemove(dir string) error {
	if !exists(dir) {
		return nil
	}
	// cgroup.kill (Linux 5.14) takes the whole subtree; the kernels this
	// package is written for all have it.
	if err := cgWrite(dir, "cgroup.kill", "1"); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	var last error
	gone := poll(5*time.Second, func() bool {
		// rmdir answers EBUSY while the last process is still being released.
		last = unix.Rmdir(dir)
		return last == nil || errors.Is(last, fs.ErrNotExist)
	})
	if !gone {
		return fmt.Errorf("remove cgroup %s: %w (cgroup.procs: %v)", dir, last, cgProcs(dir))
	}
	return nil
}

// cgParentState is the one group under which every test builds its own.
var cgParentState struct {
	once  sync.Once
	dir   string
	err   error
	added []string // controllers this run enabled in the root group
}

// cgParent creates, once, an empty parent group directly under the root
// and hands the three controllers down to it. The root group may hold
// processes and children at the same time; no other group may.
func cgParent() (string, error) {
	st := &cgParentState
	st.once.Do(func() {
		have := cgFields(cgroupRoot, "cgroup.subtree_control")
		for _, c := range wantControllers {
			if slices.Contains(have, c) {
				continue
			}
			if err := cgWrite(cgroupRoot, "cgroup.subtree_control", "+"+c); err != nil {
				st.err = fmt.Errorf("the root cgroup does not hand %s down: %w (its cgroup.controllers: %q)",
					c, err, cgFields(cgroupRoot, "cgroup.controllers"))
				return
			}
			st.added = append(st.added, c)
		}
		dir := filepath.Join(cgroupRoot, ownCgroupName())
		if err := os.Mkdir(dir, 0o755); err != nil {
			st.err = err
			return
		}
		st.dir = dir
		st.err = cgEnable(dir)
	})
	return st.dir, st.err
}

// ownCgroupName is the name of this run's parent group.
func ownCgroupName() string { return fmt.Sprintf("sandmeter-facts-%d", os.Getpid()) }

// removeCgParent undoes cgParent at the end of the run.
func removeCgParent() error {
	st := &cgParentState
	var errs []error
	if st.dir != "" {
		errs = append(errs, cgRemove(st.dir))
	}
	for _, c := range st.added {
		err := cgWrite(cgroupRoot, "cgroup.subtree_control", "-"+c)
		if errors.Is(err, unix.EBUSY) {
			// Another group uses the controller by now: it is no longer
			// this run's to turn off.
			continue
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// cgTree is the cgroup layout of the design for one session:
//
//	<dir>/s    the session group: limits, no process
//	<dir>/s/1  a leaf: one command and its init
type cgTree struct{ dir, session, leaf string }

// newCgTree builds the layout under the run's parent group and removes it,
// processes included, when the test ends.
func newCgTree(t *testing.T, name string) (*cgTree, error) {
	t.Helper()
	parent, err := cgParent()
	if err != nil {
		return nil, err
	}
	tr := &cgTree{dir: filepath.Join(parent, name)}
	tr.session = filepath.Join(tr.dir, "s")
	tr.leaf = filepath.Join(tr.session, "1")
	t.Cleanup(func() {
		for _, d := range []string{tr.leaf, tr.session, tr.dir} {
			if err := cgRemove(d); err != nil {
				t.Errorf("cleanup: %v", err)
			}
		}
	})
	for _, d := range []string{tr.dir, tr.session} {
		if err := os.Mkdir(d, 0o755); err != nil {
			return nil, err
		}
		if err := cgEnable(d); err != nil {
			return nil, err
		}
	}
	if err := os.Mkdir(tr.leaf, 0o755); err != nil {
		return nil, err
	}
	return tr, nil
}
