//go:build integration && linux

package kernelfacts

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// K4: the worker.
//
// A worker serves one connection. It runs in its own mount namespace
// (CLONE_NEWNS, then MS_REC|MS_SLAVE on /) and in its own cgroup subtree.
// Two things follow that the design counts on and that were never run:
// nothing a worker mounts is ever visible to the host, and when a worker
// dies, however it dies, the kernel takes its mounts with it.
//
// The worker is started by the service's own acceptor, not by systemd, so
// the namespace and the cgroup layout made with plain system calls are what
// is required here. What a systemd scope with Delegate=yes gives is
// recorded, for the unit the service itself runs in.

// k4Ready is what the worker holds while the test looks at the host.
type k4Ready struct {
	MountNS string   `json:"mount_ns"` // its mount namespace
	Mounts  []string `json:"mounts"`   // its own mounts, as its mountinfo lists them
	Marker  string   `json:"marker"`   // a lower file read through its overlay
}

const k4Marker = "from the lower layer"

// childK4Worker mounts an overlay and a tmpfs in a private mount namespace
// and waits to be killed. args: directory.
func childK4Worker(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: k4worker DIR")
	}
	if err := privateMounts(); err != nil {
		return err
	}
	o, err := makeOverlay(filepath.Join(args[0], "ovl"))
	if err != nil {
		return err
	}
	if err := writeTree(o.lower, tree{"marker": "f:" + k4Marker}); err != nil {
		return err
	}
	if err := o.mount(overlayOpts); err != nil {
		return err
	}
	tmp := filepath.Join(args[0], "tmp")
	if err := os.Mkdir(tmp, 0o755); err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", tmp, "tmpfs", unix.MS_NODEV|unix.MS_NOSUID, "size=1m"); err != nil {
		return fmt.Errorf("mount a tmpfs on %s: %w", tmp, err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "marker"), []byte("on the tmpfs"), 0o644); err != nil {
		return err
	}

	rdy := k4Ready{MountNS: nsLink("mnt")}
	entries := parseMountinfo(mountinfoText())
	for _, p := range []string{o.merged, tmp} {
		if e, ok := mountAt(entries, p); ok {
			rdy.Mounts = append(rdy.Mounts, e.fstype+" on "+p)
		}
	}
	b, _ := os.ReadFile(filepath.Join(o.merged, "marker"))
	rdy.Marker = string(b)
	if err := sayReady(rdy); err != nil {
		return err
	}
	waitRelease()
	return nil
}

// childK4Probe tells whether the upper directory of the worker's overlay is
// still in use by a live mount. With index=on the kernel refuses such an
// upper directory with EBUSY; with index=off it would only warn in its log.
// args: directory.
func childK4Probe(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: k4probe DIR")
	}
	if err := privateMounts(); err != nil {
		return err
	}
	o, err := makeOverlay(filepath.Join(args[0], "ovl"))
	if err != nil {
		return err
	}
	err = o.mount("index=on")
	if err == nil {
		_ = o.unmount()
	}
	return sayResult(map[string]string{"mount": errnoName(err)})
}

// k4UpperInUse runs the probe and returns "ok", an errno name, or the reason
// the probe itself did not run.
func k4UpperInUse(t *testing.T, dir string) string {
	t.Helper()
	var rep struct {
		Mount string `json:"mount"`
	}
	if err := runChild(t, spawn{name: "k4probe", args: []string{dir}, clone: unix.CLONE_NEWNS}, &rep); err != nil {
		return "probe failed: " + err.Error()
	}
	return rep.Mount
}

// k4Mounts records K4-mounts and K4-kill.
func k4Mounts(t *testing.T, r *recorder) {
	t.Helper()
	dir := scratch(t, "k4")
	before := mountinfoText()
	c, err := spawnChild(t, spawn{name: "k4worker", args: []string{dir}, clone: unix.CLONE_NEWNS})
	if err != nil {
		r.no("K4-mounts", "a helper in a new mount namespace did not start: %v", err)
		return
	}
	var rdy k4Ready
	if err := c.ready(&rdy); err != nil {
		r.no("K4-mounts", "the worker did not mount its overlay and its tmpfs: %v", err)
		return
	}
	during := mountinfoText()
	// What the worker sees through its mounts, the host must not see at
	// the same paths.
	hostSees := exists(filepath.Join(dir, "ovl", "merged", "marker")) || exists(filepath.Join(dir, "tmp", "marker"))
	own := nsLink("mnt")
	workerOK := len(rdy.Mounts) == 2 && rdy.Marker == k4Marker && rdy.MountNS != "" && rdy.MountNS != own
	// While the worker lives, its upper directory is in use.
	busy := k4UpperInUse(t, dir)

	killed := time.Now()
	c.kill()
	after := mountinfoText()

	d1, d2 := lineDiff(before, during), lineDiff(before, after)
	r.judge("K4-mounts", workerOK && !hostSees && before == during && before == after,
		"the worker, in %s (the host is in %s), lists %v and reads %q through its overlay; the host sees the worker's files at those paths: %v; host mountinfo changed while they were mounted: %s; changed after SIGKILL: %s",
		rdy.MountNS, own, rdy.Mounts, rdy.Marker, hostSees, orNothing(d1), orNothing(d2))

	// After the kill: nobody is left in the namespace, and the kernel has
	// released the upper directory.
	var members []int
	empty := poll(2*time.Second, func() bool {
		members = mntNamespaceMembers(rdy.MountNS)
		return len(members) == 0
	})
	if busy != "EBUSY" {
		// The probe cannot tell on this filesystem: say so, and judge on
		// the namespace alone.
		r.judge("K4-kill", empty,
			"processes left in %s 2 s after SIGKILL: %v; the in-use probe (overlay with index=on on the same upper directory) answered %q while the worker was alive, where EBUSY was expected, so it proves nothing here",
			rdy.MountNS, members, busy)
		return
	}
	last := ""
	released := poll(2*time.Second, func() bool {
		last = k4UpperInUse(t, dir)
		return last == "ok"
	})
	r.judge("K4-kill", empty && released,
		"processes left in %s after SIGKILL: %v; mounting an overlay with index=on on the worker's upper directory answered EBUSY while it lived and %s within %s of the kill (each probe is a new process; limit 2 s)",
		rdy.MountNS, members, last, millis(time.Since(killed)))
}

// k4Cgroup records K4-cgroup.
func k4Cgroup(t *testing.T, r *recorder) {
	t.Helper()
	tr, err := newCgTree(t, "k4")
	if err != nil {
		r.no("K4-cgroup", "the layout parent/session/leaf could not be created under %s: %v", cgroupRoot, err)
		return
	}
	// The limits of the design: memory and pids on the session, pids again
	// on the leaf.
	limits := errors.Join(
		cgWrite(tr.session, "memory.max", "268435456"),
		cgWrite(tr.session, "memory.oom.group", "1"),
		cgWrite(tr.session, "cpu.max", "50000 100000"),
		cgWrite(tr.session, "pids.max", "64"),
		cgWrite(tr.leaf, "pids.max", "32"),
	)
	swap := errnoName(cgWrite(tr.session, "memory.swap.max", "0"))

	c, err := spawnChild(t, spawn{name: "cgreport", cgroup: tr.leaf})
	if err != nil {
		r.no("K4-cgroup", "clone3 with CLONE_INTO_CGROUP into %s failed: %v; controllers of the leaf: %v", tr.leaf, err, cgFields(tr.leaf, "cgroup.controllers"))
		return
	}
	var rdy struct {
		Cgroup string `json:"cgroup"`
	}
	if err := c.ready(&rdy); err != nil {
		r.no("K4-cgroup", "the process cloned into the leaf did not report: %v", err)
		return
	}
	procs := cgProcs(tr.leaf)
	want := "0::" + strings.TrimPrefix(tr.leaf, cgroupRoot)
	missing := missingControllers(tr.leaf)
	r.judge("K4-cgroup", len(missing) == 0 && limits == nil && rdy.Cgroup == want && slices.Equal(procs, []int{c.pid()}),
		"controllers of the leaf: %v (missing: %v); limits written: %s; memory.swap.max=0: %s; the cloned process reads %q from /proc/self/cgroup (expected %q); cgroup.procs of the leaf: %v (expected [%d])",
		cgFields(tr.leaf, "cgroup.controllers"), missing, errOrOK(limits), swap, rdy.Cgroup, want, procs, c.pid())
	c.stop()
}

// k4ScopeReport is what a process found inside a systemd scope started
// with Delegate=yes.
type k4ScopeReport struct {
	Path        string            `json:"path"`        // its cgroup
	Controllers []string          `json:"controllers"` // cgroup.controllers of the scope
	Move        string            `json:"move"`        // moving itself into a child group
	Enable      map[string]string `json:"enable"`      // enabling each controller for the children of the scope
	Child       []string          `json:"child"`       // cgroup.controllers of a new child group
	Undo        string            `json:"undo"`        // putting the scope back as systemd made it
}

// childK4Scope runs inside the scope. A group that holds processes cannot
// hand controllers to its children, so it first moves itself into a child
// group, as the service will.
func childK4Scope([]string) error {
	path, err := ownCgroup()
	if err != nil {
		return err
	}
	dir := filepath.Join(cgroupRoot, path)
	pid := strconv.Itoa(os.Getpid())
	rep := k4ScopeReport{Path: path, Controllers: cgFields(dir, "cgroup.controllers"), Enable: map[string]string{}}

	supervisor := filepath.Join(dir, "supervisor")
	if err := os.Mkdir(supervisor, 0o755); err != nil {
		rep.Move = "mkdir: " + errnoName(err)
	} else {
		rep.Move = errnoName(cgWrite(supervisor, "cgroup.procs", pid))
	}
	for _, c := range wantControllers {
		rep.Enable[c] = errnoName(cgWrite(dir, "cgroup.subtree_control", "+"+c))
	}
	session := filepath.Join(dir, "session")
	if err := os.Mkdir(session, 0o755); err == nil {
		rep.Child = cgFields(session, "cgroup.controllers")
		_ = unix.Rmdir(session)
	}

	// Put the scope back as systemd made it.
	var undo []error
	for _, c := range wantControllers {
		undo = append(undo, cgWrite(dir, "cgroup.subtree_control", "-"+c))
	}
	undo = append(undo, cgWrite(dir, "cgroup.procs", pid), unix.Rmdir(supervisor))
	rep.Undo = errOrOK(errors.Join(undo...))
	return sayResult(rep)
}

// k4Scope records K4-scope.
func k4Scope(t *testing.T, r *recorder) {
	t.Helper()
	run, err := exec.LookPath("systemd-run")
	if err != nil || !exists("/run/systemd/system") {
		r.skip("K4-scope", "systemd does not run this host, or systemd-run is not installed")
		return
	}
	version, _, _ := strings.Cut(commandOutput(run, "--version"), "\n")
	unit := fmt.Sprintf("sandmeter-kf-%d-k4.scope", os.Getpid())
	var rep k4ScopeReport
	err = runChild(t, spawn{
		name: "k4scope",
		wrap: []string{run, "--scope", "--quiet", "--collect", "--unit=" + unit, "--property=Delegate=yes"},
	}, &rep)
	if err != nil {
		r.no("K4-scope", "%s: systemd-run --scope --property=Delegate=yes did not run the helper: %v", version, err)
		return
	}
	if !strings.HasSuffix(rep.Path, "/"+unit) {
		r.no("K4-scope", "%s: the helper ran in %q, not in the scope %s", version, rep.Path, unit)
		return
	}
	enabled := true
	for _, c := range wantControllers {
		enabled = enabled && rep.Enable[c] == "ok" && slices.Contains(rep.Child, c)
	}
	// The scope ends with its only process; nothing of it may stay.
	scopeDir := filepath.Join(cgroupRoot, rep.Path)
	gone := poll(5*time.Second, func() bool { return !exists(scopeDir) })
	if !gone {
		_ = exec.Command("systemctl", "stop", unit).Run()
		if !poll(5*time.Second, func() bool { return !exists(scopeDir) }) {
			t.Errorf("the scope %s is still there after systemctl stop: %s", unit, scopeDir)
		}
	}
	r.judge("K4-scope", rep.Move == "ok" && enabled,
		"%s; scope at %s with cgroup.controllers %v; moving the process into a child group: %s; enabling for the children: cpu %s, memory %s, pids %s; a new child group gets %v; scope put back: %s; scope removed by systemd within 5 s of the exit: %v",
		version, rep.Path, rep.Controllers, rep.Move, rep.Enable["cpu"], rep.Enable["memory"], rep.Enable["pids"], rep.Child, rep.Undo, gone)
}

func TestK4WorkerIsolation(t *testing.T) {
	r := declare(t, "K4-mounts", "K4-kill", "K4-cgroup", "K4-scope")
	r.needRoot()
	k4Mounts(t, r)
	r.needCgroup2()
	k4Cgroup(t, r)
	k4Scope(t, r)
}
