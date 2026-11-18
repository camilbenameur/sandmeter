//go:build integration && linux

package kernelfacts

import (
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// K6: gVisor with a user namespace.
//
// Today's backend gives runsc no user namespace, so the Sentry and the
// gofer are host root. The design adds an OCI user namespace that maps 0 to
// the shifted uid, and hands the workspace overlay to runsc as an OCI bind
// mount. Both ship only if this test proves them: a file the workload
// writes must be owned by the shifted uid on the host, and the overlay,
// mounted by the worker in its own mount namespace, must work through the
// bind. Otherwise gVisor is "preview: network none, no project".

// k6Written is the file the probe creates on each writable mount.
const k6Written = "written-inside"

const (
	k6LowerContent = "from the lower layer"
	k6SubContent   = "in a mount under the root path"
)

// k6Layout is where everything of the test lives under its directory.
type k6Layout struct {
	bundle string  // OCI bundle: config.json
	rootfs string  // root.path, owned by the shifted uid
	work   string  // bind-mounted read-write at /work
	subSrc string  // bind-mounted by the worker on rootfs/sub before runsc starts
	ovl    overlay // mounted by the worker; its merged directory is bound at /ovl
	state  string  // runsc --root
	logs   string  // runsc --debug-log
}

func k6Paths(dir string) k6Layout {
	o := filepath.Join(dir, "ovl")
	return k6Layout{
		bundle: filepath.Join(dir, "bundle"),
		rootfs: filepath.Join(dir, "rootfs"),
		work:   filepath.Join(dir, "work"),
		subSrc: filepath.Join(dir, "sub"),
		ovl: overlay{
			lower:  filepath.Join(o, "lower"),
			upper:  filepath.Join(o, "upper"),
			work:   filepath.Join(o, "work"),
			merged: filepath.Join(o, "merged"),
		},
		state: filepath.Join(dir, "state"),
		logs:  filepath.Join(dir, "logs"),
	}
}

// isStatic reports whether an ELF file needs no loader.
func isStatic(path string) (bool, error) {
	f, err := elf.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return false, nil
		}
	}
	return true, nil
}

// copyFile copies a file and gives the copy the mode.
func copyFile(dst, src string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// k6Prepare creates the directories as the service would: what the sandbox
// may write belongs to the shifted uid, the rest to root. Every directory
// on the way can be searched by the shifted uid (scratch).
func k6Prepare(lay k6Layout) error {
	shifted := []string{
		lay.rootfs, lay.work, lay.ovl.lower, lay.ovl.upper,
		filepath.Join(lay.rootfs, "proc"), filepath.Join(lay.rootfs, "dev"), filepath.Join(lay.rootfs, "tmp"),
		filepath.Join(lay.rootfs, "work"), filepath.Join(lay.rootfs, "ovl"), filepath.Join(lay.rootfs, "sub"),
		filepath.Join(lay.rootfs, "kf"),
	}
	rootOwned := []string{lay.bundle, lay.subSrc, lay.ovl.work, lay.ovl.merged, lay.state, lay.logs}
	for _, d := range append(slices.Clone(shifted), rootOwned...) {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	probe := filepath.Join(lay.rootfs, "kf", "probe")
	if err := copyFile(probe, "/proc/self/exe", 0o755); err != nil {
		return fmt.Errorf("copy the test binary into the root filesystem: %w", err)
	}
	lowerFile := filepath.Join(lay.ovl.lower, "lower.txt")
	if err := os.WriteFile(lowerFile, []byte(k6LowerContent), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(lay.subSrc, "marker"), []byte(k6SubContent), 0o644); err != nil {
		return err
	}
	for _, p := range append(shifted, probe, lowerFile) {
		if err := os.Lchown(p, idShift, idShift); err != nil {
			return err
		}
	}
	cfg, err := k6Config(lay)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(lay.bundle, "config.json"), cfg, 0o644)
}

// k6Config is the OCI runtime configuration: today's, plus a user namespace
// with the mapping of the design and the two bind mounts under test.
func k6Config(lay k6Layout) ([]byte, error) {
	caps := []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL",
		"CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE", "CAP_SYS_CHROOT", "CAP_AUDIT_WRITE"}
	ids := []map[string]int{{"containerID": 0, "hostID": idShift, "size": idRange}}
	cfg := map[string]any{
		"ociVersion": "1.0.2",
		"process": map[string]any{
			"terminal":        false,
			"user":            map[string]int{"uid": 0, "gid": 0},
			"args":            []string{"/kf/probe", childArg, "k6probe"},
			"env":             []string{"PATH=/usr/bin:/bin"},
			"cwd":             "/",
			"capabilities":    map[string][]string{"bounding": caps, "effective": caps, "permitted": caps},
			"noNewPrivileges": true,
		},
		"root":     map[string]any{"path": lay.rootfs, "readonly": false},
		"hostname": "kernelfacts",
		"mounts": []map[string]any{
			{"destination": "/proc", "type": "proc", "source": "proc"},
			{"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
			{"destination": "/work", "type": "bind", "source": lay.work, "options": []string{"rbind", "rw"}},
			{"destination": "/ovl", "type": "bind", "source": lay.ovl.merged, "options": []string{"rbind", "rw"}},
		},
		"linux": map[string]any{
			"namespaces": []map[string]string{
				{"type": "pid"}, {"type": "ipc"}, {"type": "uts"}, {"type": "mount"}, {"type": "network"}, {"type": "user"},
			},
			"uidMappings": ids,
			"gidMappings": ids,
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// k6ProbeReport is what the process inside the sandbox saw.
type k6ProbeReport struct {
	UID        int    `json:"uid"`         // its own uid
	UIDMap     string `json:"uid_map"`     // /proc/self/uid_map as the sandbox shows it
	RootOwner  string `json:"root_owner"`  // owner of /
	Write      string `json:"write"`       // creating a file on the bind-mounted directory
	WriteOwner string `json:"write_owner"` // its owner, seen from inside
	Submount   string `json:"submount"`    // the marker under the mount below the root path
	Lower      string `json:"lower"`       // the lower file, through the bound overlay
	OvlWrite   string `json:"ovl_write"`   // creating a file through the bound overlay
	Released   string `json:"released"`    // how its wait ended
}

// childK6Probe runs inside the sandbox, as its only process.
func childK6Probe([]string) error {
	rep := k6ProbeReport{
		UID:       os.Getuid(),
		UIDMap:    strings.Join(strings.Fields(contentOf("/proc/self/uid_map")), " "),
		RootOwner: ownerOf("/"),
	}
	rep.Write = errnoName(os.WriteFile("/work/"+k6Written, []byte("written inside"), 0o644))
	rep.WriteOwner = ownerOf("/work/" + k6Written)
	rep.Submount = contentOf("/sub/marker")
	rep.Lower = contentOf("/ovl/lower.txt")
	rep.OvlWrite = errnoName(os.WriteFile("/ovl/"+k6Written, []byte("written inside"), 0o644))

	// Stay until the test has looked at the host processes that run this
	// sandbox. It then closes our standard input and creates /work/release;
	// either is enough, and the wait is bounded in case neither arrives.
	eof := make(chan struct{})
	go func() {
		waitRelease()
		close(eof)
	}()
	started := time.Now()
	rep.Released = "nothing within 30 s"
	for time.Since(started) < 30*time.Second {
		select {
		case <-eof:
			rep.Released = fmt.Sprintf("end-of-file on standard input after %s", millis(time.Since(started)))
		case <-time.After(20 * time.Millisecond):
			if !exists("/work/release") {
				continue
			}
			rep.Released = fmt.Sprintf("/work/release seen after %s", millis(time.Since(started)))
		}
		break
	}
	return sayResult(rep)
}

// k6WorkerReport is what the stand-in for the worker reports.
type k6WorkerReport struct {
	Runsc  string          `json:"runsc"`           // how runsc run ended
	Probe  json.RawMessage `json:"probe,omitempty"` // the probe's result, absent when it printed none
	Stderr string          `json:"stderr"`          // end of runsc's standard error
	Logs   string          `json:"logs"`            // end of each runsc debug log
}

// k6Logs returns the end of each debug log runsc wrote.
func k6Logs(dir string) string {
	var out []string
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		out = append(out, fmt.Sprintf("== %s ==\n%s", e.Name(), tail(string(b), 3000)))
	}
	return strings.Join(out, "\n")
}

// childK6Worker does what the worker does: it mounts the overlay in its own
// mount namespace and runs runsc from there. args: directory, runsc, id.
func childK6Worker(args []string) error {
	if len(args) != 3 {
		return errors.New("usage: k6worker DIR RUNSC ID")
	}
	dir, runsc, id := args[0], args[1], args[2]
	if err := privateMounts(); err != nil {
		return err
	}
	lay := k6Paths(dir)
	if err := lay.ovl.mount(overlayOpts); err != nil {
		return err
	}
	sub := filepath.Join(lay.rootfs, "sub")
	if err := unix.Mount(lay.subSrc, sub, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind %s on %s: %w", lay.subSrc, sub, err)
	}

	outPath, errPath := filepath.Join(dir, "runsc.stdout"), filepath.Join(dir, "runsc.stderr")
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()
	errf, err := os.Create(errPath)
	if err != nil {
		return err
	}
	defer errf.Close()

	// The flags of the backend (network none, writes straight to the host
	// directories), plus debug logs for the day this fails.
	global := []string{
		"--root=" + lay.state,
		"--debug", "--debug-log=" + lay.logs + "/",
		"--platform=systrap",
		"--network=none",
		"--overlay2=none",
	}
	cmd := exec.Command(runsc, append(slices.Clone(global), "run", "--bundle="+lay.bundle, id)...)
	cmd.Stdin = os.Stdin // the probe waits for end-of-file on it
	cmd.Stdout, cmd.Stderr = out, errf
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	rep := k6WorkerReport{Runsc: errOrOK(cmd.Run())}
	_ = exec.Command(runsc, append(slices.Clone(global), "delete", "--force", id)...).Run()

	data, _ := os.ReadFile(outPath)
	if p, ok := findLine(data, "result "); ok {
		rep.Probe = json.RawMessage(p)
	}
	rep.Stderr = tail(contentOf(errPath), 2000)
	rep.Logs = k6Logs(lay.logs)
	return sayResult(rep)
}

// k6Proc is one host process of the sandbox.
type k6Proc struct {
	pid  int
	role string // "sentry", "gofer" or "other"
	comm string
	args string
	uids []string // real, effective, saved, filesystem
}

func (p k6Proc) String() string {
	return fmt.Sprintf("%s pid %d (%s: %s) uids %s", p.role, p.pid, p.comm, p.args, strings.Join(p.uids, "/"))
}

// k6Processes describes the processes of the leaf other than the worker:
// runsc and what it started.
func k6Processes(leaf string, worker int) []k6Proc {
	var out []k6Proc
	for _, pid := range cgProcs(leaf) {
		if pid == worker {
			continue
		}
		dir := fmt.Sprintf("/proc/%d", pid)
		p := k6Proc{pid: pid, role: "other", comm: readOr(filepath.Join(dir, "comm"))}
		cmdline, _ := os.ReadFile(filepath.Join(dir, "cmdline"))
		argv := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
		p.args = tail(strings.Join(argv, " "), 160)
		status, _ := os.ReadFile(filepath.Join(dir, "status"))
		for _, line := range strings.Split(string(status), "\n") {
			if f := strings.Fields(line); len(f) == 5 && f[0] == "Uid:" {
				p.uids = f[1:]
			}
		}
		// runsc re-executes itself with the role as a sub-command and
		// renames the process after it.
		switch {
		case slices.Contains(argv, "boot") || strings.Contains(p.comm, "sandbox") || strings.Contains(p.comm, "sentry"):
			p.role = "sentry"
		case slices.Contains(argv, "gofer") || strings.Contains(p.comm, "gofer"):
			p.role = "gofer"
		}
		out = append(out, p)
	}
	return out
}

func TestK6RunscUIDMappings(t *testing.T) {
	r := declare(t, "K6-owner", "K6-bind", "K6-uids", "K6-submount")
	r.needRoot()
	runsc, err := exec.LookPath("runsc")
	r.need("runsc", err == nil, "runsc is not installed (not found in PATH)")
	static, err := isStatic("/proc/self/exe")
	r.need("runsc", err == nil && static, "the test binary is dynamically linked and cannot be the process inside the sandbox: build it with CGO_ENABLED=0")
	// The leaf is how the test finds the processes of the sandbox, and how
	// it is sure to kill them.
	r.needCgroup2()

	version, _, _ := strings.Cut(commandOutput(runsc, "--version"), "\n")
	dir := scratch(t, "k6")
	lay := k6Paths(dir)
	id := fmt.Sprintf("kernelfacts-%d", os.Getpid())
	if err := k6Prepare(lay); err != nil {
		r.no("K6-owner", "the bundle could not be prepared: %v", err)
		return
	}
	tr, err := newCgTree(t, "k6")
	if err != nil {
		r.no("K6-owner", "the cgroup layout could not be created: %v", err)
		return
	}
	c, err := spawnChild(t, spawn{name: "k6worker", args: []string{dir, runsc, id}, clone: unix.CLONE_NEWNS, cgroup: tr.leaf})
	if err != nil {
		r.no("K6-owner", "the worker that runs runsc did not start: %v", err)
		return
	}

	// The probe writes this file first; the sandbox is then up, and stays
	// up until it is released.
	written := filepath.Join(lay.work, k6Written)
	poll(20*time.Second, func() bool {
		select {
		case <-c.exited:
			return true
		default:
			return exists(written)
		}
	})
	procs := k6Processes(tr.leaf, c.pid())
	if err := os.WriteFile(filepath.Join(lay.work, "release"), nil, 0o644); err != nil {
		t.Errorf("release file: %v", err)
	}
	c.release()

	var rep k6WorkerReport
	if err := c.result(&rep); err != nil {
		r.no("K6-owner", "%s: the worker that runs runsc did not complete: %v", version, err)
		return
	}
	var probe k6ProbeReport
	if len(rep.Probe) == 0 || json.Unmarshal(rep.Probe, &probe) != nil {
		t.Logf("runsc standard error:\n%s\nrunsc debug logs:\n%s", rep.Stderr, rep.Logs)
		r.no("K6-owner", "%s: the process inside the sandbox reported nothing; runsc run ended with: %s; end of its standard error: %s",
			version, rep.Runsc, tail(rep.Stderr, 600))
		return
	}
	if rep.Runsc != "ok" {
		t.Logf("runsc run ended with %s; standard error:\n%s\nrunsc debug logs:\n%s", rep.Runsc, rep.Stderr, rep.Logs)
	}

	shifted := fmt.Sprintf("%d:%d", idShift, idShift)
	hostOwner := ownerOf(written)
	r.judge("K6-owner", probe.Write == "ok" && hostOwner == shifted,
		"%s, platform systrap, uid map \"0 %d %d\"; inside: uid %d, uid_map %q, / owned by %s, write on the bind mount: %s, the file owned by %s; on the host that file is owned by %s (expected %s)",
		version, idShift, idRange, probe.UID, probe.UIDMap, probe.RootOwner, probe.Write, probe.WriteOwner, hostOwner, shifted)

	upperOwner := ownerOf(filepath.Join(lay.ovl.upper, k6Written))
	r.judge("K6-bind", probe.Lower == k6LowerContent && probe.OvlWrite == "ok" && upperOwner == shifted,
		"overlay mounted by the worker in its mount namespace and given to runsc as an rbind mount; inside: the lower file reads %q (expected %q), a write answers %s; on the host the upper directory holds that file owned by %s (expected %s)",
		probe.Lower, k6LowerContent, probe.OvlWrite, upperOwner, shifted)

	r.judge("K6-submount", probe.Submount == k6SubContent,
		"a bind mount placed on a directory of the root path before runsc started; its file reads %q inside (expected %q)", probe.Submount, k6SubContent)

	var sentries, gofers, wrong int
	var listed []string
	for _, p := range procs {
		listed = append(listed, p.String())
		if p.role == "other" {
			continue
		}
		if p.role == "sentry" {
			sentries++
		} else {
			gofers++
		}
		if !slices.Equal(p.uids, []string{fmt.Sprint(idShift), fmt.Sprint(idShift), fmt.Sprint(idShift), fmt.Sprint(idShift)}) {
			wrong++
		}
	}
	if len(procs) == 0 {
		r.skip("K6-uids", "no process of the sandbox was running when the test looked; the probe says its wait ended with: %s", probe.Released)
		return
	}
	r.judge("K6-uids", sentries > 0 && gofers > 0 && wrong == 0,
		"expected the Sentry and the gofer with all four uids equal to %d; host processes of the sandbox: %s", idShift, strings.Join(listed, "; "))
}

// The bundle of K6 is what the design says it is.
func TestSelfK6Bundle(t *testing.T) {
	lay := k6Paths("/var/lib/x")
	raw, err := k6Config(lay)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Process struct {
			Args []string `json:"args"`
		} `json:"process"`
		Root struct {
			Path string `json:"path"`
		} `json:"root"`
		Mounts []struct {
			Destination string   `json:"destination"`
			Type        string   `json:"type"`
			Source      string   `json:"source"`
			Options     []string `json:"options"`
		} `json:"mounts"`
		Linux struct {
			Namespaces []struct {
				Type string `json:"type"`
				Path string `json:"path"`
			} `json:"namespaces"`
			UIDMappings []struct {
				ContainerID, HostID, Size int64
			} `json:"uidMappings"`
			GIDMappings []struct {
				ContainerID, HostID, Size int64
			} `json:"gidMappings"`
		} `json:"linux"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cfg.Process.Args, []string{"/kf/probe", childArg, "k6probe"}) || cfg.Root.Path != lay.rootfs {
		t.Errorf("process %v in root %s", cfg.Process.Args, cfg.Root.Path)
	}
	kinds := map[string]string{}
	for _, ns := range cfg.Linux.Namespaces {
		kinds[ns.Type] = ns.Path
	}
	// A network namespace without a path is a new, empty one; runsc is also
	// told --network=none.
	for _, kind := range []string{"user", "network", "pid", "mount"} {
		if path, ok := kinds[kind]; !ok || path != "" {
			t.Errorf("namespace %s: present %v, path %q; want a new one", kind, ok, path)
		}
	}
	for name, m := range map[string][]struct{ ContainerID, HostID, Size int64 }{"uid": cfg.Linux.UIDMappings, "gid": cfg.Linux.GIDMappings} {
		if len(m) != 1 || m[0].ContainerID != 0 || m[0].HostID != idShift || m[0].Size != idRange {
			t.Errorf("%s mappings %+v, want one line 0 %d %d", name, m, idShift, idRange)
		}
	}
	binds := map[string]string{}
	for _, m := range cfg.Mounts {
		if m.Type == "bind" && slices.Contains(m.Options, "rbind") && slices.Contains(m.Options, "rw") {
			binds[m.Destination] = m.Source
		}
	}
	if want := map[string]string{"/work": lay.work, "/ovl": lay.ovl.merged}; !maps.Equal(binds, want) {
		t.Errorf("read-write rbind mounts %v, want %v", binds, want)
	}

	if _, err := isStatic("/proc/self/exe"); err != nil {
		t.Errorf("isStatic on the test binary: %v", err)
	}
	copied := filepath.Join(t.TempDir(), "probe")
	if err := copyFile(copied, "/proc/self/exe", 0o755); err != nil {
		t.Fatal(err)
	}
	self, err := os.Stat("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(copied); err != nil || fi.Size() != self.Size() || fi.Mode().Perm()&0o111 == 0 {
		t.Errorf("the copy of the test binary: %v, %v; want %d executable bytes", fi, err, self.Size())
	}
}

// The list of host processes K6 builds from a cgroup, on the group of this
// process: it is in the list, with the four uids of /proc/pid/status, and
// it is neither a Sentry nor a gofer.
func TestSelfK6Processes(t *testing.T) {
	if !haveCgroup2() {
		t.Skip("cgroup v2 is not mounted at " + cgroupRoot)
	}
	path, err := ownCgroup()
	if err != nil {
		t.Fatal(err)
	}
	uid := fmt.Sprint(os.Getuid())
	for _, p := range k6Processes(filepath.Join(cgroupRoot, path), -1) {
		if p.pid != os.Getpid() {
			continue
		}
		if p.role != "other" || !slices.Equal(p.uids, []string{uid, uid, uid, uid}) || p.comm == "" {
			t.Errorf("this process is described as: %v", p)
		}
		return
	}
	t.Errorf("k6Processes does not list this process")
}
