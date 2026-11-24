package testhost

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// recorder stands for a test: it records what Require and AssertClean do to
// it. Skipf and Fatalf end the calling function, as the real ones do.
type recorder struct {
	skipped, failed string
	errors          []string
	cleanups        []func()
}

type stop struct{}

func (r *recorder) Helper() {}
func (r *recorder) Skipf(format string, args ...any) {
	r.skipped = fmt.Sprintf(format, args...)
	panic(stop{})
}
func (r *recorder) Fatalf(format string, args ...any) {
	r.failed = fmt.Sprintf(format, args...)
	panic(stop{})
}
func (r *recorder) Errorf(format string, args ...any) {
	r.errors = append(r.errors, fmt.Sprintf(format, args...))
}
func (r *recorder) Cleanup(f func()) { r.cleanups = append(r.cleanups, f) }

// finish runs the clean-ups in the order a test runs them: last first.
func (r *recorder) finish() {
	for i := len(r.cleanups) - 1; i >= 0; i-- {
		r.cleanups[i]()
	}
}

// run calls f and reports whether it went to its end.
func run(f func()) (completed bool) {
	defer func() {
		if v := recover(); v != nil {
			if _, ok := v.(stop); !ok {
				panic(v)
			}
		}
	}()
	f()
	return true
}

// fakeHost is a machine with exactly the given properties.
func fakeHost(env string, root bool, files ...string) host {
	has := map[string]bool{}
	for _, f := range files {
		has[f] = true
	}
	return host{
		getenv: func(k string) string {
			if k == EnvRequire {
				return env
			}
			return ""
		},
		geteuid: func() int {
			if root {
				return 0
			}
			return 1000
		},
		readFile: func(p string) ([]byte, error) {
			if p == "/proc/filesystems" && has["overlay"] {
				return []byte("nodev\tsysfs\n\text4\nnodev\toverlay\n"), nil
			}
			if p == "/proc/filesystems" {
				return []byte("nodev\tsysfs\n\text4\nnodev\toverlayx\n"), nil
			}
			return nil, os.ErrNotExist
		},
		exists: func(p string) bool { return has[p] },
		lookPath: func(name string) (string, error) {
			if has["PATH:"+name] {
				return "/opt/bin/" + name, nil
			}
			return "", errors.New("not found")
		},
	}
}

const cgroupFile = "/sys/fs/cgroup/cgroup.controllers"

func TestRequire(t *testing.T) {
	everything := []string{cgroupFile, "overlay", "/usr/local/bin/runsc"}
	for _, tc := range []struct {
		name      string
		host      host
		need      []string
		completed bool
		skipped   string // substring of the skip message
		failed    string // substring of the failure message
	}{
		{name: "everything is there", host: fakeHost("", true, everything...), need: []string{Root, Cgroup2, Overlay, Runsc}, completed: true},
		{name: "nothing is needed", host: fakeHost("", false), completed: true},
		{name: "not root, not required: skip", host: fakeHost("", false, everything...), need: []string{Root, Cgroup2}, skipped: "needs root"},
		{name: "not root, required: fail", host: fakeHost("root", false, everything...), need: []string{Root, Cgroup2}, failed: `lacks the prerequisite "root"`},
		{name: "required by all", host: fakeHost("all", true, cgroupFile, "overlay"), need: []string{Root, Runsc}, failed: `lacks the prerequisite "runsc"`},
		{name: "another prerequisite is required: still a skip", host: fakeHost("root,cgroup2", true, cgroupFile), need: []string{Root, Overlay}, skipped: "needs overlay"},
		{name: "spaces and empty items in the variable", host: fakeHost(" root , ,cgroup2,", false), need: []string{Root}, failed: `lacks the prerequisite "root"`},
		{name: "no cgroup v2", host: fakeHost("", true), need: []string{Cgroup2}, skipped: "no cgroup v2 hierarchy"},
		{name: "a filesystem whose name only starts with overlay", host: fakeHost("", true), need: []string{Overlay}, skipped: "does not list the overlay filesystem"},
		{name: "runsc found through PATH", host: fakeHost("", true, "PATH:runsc"), need: []string{Runsc}, completed: true},
		{name: "runsc missing", host: fakeHost("", true), need: []string{Runsc}, skipped: "runsc is not installed"},
		{name: "the internet is never assumed", host: fakeHost("", true, everything...), need: []string{Internet}, skipped: "allowed only where"},
		{name: "the internet where the job says so", host: fakeHost("internet", true), need: []string{Internet}, completed: true},
		{name: "a misspelt prerequisite in the call", host: fakeHost("", true, everything...), need: []string{"rooot"}, failed: `"rooot" is not a prerequisite`},
		{name: "a misspelt prerequisite after a missing one", host: fakeHost("", false), need: []string{Root, "cgroups"}, failed: `"cgroups" is not a prerequisite`},
		{name: "a misspelt prerequisite in the variable", host: fakeHost("root,runc", true, everything...), need: []string{Root}, failed: `names "runc"`},
	} {
		before := passed.Load()
		rec := &recorder{}
		completed := run(func() { require(rec, tc.host, tc.need) })
		if completed != tc.completed {
			t.Errorf("%s: completed = %v, want %v (skip %q, failure %q)", tc.name, completed, tc.completed, rec.skipped, rec.failed)
		}
		if (tc.skipped == "") != (rec.skipped == "") || !strings.Contains(rec.skipped, tc.skipped) {
			t.Errorf("%s: skipped with %q, want %q", tc.name, rec.skipped, tc.skipped)
		}
		if (tc.failed == "") != (rec.failed == "") || !strings.Contains(rec.failed, tc.failed) {
			t.Errorf("%s: failed with %q, want %q", tc.name, rec.failed, tc.failed)
		}
		// Only a test that got past its prerequisites counts as having run.
		if got := passed.Load() - before; (got == 1) != tc.completed {
			t.Errorf("%s: counted %d tests as having run", tc.name, got)
		}
	}
}

func TestRequireOnThisHost(t *testing.T) {
	// The real probes agree with the obvious facts about this process.
	ok, _ := realHost.has(Root, nil)
	if ok != (os.Geteuid() == 0) {
		t.Errorf("has(root) = %v for euid %d", ok, os.Geteuid())
	}
	if _, why := realHost.has("nonsense", nil); why == "" {
		t.Error("an unknown prerequisite has no reason")
	}
}

func TestFinish(t *testing.T) {
	for _, tc := range []struct {
		name    string
		code    int
		env     string
		passed  int64
		want    int
		message string
	}{
		{name: "nothing required, nothing ran", want: 0},
		{name: "nothing required, tests ran", passed: 3, want: 0},
		{name: "required and ran", env: "root", passed: 1, want: 0},
		{name: "required and nothing got past Require", env: "root,cgroup2", want: 1, message: "nothing was verified"},
		{name: "all required and nothing ran", env: "all", want: 1, message: "nothing was verified"},
		{name: "a failing run keeps its status", code: 2, env: "root", want: 2},
		{name: "a misspelt variable fails even when tests ran", env: "rot", passed: 5, want: 1, message: `names "rot"`},
		{name: "a variable of spaces requires nothing", env: "  ", want: 0},
	} {
		var stderr strings.Builder
		if got := finish(tc.code, tc.env, tc.passed, &stderr); got != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, got, tc.want)
		}
		if (tc.message == "") != (stderr.Len() == 0) || !strings.Contains(stderr.String(), tc.message) {
			t.Errorf("%s: stderr %q, want %q", tc.name, stderr.String(), tc.message)
		}
	}
}

// write creates a file of a fixture tree, with its directories.
func write(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const mountinfo = `22 28 0:21 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
28 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,discard
31 28 0:5 / /dev rw,nosuid shared:2 - devtmpfs udev rw,size=4003244k
`

// fixture builds a host with one mount namespace, a cgroup parent, a
// network link, a loop device and this process with its parent.
func fixture(t *testing.T) Scope {
	t.Helper()
	root := t.TempDir()
	proc, sys := filepath.Join(root, "proc"), filepath.Join(root, "sys")
	write(t, proc, "self/mountinfo", mountinfo)
	write(t, proc, "1/mountinfo", mountinfo)
	write(t, proc, "1/stat", "1 (systemd) S 0 1 1 0 -1")
	write(t, proc, "50/stat", "50 (go) S 1 50 50 0 -1")
	write(t, proc, "100/stat", "100 (native.test) S 50 100 50 0 -1")
	write(t, proc, "uptime", "1.0 1.0")
	write(t, sys, "fs/cgroup/sandmeter/cgroup.procs", "")
	write(t, sys, "fs/cgroup/other/cgroup.procs", "")
	write(t, sys, "class/net/lo/mtu", "65536")
	write(t, sys, "block/loop0/size", "0")
	write(t, sys, "block/loop1/loop/backing_file", "/var/lib/snapd/snaps/core.snap\n")
	write(t, sys, "block/sda/size", "1")
	state := filepath.Join(root, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	return Scope{Proc: proc, Sys: sys, NetnsDir: filepath.Join(root, "netns"), StateRoots: []string{state}, Self: 100}
}

func TestTakeReadsTheHost(t *testing.T) {
	scope := fixture(t)
	s := Take(scope)
	if got := strings.Join(s.Mounts, "|"); got != "/ ext4 /dev/sda1|/dev devtmpfs udev|/sys sysfs sysfs" {
		t.Errorf("Mounts = %q", got)
	}
	if strings.Join(s.HostMounts, "|") != strings.Join(s.Mounts, "|") {
		t.Errorf("HostMounts = %q", s.HostMounts)
	}
	if len(s.Cgroups) != 0 || strings.Join(s.Links, "|") != "lo" || len(s.Netns) != 0 || len(s.State) != 0 {
		t.Errorf("snapshot of a quiet host: %+v", s)
	}
	// Only attached loop devices are listed.
	if strings.Join(s.Loops, "|") != "loop1 /var/lib/snapd/snaps/core.snap" {
		t.Errorf("Loops = %q", s.Loops)
	}
	// This process and its ancestors are not leftovers of a test.
	if len(s.Processes) != 0 {
		t.Errorf("Processes = %q", s.Processes)
	}
	if diff := s.Diff(Take(scope)); len(diff) != 0 {
		t.Errorf("two snapshots of an unchanged host differ: %v", diff)
	}
}

func TestDiffNamesEveryLeftover(t *testing.T) {
	scope := fixture(t)
	before := Take(scope)

	state := scope.StateRoots[0]
	// A mount in this namespace only, and the same mount point twice.
	write(t, scope.Proc, "self/mountinfo", mountinfo+
		"90 28 0:60 / "+state+"/s1/root rw,relatime - overlay overlay rw,lowerdir=/l,upperdir=/u,workdir=/w\n"+
		"91 28 0:61 / /mnt/x rw - tmpfs tmpfs rw\n92 28 0:62 / /mnt/x rw - tmpfs tmpfs rw\n")
	// A session cgroup with a leaf, a link, a named namespace, a loop
	// device, a helper process with a name full of traps, a state entry.
	write(t, scope.Sys, "fs/cgroup/sandmeter/00112233445566778899aabbccddeeff/1/cgroup.procs", "")
	write(t, scope.Sys, "fs/cgroup/other/elsewhere/cgroup.procs", "")
	write(t, scope.Sys, "class/net/veth0/mtu", "1500")
	write(t, scope.NetnsDir, "sandmeter-ns", "")
	write(t, scope.Sys, "block/loop0/loop/backing_file", state+"/s1/disk.img\n")
	write(t, scope.Proc, "200/stat", "200 (native.test) S 100 200 50 0 -1")
	write(t, scope.Proc, "201/stat", "201 (runsc-sandbox) S 1 201 201 0 -1")
	write(t, scope.Proc, "202/stat", "202 (a) b) (c) S 1 202 202 0 -1")
	write(t, scope.Proc, "203/stat", "203 (sandmeterd) S 1 203 203 0 -1")
	write(t, scope.Proc, "204/stat", "204 (bash) S 1 204 204 0 -1")
	write(t, state, "s1/owner", "")

	diff := before.Diff(Take(scope))
	want := []string{
		"+ mount: " + state + "/s1/root overlay overlay",
		"+ mount: /mnt/x tmpfs tmpfs",
		"+ mount: /mnt/x tmpfs tmpfs",
		"+ cgroup: sandmeter/00112233445566778899aabbccddeeff",
		"+ cgroup: sandmeter/00112233445566778899aabbccddeeff/1",
		"+ network link: veth0",
		"+ network namespace: sandmeter-ns",
		"+ loop device: loop0 " + state + "/s1/disk.img",
		"+ process: native.test (pid 200)",
		"+ process: runsc-sandbox (pid 201)",
		"+ process: sandmeterd (pid 203)",
		"+ state entry: " + state + "/s1",
	}
	// Kinds come in a fixed order, mounts first; within a kind the lines are
	// sorted, and where the temporary directory sorts depends on the machine.
	if len(diff) == 0 || !strings.HasPrefix(diff[0], "+ mount: ") || !strings.HasPrefix(diff[len(diff)-1], "+ state entry: ") {
		t.Errorf("the kinds are out of order: %v", diff)
	}
	sort.Strings(diff)
	sort.Strings(want)
	if strings.Join(diff, "\n") != strings.Join(want, "\n") {
		t.Errorf("Diff =\n%s\nwant\n%s", strings.Join(diff, "\n"), strings.Join(want, "\n"))
	}

	// Something that was there and is gone is a difference too.
	gone := Take(scope).Diff(before)
	if len(gone) != len(want) || !strings.HasPrefix(gone[0], "- mount: ") {
		t.Errorf("the reverse comparison: %v", gone)
	}
}

func TestSnapshotRecordsWhatItCannotRead(t *testing.T) {
	scope := fixture(t)
	before := Take(scope)
	if err := os.Remove(filepath.Join(scope.Proc, "1/mountinfo")); err != nil {
		t.Fatal(err)
	}
	write(t, scope.Proc, "self/mountinfo", mountinfo+"garbage line without a separator\n")
	after := Take(scope)
	if len(after.HostMounts) != 1 || !strings.HasPrefix(after.HostMounts[0], "! ") {
		t.Errorf("an unreadable mountinfo: %q", after.HostMounts)
	}
	diff := before.Diff(after)
	// Losing the ability to read a kind of state is a difference, and so
	// is a line that cannot be parsed: neither is silently "clean".
	joined := strings.Join(diff, "\n")
	if !strings.Contains(joined, "+ host mount: ! ") || !strings.Contains(joined, "+ mount: ! unparsed mountinfo line") {
		t.Errorf("Diff = %v", diff)
	}
	// The same error before and after is not a difference.
	if d := after.Diff(Take(scope)); len(d) != 0 {
		t.Errorf("a constant error is reported as a change: %v", d)
	}
}

func TestAssertClean(t *testing.T) {
	scope := fixture(t)

	clean := &recorder{}
	AssertClean(clean, scope)
	clean.finish()
	if len(clean.errors) != 0 {
		t.Errorf("a test that changed nothing: %v", clean.errors)
	}

	// A test that leaks, and whose own clean-up, registered after
	// AssertClean, removes only part of what it created.
	leaky := &recorder{}
	AssertClean(leaky, scope, Scope{CgroupParents: []string{"other"}})
	write(t, scope.Sys, "fs/cgroup/sandmeter/leaked/cgroup.procs", "")
	write(t, scope.Sys, "fs/cgroup/other/leaked-too/cgroup.procs", "")
	write(t, scope.StateRoots[0], "tmp/x", "")
	leaky.Cleanup(func() { os.RemoveAll(filepath.Join(scope.StateRoots[0], "tmp")) })
	leaky.finish()
	if len(leaky.errors) != 1 {
		t.Fatalf("a leaking test got %d errors: %v", len(leaky.errors), leaky.errors)
	}
	msg := leaky.errors[0]
	for _, want := range []string{"did not leave the host as it found it", "+ cgroup: sandmeter/leaked", "+ cgroup: other/leaked-too"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message lacks %q:\n%s", want, msg)
		}
	}
	// What the test's own clean-up removed is judged after that clean-up.
	if strings.Contains(msg, "state entry") {
		t.Errorf("the snapshot was taken before the test's clean-up ran:\n%s", msg)
	}
}

// TestTakeOnThisHost reads the real machine, which this package only ever
// reads: two snapshots in a row agree on the kinds of state that nothing
// changes during a unit test run.
func TestTakeOnThisHost(t *testing.T) {
	a, b := Take(Scope{}), Take(Scope{})
	if len(a.Mounts) == 0 {
		t.Error("no mount was read from /proc/self/mountinfo")
	}
	for _, line := range a.Mounts {
		if strings.HasPrefix(line, "! ") {
			t.Errorf("a mountinfo line of this host was not understood: %s", line)
		}
	}
	if strings.Join(a.Mounts, "\n") != strings.Join(b.Mounts, "\n") || strings.Join(a.Links, "\n") != strings.Join(b.Links, "\n") {
		t.Log("the mounts or links of this host changed between two snapshots")
	}
}
