package testhost

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// helperEnv selects, in a copy of this test binary started by a test, what
// the copy does instead of running tests.
const helperEnv = "SANDMETER_TESTHOST_HELPER"

// TestMain lets the test binary stand in for the helpers of the root side,
// which are re-executions of a binary by itself.
func TestMain(m *testing.M) {
	switch os.Getenv(helperEnv) {
	case "wait":
		// Stay until whoever holds the other end of standard input lets go:
		// the test, or the kernel when the test dies.
		io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	case "orphan":
		// Start a waiting copy through /proc/self/exe, as the root side
		// starts its helpers, say its pid and leave it without a parent.
		cmd := exec.Command("/proc/self/exe")
		cmd.Env = []string{helperEnv + "=wait"}
		cmd.Stdin = os.Stdin
		if err := cmd.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(cmd.Process.Pid)
		os.Exit(0)
	}
	// The tests below call AssertClean on fixtures. They take a lock of
	// their own, so that they neither wait for a root test that holds the
	// host's for minutes nor make one wait.
	private := filepath.Join(os.TempDir(), "sandmeter-testhost-selftest-"+strconv.Itoa(os.Getpid())+".lock")
	lockPath = func() string { return private }
	code := m.Run()
	os.Remove(private)
	os.Exit(code)
}

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
		"+ process: native.test (pid 200, started by this test)",
		"+ process: runsc-sandbox (pid 201, named like a process of sandmeter)",
		"+ process: sandmeterd (pid 203, named like a process of sandmeter)",
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

// TestAHelperIsKnownByItsExecutable is the case of everything the root side
// starts: a re-execution of /proc/self/exe, which the kernel names "exe"
// whatever the binary is called. Its name says nothing, and once its parent
// is gone its ancestry says nothing either: only the file it executes does.
func TestAHelperIsKnownByItsExecutable(t *testing.T) {
	scope := fixture(t)
	binary := filepath.Join(t.TempDir(), "native.test")
	other := filepath.Join(t.TempDir(), "bash")
	installed := filepath.Join(t.TempDir(), "sandmeterd")
	for _, p := range []string{binary, other, installed} {
		if err := os.WriteFile(p, []byte(p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := func(pid int, target string) {
		t.Helper()
		if err := os.Symlink(target, filepath.Join(scope.Proc, strconv.Itoa(pid), "exe")); err != nil {
			t.Fatal(err)
		}
	}
	link(100, binary) // the test itself
	before := Take(scope)

	// A leaked init: named "exe", adopted by process 1, same executable.
	write(t, scope.Proc, "300/stat", "300 (exe) S 1 300 300 0 -1")
	link(300, binary)
	// A process that is also named "exe" and executes something else.
	write(t, scope.Proc, "301/stat", "301 (exe) S 1 301 301 0 -1")
	link(301, other)
	// A daemon started from the binary the test installed.
	write(t, scope.Proc, "302/stat", "302 (exe) S 1 302 302 0 -1")
	link(302, installed)
	// A runtime that re-executed itself and kept its name in its arguments.
	write(t, scope.Proc, "303/stat", "303 (exe) S 1 303 303 0 -1")
	link(303, other)
	write(t, scope.Proc, "303/cmdline", "runsc-gofer\x00--root\x00/x\x00")
	// A process whose arguments merely mention sandmeter.
	write(t, scope.Proc, "304/stat", "304 (vi) S 1 304 304 0 -1")
	write(t, scope.Proc, "304/cmdline", "vi\x00sandmeter.go\x00")

	withBinary := scope
	withBinary.Binaries = []string{installed, filepath.Join(t.TempDir(), "absent")}
	got := strings.Join(Take(withBinary).Processes, "\n")
	want := strings.Join([]string{
		"exe (pid 300, runs the executable of this test)",
		"exe (pid 302, runs " + installed + ")",
		"exe (pid 303, started as runsc-gofer)",
	}, "\n")
	if got != want {
		t.Errorf("Processes =\n%s\nwant\n%s", got, want)
	}
	// Without the binary in the scope, its daemon is not this test's to see.
	diff := strings.Join(before.Diff(Take(scope)), "\n")
	if !strings.Contains(diff, "+ process: exe (pid 300, runs the executable of this test)") || strings.Contains(diff, "pid 302") || strings.Contains(diff, "pid 301") || strings.Contains(diff, "pid 304") {
		t.Errorf("Diff =\n%s", diff)
	}
}

// TestTakeSeesAnOrphanedCopyOfThisBinary does it for real: a copy of this
// test binary, started through /proc/self/exe by a process that exits at
// once, as a leaked helper of the root side would be. The kernel names it
// "exe" and it is nobody's child.
func TestTakeSeesAnOrphanedCopyOfThisBinary(t *testing.T) {
	before := Take(Scope{})

	// The helper lives exactly as long as this pipe has a writer.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	starter := exec.Command("/proc/self/exe")
	starter.Env = []string{helperEnv + "=orphan"}
	starter.Stdin = r
	out, err := starter.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := starter.Start(); err != nil {
		t.Fatal(err)
	}
	r.Close()
	line, _ := bufio.NewReader(out).ReadString('\n')
	if err := starter.Wait(); err != nil {
		t.Fatalf("the starter: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatalf("the starter printed %q", line)
	}
	gone := func() bool { return syscall.Kill(pid, 0) != nil }
	defer func() {
		w.Close()
		for deadline := time.Now().Add(5 * time.Second); !gone(); time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Errorf("the helper %d is still running after its pipe was closed", pid)
				return
			}
		}
	}()

	// What the old rule looked at: the name, which says nothing.
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		t.Fatalf("the helper %d is not running: %v", pid, err)
	}
	if !strings.Contains(string(stat), "(exe)") {
		t.Logf("the kernel named the helper otherwise than expected: %s", stat)
	}
	if strings.Contains(string(stat), ") S "+strconv.Itoa(os.Getpid())+" ") {
		t.Fatalf("the helper is still a child of this test: %s", stat)
	}

	want := "(pid " + strconv.Itoa(pid) + ", runs the executable of this test)"
	found := false
	for _, line := range Take(Scope{}).Processes {
		found = found || strings.HasSuffix(line, want)
	}
	if !found {
		t.Errorf("a snapshot does not list the leaked helper %d:\n%s", pid, strings.Join(Take(Scope{}).Processes, "\n"))
	}
	diff := strings.Join(before.Diff(Take(Scope{})), "\n")
	if !strings.Contains(diff, "+ process: ") || !strings.Contains(diff, want) {
		t.Errorf("the leak is not a difference:\n%s", diff)
	}
}

// TestAssertCleanTakesTurns: the comparison is of the whole host, so two
// tests never make it at the same time, in one test binary or in two.
func TestAssertCleanTakesTurns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host.lock")
	unlock, err := lockHost(path)
	if err != nil {
		t.Fatal(err)
	}
	// A second taker waits for as long as the first holds the lock.
	acquired := make(chan func(), 1)
	go func() {
		again, err := lockHost(path)
		if err != nil {
			t.Error(err)
		}
		acquired <- again
	}()
	select {
	case <-acquired:
		t.Fatal("the lock was taken twice")
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	select {
	case again := <-acquired:
		again()
	case <-time.After(5 * time.Second):
		t.Fatal("the lock was not handed over when it was released")
	}

	// A link planted under the predictable name is not followed.
	target := filepath.Join(t.TempDir(), "victim")
	planted := filepath.Join(t.TempDir(), "host.lock")
	if err := os.Symlink(target, planted); err != nil {
		t.Fatal(err)
	}
	if _, err := lockHost(planted); err == nil {
		t.Error("a symbolic link was taken for the lock file")
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Error("the file behind the link was created")
	}

	// AssertClean holds the real lock from the call to the end of the
	// comparison, and gives it back after it. A test and its subtest may
	// both call it: the second call joins the hold of the first instead of
	// waiting for it for ever.
	scope := fixture(t)
	outer, inner := &recorder{}, &recorder{}
	AssertClean(outer, scope)
	nested := make(chan struct{})
	go func() {
		AssertClean(inner, scope)
		close(nested)
	}()
	select {
	case <-nested:
	case <-time.After(5 * time.Second):
		t.Fatal("a second AssertClean in the same test binary waits for the first")
	}
	taken := make(chan func(), 1)
	go func() {
		// Another test binary: a lock of its own on the same file.
		u, err := lockHost(lockPath())
		if err != nil {
			t.Error(err)
		}
		taken <- u
	}()
	stillHeld := func(when string) {
		t.Helper()
		select {
		case <-taken:
			t.Fatalf("the host lock is free %s", when)
		case <-time.After(100 * time.Millisecond):
		}
	}
	stillHeld("while a test that called AssertClean runs")
	inner.finish()
	stillHeld("after the subtest, while the test that called AssertClean first still runs")
	outer.finish()
	select {
	case u := <-taken:
		u()
	case <-time.After(5 * time.Second):
		t.Fatal("AssertClean did not give the host lock back")
	}
	// The real lock: one file per user, in the temporary directory, the same
	// for every test binary of that user.
	if real := hostLockPath(); filepath.Dir(real) != filepath.Clean(os.TempDir()) || !strings.Contains(filepath.Base(real), strconv.Itoa(os.Getuid())) || real != hostLockPath() {
		t.Errorf("the lock file is %s", real)
	}
}
