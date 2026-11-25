// Package testhost is for the tests that need a real host: root, cgroups,
// mounts, a runtime. It answers three questions that such tests otherwise
// answer badly.
//
// Did the test run at all? A test that needs root skips on a developer's
// machine, and that is right. The same skip on the CI runner that exists to
// run it turns a broken job green. Require skips when a prerequisite is
// missing, and fails instead when the environment variable SANDMETER_REQUIRE
// lists that prerequisite: the job says what its runner must have, and a
// runner that lacks it is a failure.
//
// Did any test run? A test binary whose filter matches nothing, or whose
// every test skipped, exits with success. Main, called from TestMain, fails
// the binary when SANDMETER_REQUIRE is set and no test got past Require.
//
// Did the test leave the host as it found it? A sandbox that leaks a mount,
// a cgroup or a process passes every assertion about its own result.
// AssertClean compares the host before and after a test: mounts, cgroups,
// network links and namespaces, loop devices, processes and state
// directories.
//
// The package reads the host and changes nothing on it, with one exception:
// AssertClean keeps an empty lock file in the temporary directory, so that
// two tests never compare the host at the same time.
package testhost

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
)

// EnvRequire names the environment variable that lists, separated by
// commas, the prerequisites that must be present: a test that needs one of
// them fails instead of skipping when it is missing. The word "all" stands
// for every prerequisite this package knows.
const EnvRequire = "SANDMETER_REQUIRE"

// The prerequisites.
const (
	// Root: the test process is root.
	Root = "root"
	// Cgroup2: the unified cgroup hierarchy is mounted at /sys/fs/cgroup.
	Cgroup2 = "cgroup2"
	// Overlay: the kernel has the overlay filesystem.
	Overlay = "overlay"
	// Runsc: the gVisor runtime is installed.
	Runsc = "runsc"
	// Internet: the test may reach hosts on the public internet. Nothing
	// probes for it: it holds only where SANDMETER_REQUIRE says so, so that
	// a test never dials out from a machine that did not ask for it.
	Internet = "internet"
)

// Prerequisites is the closed list of prerequisites.
var Prerequisites = []string{Root, Cgroup2, Overlay, Runsc, Internet}

// TB is the part of testing.TB this package uses.
type TB interface {
	Helper()
	Skipf(format string, args ...any)
	Fatalf(format string, args ...any)
	Errorf(format string, args ...any)
	Cleanup(func())
}

// host is what Require asks the machine. The tests of this package replace
// it.
type host struct {
	getenv   func(string) string
	geteuid  func() int
	readFile func(string) ([]byte, error)
	exists   func(string) bool
	lookPath func(string) (string, error)
}

var realHost = host{
	getenv:   os.Getenv,
	geteuid:  os.Geteuid,
	readFile: os.ReadFile,
	exists:   func(path string) bool { _, err := os.Stat(path); return err == nil },
	lookPath: exec.LookPath,
}

// passed counts the calls of Require that found every prerequisite.
var passed atomic.Int64

// Require declares what a test needs from the host. When everything is
// there it returns. When a prerequisite is missing it skips the test, unless
// SANDMETER_REQUIRE lists that prerequisite (or says "all"): then the test
// fails, with a message that names what the runner lacks.
//
// A name that is not in Prerequisites fails the test, in a call and in the
// variable alike: a typing error must not turn into a skip.
func Require(t TB, prerequisites ...string) {
	t.Helper()
	require(t, realHost, prerequisites)
}

func require(t TB, h host, prerequisites []string) {
	t.Helper()
	required, err := parseRequired(h.getenv(EnvRequire))
	if err != nil {
		t.Fatalf("%v", err)
		return
	}
	for _, p := range prerequisites {
		if !known(p) {
			t.Fatalf("testhost.Require: %q is not a prerequisite (have %s)", p, strings.Join(Prerequisites, ", "))
			return
		}
	}
	for _, p := range prerequisites {
		ok, why := h.has(p, required)
		switch {
		case ok:
			continue
		case required[p]:
			t.Fatalf("this host lacks the prerequisite %q (%s), which %s requires: the test must run here, so this is a failure and not a skip", p, why, EnvRequire)
			return
		default:
			t.Skipf("needs %s: %s (set %s=%s to make this a failure)", p, why, EnvRequire, p)
			return
		}
	}
	passed.Add(1)
}

// parseRequired reads the value of SANDMETER_REQUIRE.
func parseRequired(v string) (map[string]bool, error) {
	required := map[string]bool{}
	for _, name := range strings.Split(v, ",") {
		name = strings.TrimSpace(name)
		switch {
		case name == "":
		case name == "all":
			for _, p := range Prerequisites {
				required[p] = true
			}
		case known(name):
			required[name] = true
		default:
			return nil, fmt.Errorf("%s names %q, which is not a prerequisite (have %s, or all)", EnvRequire, name, strings.Join(Prerequisites, ", "))
		}
	}
	return required, nil
}

func known(name string) bool {
	for _, p := range Prerequisites {
		if p == name {
			return true
		}
	}
	return false
}

// has reports whether the host has a prerequisite, and why not.
func (h host) has(p string, required map[string]bool) (ok bool, why string) {
	switch p {
	case Root:
		if h.geteuid() == 0 {
			return true, ""
		}
		return false, "the test process is not root"
	case Cgroup2:
		if h.exists("/sys/fs/cgroup/cgroup.controllers") {
			return true, ""
		}
		return false, "no cgroup v2 hierarchy at /sys/fs/cgroup"
	case Overlay:
		if b, err := h.readFile("/proc/filesystems"); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if f := strings.Fields(line); len(f) > 0 && f[len(f)-1] == "overlay" {
					return true, ""
				}
			}
		}
		return false, "the kernel does not list the overlay filesystem"
	case Runsc:
		for _, path := range []string{"/usr/local/bin/runsc", "/usr/bin/runsc"} {
			if h.exists(path) {
				return true, ""
			}
		}
		if _, err := h.lookPath("runsc"); err == nil {
			return true, ""
		}
		return false, "runsc is not installed"
	case Internet:
		if required[Internet] {
			return true, ""
		}
		return false, "reaching the internet is allowed only where " + EnvRequire + " lists it"
	}
	return false, "not a prerequisite"
}

// Main is for TestMain: os.Exit(testhost.Main(m)) in place of
// os.Exit(m.Run()). It runs the tests and returns their exit status, with
// one addition: when SANDMETER_REQUIRE is set and no test got past Require,
// the status is a failure. That is the case of a filter that matches
// nothing and of a package whose every test skipped, on a runner that was
// told what it must be able to run: a run that verified nothing is not a
// success.
//
// A TestMain that hands control to a hidden entry point does so before it
// calls Main.
func Main(m *testing.M) int {
	return finish(m.Run(), os.Getenv(EnvRequire), passed.Load(), os.Stderr)
}

func finish(code int, requireEnv string, passed int64, stderr io.Writer) int {
	if code != 0 {
		return code
	}
	if _, err := parseRequired(requireEnv); err != nil {
		fmt.Fprintf(stderr, "testhost: %v\n", err)
		return 1
	}
	if strings.TrimSpace(requireEnv) != "" && passed == 0 {
		fmt.Fprintf(stderr, "testhost: %s=%s and no test got past its prerequisites: nothing was verified, which is a failure here\n", EnvRequire, requireEnv)
		return 1
	}
	return code
}

// Scope says where a snapshot looks. The zero value of a field means its
// default; the tests of this package point the roots at fixtures.
type Scope struct {
	// Proc and Sys are the roots of procfs and sysfs: "/proc" and "/sys".
	Proc, Sys string
	// NetnsDir is where named network namespaces are bound: "/run/netns".
	NetnsDir string
	// CgroupParents lists the cgroups, as paths below the cgroup root, whose
	// descendants a snapshot lists. Default: "sandmeter".
	CgroupParents []string
	// StateRoots lists directories whose entries a snapshot lists: the state
	// directory a test gave to what it tests. No default.
	StateRoots []string
	// Binaries lists the paths of executables, besides the test's own, whose
	// processes a snapshot lists: the sandmeterd a test installed and
	// started, the runsc it was given. No default.
	Binaries []string
	// Self is the pid of the process the snapshot is taken for; it and its
	// ancestors are not listed among the processes. Default: this process.
	Self int
}

func (s Scope) withDefaults() Scope {
	if s.Proc == "" {
		s.Proc = "/proc"
	}
	if s.Sys == "" {
		s.Sys = "/sys"
	}
	if s.NetnsDir == "" {
		s.NetnsDir = "/run/netns"
	}
	if s.CgroupParents == nil {
		s.CgroupParents = []string{"sandmeter"}
	}
	if s.Self == 0 {
		s.Self = os.Getpid()
	}
	return s
}

// Snapshot is the state of the host that a sandbox can leave something in.
// Each field is a sorted list of lines; a kind of state that could not be
// read holds one line that starts with "!" and says why, so that an error
// that is the same before and after is not a difference and one that
// appears is.
type Snapshot struct {
	// Mounts holds one line per mount of this process's mount namespace:
	// mount point, filesystem type and source. HostMounts holds the same for
	// the mount namespace of process 1.
	Mounts, HostMounts []string
	// Cgroups holds the descendants of the cgroup parents of the scope.
	Cgroups []string
	// Links holds the network interfaces of this process's network
	// namespace, and Netns the named network namespaces.
	Links, Netns []string
	// Loops holds the loop devices that have a backing file, with it.
	Loops []string
	// Processes holds the processes, other than this one and its ancestors,
	// that a test may have started and should have reaped. A process is
	// listed when it executes the same file as this process, or one of the
	// scope's binaries; when this process is one of its ancestors; or when
	// its name, or the name it was started under, begins with "sandmeter" or
	// "runsc". Each line says which.
	//
	// The first rule is the one that finds what the root side leaves behind.
	// Every helper it starts (the first process of a sandbox, a worker, the
	// egress proxy, the image fetcher) is a re-execution of /proc/self/exe,
	// and the kernel names such a process "exe" whatever the binary is
	// called: no rule on names can see it, and once its parent is gone no
	// rule on parents can either.
	Processes []string
	// State holds the entries of the state roots of the scope.
	State []string
}

// Take reads the host. It never fails: what cannot be read is recorded in
// the snapshot.
func Take(scope Scope) Snapshot {
	scope = scope.withDefaults()
	return Snapshot{
		Mounts:     mounts(scope.Proc + "/self/mountinfo"),
		HostMounts: mounts(scope.Proc + "/1/mountinfo"),
		Cgroups:    cgroups(scope),
		Links:      names(scope.Sys+"/class/net", "links"),
		Netns:      names(scope.NetnsDir, "netns"),
		Loops:      loops(scope.Sys + "/block"),
		Processes:  processes(scope),
		State:      state(scope.StateRoots),
	}
}

func unreadable(what string, err error) []string {
	return []string{"! " + what + ": " + err.Error()}
}

// mounts parses a mountinfo file into "mount-point type source" lines.
func mounts(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return unreadable(path, err)
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" {
			continue
		}
		// "36 35 98:0 /root /mount/point options [tags...] - type source super"
		before, after, found := strings.Cut(line, " - ")
		left, right := strings.Fields(before), strings.Fields(after)
		if !found || len(left) < 5 || len(right) < 2 {
			out = append(out, "! unparsed mountinfo line: "+line)
			continue
		}
		out = append(out, left[4]+" "+right[0]+" "+right[1])
	}
	sort.Strings(out)
	return out
}

// cgroups lists every directory below each parent.
func cgroups(scope Scope) []string {
	var out []string
	for _, parent := range scope.CgroupParents {
		root := scope.Sys + "/fs/cgroup/" + parent
		var walk func(rel string)
		walk = func(rel string) {
			entries, err := os.ReadDir(root + rel)
			if err != nil {
				if !errors.Is(err, os.ErrNotExist) || rel != "" {
					out = append(out, "! "+parent+rel+": "+err.Error())
				}
				return
			}
			for _, e := range entries {
				if e.IsDir() {
					out = append(out, parent+rel+"/"+e.Name())
					walk(rel + "/" + e.Name())
				}
			}
		}
		walk("")
	}
	sort.Strings(out)
	return out
}

// names lists the entries of a directory. A directory that does not exist
// has no entries.
func names(dir, what string) []string {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return unreadable(what, err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

// loops lists the loop devices that are attached to a file.
func loops(block string) []string {
	entries, err := os.ReadDir(block)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return unreadable("loop devices", err)
	}
	var out []string
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "loop") {
			continue
		}
		b, err := os.ReadFile(block + "/" + e.Name() + "/loop/backing_file")
		if err != nil {
			continue // not attached
		}
		out = append(out, e.Name()+" "+strings.TrimSpace(string(b)))
	}
	sort.Strings(out)
	return out
}

// leftoverName reports whether a process name is one of sandmeter's or of
// the runtime it wraps.
func leftoverName(name string) bool {
	name = filepath.Base(name)
	return strings.HasPrefix(name, "sandmeter") || strings.HasPrefix(name, "runsc")
}

// processes lists the processes a test may have left behind.
func processes(scope Scope) []string {
	entries, err := os.ReadDir(scope.Proc)
	if err != nil {
		return unreadable("processes", err)
	}
	type proc struct {
		comm string
		ppid int
	}
	all := map[int]proc{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile(scope.Proc + "/" + e.Name() + "/stat")
		if err != nil {
			continue // gone already
		}
		// "pid (comm) state ppid ...": the name may hold spaces and
		// parentheses, so it ends at the last ")".
		s := string(b)
		open, end := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
		if open < 0 || end < open {
			continue
		}
		rest := strings.Fields(s[end+1:])
		if len(rest) < 2 {
			continue
		}
		ppid, _ := strconv.Atoi(rest[1])
		all[pid] = proc{comm: s[open+1 : end], ppid: ppid}
	}
	skip := map[int]bool{}
	for pid := scope.Self; pid > 0 && !skip[pid]; pid = all[pid].ppid {
		skip[pid] = true
	}
	// A process is known by the file it executes. The link /proc/<pid>/exe
	// leads to that file even when it was renamed or removed since; two
	// processes execute the same file when the links lead to the same inode
	// of the same device.
	exe := func(pid int) os.FileInfo {
		fi, err := os.Stat(scope.Proc + "/" + strconv.Itoa(pid) + "/exe")
		if err != nil {
			return nil // a kernel thread, a process that is gone or not ours to see
		}
		return fi
	}
	type binary struct {
		what string
		file os.FileInfo
	}
	var known []binary
	if fi := exe(scope.Self); fi != nil {
		known = append(known, binary{"runs the executable of this test", fi})
	}
	for _, path := range scope.Binaries {
		if fi, err := os.Stat(path); err == nil {
			known = append(known, binary{"runs " + path, fi})
		}
	}
	descends := func(pid int) bool {
		for steps := 0; pid > 0 && steps <= len(all); steps++ {
			if pid = all[pid].ppid; pid == scope.Self {
				return true
			}
		}
		return false
	}
	var out []string
	for pid, p := range all {
		if skip[pid] {
			continue
		}
		why := ""
		if fi := exe(pid); fi != nil {
			for _, b := range known {
				if os.SameFile(fi, b.file) {
					why = b.what
					break
				}
			}
		}
		if why == "" && descends(pid) {
			why = "started by this test"
		}
		if why == "" && leftoverName(p.comm) {
			why = "named sandmeter* or runsc*"
		}
		if why == "" {
			// The name a process was started under: a runtime that
			// re-executes itself keeps its name only there.
			if b, err := os.ReadFile(scope.Proc + "/" + strconv.Itoa(pid) + "/cmdline"); err == nil {
				if argv0, _, _ := strings.Cut(string(b), "\x00"); argv0 != "" && leftoverName(argv0) {
					why = "started as " + filepath.Base(argv0)
				}
			}
		}
		if why != "" {
			out = append(out, fmt.Sprintf("%s (pid %d, %s)", p.comm, pid, why))
		}
	}
	sort.Strings(out)
	return out
}

// state lists the entries of each state root.
func state(roots []string) []string {
	var out []string
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			out = append(out, "! "+root+": "+err.Error())
			continue
		}
		for _, e := range entries {
			out = append(out, root+"/"+e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// Diff returns what differs between a snapshot taken before and one taken
// after, one line per difference: "+ kind: line" for something that is
// there now and was not, "- kind: line" for something that is gone. An
// empty result means the host is as it was.
func (before Snapshot) Diff(after Snapshot) []string {
	var out []string
	for _, k := range []struct {
		kind string
		a, b []string
	}{
		{"mount", before.Mounts, after.Mounts},
		{"host mount", before.HostMounts, after.HostMounts},
		{"cgroup", before.Cgroups, after.Cgroups},
		{"network link", before.Links, after.Links},
		{"network namespace", before.Netns, after.Netns},
		{"loop device", before.Loops, after.Loops},
		{"process", before.Processes, after.Processes},
		{"state entry", before.State, after.State},
	} {
		// The lists are compared as multisets: the same mount point can be
		// mounted twice.
		count := map[string]int{}
		for _, line := range k.a {
			count[line]--
		}
		for _, line := range k.b {
			count[line]++
		}
		var lines []string
		for line := range count {
			lines = append(lines, line)
		}
		sort.Strings(lines)
		for _, line := range lines {
			for n := count[line]; n > 0; n-- {
				out = append(out, "+ "+k.kind+": "+line)
			}
			for n := count[line]; n < 0; n++ {
				out = append(out, "- "+k.kind+": "+line)
			}
		}
	}
	return out
}

// AssertClean takes a snapshot of the host now and another when the test
// and everything it registered for clean-up is done, and fails the test,
// listing every difference, if the two differ. Call it first in a test that
// creates anything on the host, before the clean-ups it is meant to judge
// are registered.
//
// The scope is the default one, extended by the state roots, the cgroup
// parents and the binaries of the scopes given: a test names the state
// directory and the cgroup parent it handed to what it tests.
//
// The whole host is compared, not the part one test touches. Two things
// follow.
//
// Tests that call AssertClean take turns, across test binaries: a test
// binary holds a lock on the host from this call until the comparison is
// done, and the next binary waits. Inside one binary the lock is shared, so
// that a test and its subtests may both call AssertClean; that is also why
// a test that calls it must not call t.Parallel, which would let two tests
// of the same binary change the host at once.
//
// Whatever else creates mounts, cgroups, links or processes of sandmeter on
// the host during the test shows up as a difference, and the lock cannot
// keep away what does not take it: a test of another package that starts a
// sandbox without calling AssertClean, a service left running. A job that
// runs root tests therefore runs its packages one at a time (go test -p 1),
// and on a host that runs nothing else of sandmeter.
func AssertClean(t TB, more ...Scope) {
	t.Helper()
	scope := Scope{}.withDefaults()
	for _, m := range more {
		if m.Proc != "" {
			scope.Proc = m.Proc
		}
		if m.Sys != "" {
			scope.Sys = m.Sys
		}
		if m.NetnsDir != "" {
			scope.NetnsDir = m.NetnsDir
		}
		if m.Self != 0 {
			scope.Self = m.Self
		}
		scope.CgroupParents = append(scope.CgroupParents, m.CgroupParents...)
		scope.StateRoots = append(scope.StateRoots, m.StateRoots...)
		scope.Binaries = append(scope.Binaries, m.Binaries...)
	}
	unlock, err := holdHost()
	if err != nil {
		t.Fatalf("testhost: the host cannot be compared alone: %v", err)
		return
	}
	// Registered first, so that it runs last: after the comparison below.
	t.Cleanup(unlock)
	before := Take(scope)
	t.Cleanup(func() {
		t.Helper()
		if diff := before.Diff(Take(scope)); len(diff) > 0 {
			t.Errorf("the test did not leave the host as it found it:\n%s", strings.Join(diff, "\n"))
		}
	})
}

// held is this process's hold on the host lock: taken by the first test
// that asks, shared by those that ask while it is held, given back when the
// last of them is done.
var held struct {
	sync.Mutex
	holders int
	release func()
}

// holdHost takes the host lock for this process, or joins the hold the
// process already has, and returns the function that lets go.
func holdHost() (letGo func(), err error) {
	held.Lock()
	defer held.Unlock()
	if held.holders == 0 {
		release, err := lockHost(lockPath())
		if err != nil {
			return nil, err
		}
		held.release = release
	}
	held.holders++
	var once sync.Once
	return func() {
		once.Do(func() {
			held.Lock()
			defer held.Unlock()
			if held.holders--; held.holders == 0 {
				held.release()
				held.release = nil
			}
		})
	}, nil
}

// lockPath says where the lock file of AssertClean is. The tests of this
// package replace it: they must not wait for, nor hold up, the real tests
// that run on the same host.
var lockPath = hostLockPath

// hostLockPath is the lock file of AssertClean: one per user, in the
// temporary directory, so that every test binary of that user finds the
// same one. Root tests, which are the ones that change the host, all run as
// one user. Test binaries that are given different temporary directories do
// not exclude one another: a job that does that runs them one at a time.
func hostLockPath() string {
	return filepath.Join(os.TempDir(), "sandmeter-testhost-"+strconv.Itoa(os.Getuid())+".lock")
}

// lockHost takes the lock, waiting for whoever holds it, and returns the
// function that gives it back. The lock is an advisory lock on an open file:
// the kernel releases it when the test binary dies, so a test that crashes
// blocks nobody.
func lockHost(path string) (unlock func(), err error) {
	// O_NOFOLLOW: the name is predictable and lives in a directory everybody
	// writes to. A link planted there is refused, not followed.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if err != syscall.EINTR {
			break
		}
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return func() { f.Close() }, nil
}
