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
// The package reads the host and changes nothing on it.
package testhost

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
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
	// whose name starts with "sandmeter" or "runsc" or is this process's own
	// name: the helpers a test started and should have reaped.
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
	own := all[scope.Self].comm
	var out []string
	for pid, p := range all {
		if skip[pid] {
			continue
		}
		if strings.HasPrefix(p.comm, "sandmeter") || strings.HasPrefix(p.comm, "runsc") || (own != "" && p.comm == own) {
			out = append(out, fmt.Sprintf("%s (pid %d)", p.comm, pid))
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
// The scope is the default one, extended by the state roots and cgroup
// parents of the scopes given: a test names the state directory and the
// cgroup parent it handed to what it tests.
//
// The whole host is compared, so two tests that create things at the same
// time see each other's: a test that calls AssertClean does not run in
// parallel with another.
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
	}
	before := Take(scope)
	t.Cleanup(func() {
		t.Helper()
		if diff := before.Diff(Take(scope)); len(diff) > 0 {
			t.Errorf("the test did not leave the host as it found it:\n%s", strings.Join(diff, "\n"))
		}
	})
}
