//go:build integration && linux

package kernelfacts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// childArg is the hidden first argument that turns the test binary into a
// helper process. TestMain dispatches on it before the testing package sees
// the command line. Helpers are how a test gets a process in new namespaces:
// a Go program cannot unshare most of them once its threads exist.
const childArg = "__kernelfacts_child"

// The default sandbox id range of the design: uid 0 of a sandbox is this
// uid on the host.
const (
	idShift = 1879048192
	idRange = 65536
)

// Every helper receives the namespaces of the test process, so that it can
// refuse to mount or to configure a network when a clone flag is missing.
const (
	hostMntEnv = "KERNELFACTS_HOST_MNTNS"
	hostNetEnv = "KERNELFACTS_HOST_NETNS"
)

// Bounds on how long a test waits for a helper.
const (
	readyTimeout  = 30 * time.Second
	resultTimeout = 2 * time.Minute
)

// childMain runs one helper, named in the table of children_test.go, and
// returns its exit status.
func childMain(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "kernelfacts helper: no name given")
		return 2
	}
	fn, ok := children[args[0]]
	if !ok {
		fmt.Fprintf(os.Stderr, "kernelfacts helper: unknown name %q\n", args[0])
		return 2
	}
	if err := fn(args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "kernelfacts helper %s: %v\n", args[0], err)
		return 1
	}
	return 0
}

// say prints one message line: a prefix and a JSON value, in a single write
// so that the test never reads half of it.
func say(prefix string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(append([]byte(prefix), b...), '\n'))
	return err
}

// sayReady tells the test that the helper reached the state it waits in.
func sayReady(v any) error { return say("ready ", v) }

// sayResult is the last thing a helper prints: what it measured.
func sayResult(v any) error { return say("result ", v) }

// waitRelease blocks until the test closes its end of the helper's standard
// input. The kernel closes it too when the test process dies, so a helper
// that waits here never outlives the test.
func waitRelease() { _, _ = io.Copy(io.Discard, os.Stdin) }

// childIdle stays alive until the test lets go of it or kills it.
func childIdle([]string) error {
	waitRelease()
	return nil
}

// childEcho exercises the message helpers; see TestSelfChildRoundTrip.
func childEcho(args []string) error {
	if len(args) > 0 && args[0] == "fail" {
		return errors.New("asked to fail")
	}
	if err := sayReady(map[string]any{"args": args}); err != nil {
		return err
	}
	waitRelease()
	return sayResult(map[string]any{"released": true})
}

// childCgroupReport reports where the kernel put this process.
func childCgroupReport([]string) error {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return err
	}
	if err := sayReady(map[string]string{"cgroup": string(bytes.TrimSpace(b))}); err != nil {
		return err
	}
	waitRelease()
	return nil
}

// errnoName turns an error into the name of its errno ("ENOSPC"), "ok" for
// nil, or the error text when it carries no errno. Replies carry these
// names so that a detail reads "expected ENOSPC, found EPERM".
func errnoName(err error) string {
	if err == nil {
		return "ok"
	}
	var e syscall.Errno
	if errors.As(err, &e) {
		if name := unix.ErrnoName(e); name != "" {
			return name
		}
		return fmt.Sprintf("errno %d", int(e))
	}
	return err.Error()
}

// nsLink is the identity of one of this process's namespaces, as
// /proc/self/ns prints it ("mnt:[4026531841]").
func nsLink(kind string) string {
	l, err := os.Readlink("/proc/self/ns/" + kind)
	if err != nil {
		return ""
	}
	return l
}

// outsideHost fails unless this process is in another namespace of that
// kind than the test process. Every helper that mounts or configures a
// network calls it first: a forgotten clone flag must never touch the host.
func outsideHost(kind, env string) error {
	host, own := os.Getenv(env), nsLink(kind)
	if host == "" || own == "" {
		return fmt.Errorf("cannot tell the %s namespace of this helper (%q) from the host's (%q)", kind, own, host)
	}
	if host == own {
		return fmt.Errorf("this helper is still in the host's %s namespace %s: refusing to go on", kind, own)
	}
	return nil
}

// privateMounts does what a worker does first in its new mount namespace:
// nothing mounted afterwards propagates to the host, while host mounts
// still propagate in.
func privateMounts() error {
	if err := outsideHost("mnt", hostMntEnv); err != nil {
		return err
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_SLAVE, ""); err != nil {
		return fmt.Errorf("mount MS_REC|MS_SLAVE on /: %w", err)
	}
	return nil
}

// spawn describes a helper process.
type spawn struct {
	name   string     // key of the children table
	args   []string   // its arguments
	clone  uintptr    // CLONE_NEW* flags
	userns bool       // also a new user namespace: 0 is idShift, the helper runs as 0:0
	nobody bool       // run as nobodyID without any privilege; for a root test, not with userns
	cgroup string     // cgroup directory to clone into (CLONE_INTO_CGROUP)
	files  []*os.File // inherited as descriptors 3, 4, ...
	wrap   []string   // command that runs the helper, such as systemd-run --scope
}

// nobodyID is the uid and gid of a helper that must be able to do nothing:
// the overflow id, which owns no file of the tests.
const nobodyID = 65534

// child is a running helper, seen from the test.
type child struct {
	name    string
	cmd     *exec.Cmd
	hold    *os.File // write end of the helper's standard input
	outPath string
	errPath string
	exited  chan struct{}
	waitErr error // valid once exited is closed
}

// usernsAttr adds a user namespace in which 0 is idShift, entered as 0:0
// with no supplementary group, as the supervisor starts the init.
func usernsAttr(attr *syscall.SysProcAttr) {
	ids := []syscall.SysProcIDMap{{ContainerID: 0, HostID: idShift, Size: idRange}}
	attr.Cloneflags |= unix.CLONE_NEWUSER
	attr.UidMappings = ids
	attr.GidMappings = ids
	attr.GidMappingsEnableSetgroups = true
	// The parent is host root, which the map leaves out: without these the
	// child would be nobody in its namespace and lose every capability at
	// execve.
	attr.Credential = &syscall.Credential{Uid: 0, Gid: 0, Groups: []uint32{}}
}

// startChild starts a helper. Its output goes to files in dir, never to
// pipes: a helper's own children may outlive it, and a pipe they hold would
// keep the test waiting.
func startChild(dir string, s spawn) (*child, error) {
	argv := append([]string{childArg, s.name}, s.args...)
	// The magic link, not a path: a helper that is already the shifted uid
	// may not be allowed to walk to the build directory.
	cmd := exec.Command("/proc/self/exe", argv...)
	if len(s.wrap) > 0 {
		self, err := os.Executable()
		if err != nil {
			return nil, err
		}
		cmd = exec.Command(s.wrap[0], append(append(slices.Clone(s.wrap[1:]), self), argv...)...)
	}
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer stdinR.Close()
	out, err := os.CreateTemp(dir, s.name+".*.stdout")
	if err != nil {
		stdinW.Close()
		return nil, err
	}
	defer out.Close()
	errf, err := os.CreateTemp(dir, s.name+".*.stderr")
	if err != nil {
		stdinW.Close()
		return nil, err
	}
	defer errf.Close()

	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdinR, out, errf
	cmd.ExtraFiles = s.files
	// What TestMain read before the first test, not what /proc/self says
	// now. Empty values, as in a process that did not go through TestMain,
	// make every guard refuse.
	cmd.Env = append(os.Environ(), hostMntEnv+"="+hostMntNS, hostNetEnv+"="+hostNetNS)
	attr := &syscall.SysProcAttr{Cloneflags: s.clone}
	if s.nobody {
		attr.Credential = &syscall.Credential{Uid: nobodyID, Gid: nobodyID, Groups: []uint32{}}
	}
	if s.userns {
		usernsAttr(attr)
	}
	if s.cgroup != "" {
		fd, err := unix.Open(s.cgroup, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			stdinW.Close()
			return nil, fmt.Errorf("open cgroup %s: %w", s.cgroup, err)
		}
		defer unix.Close(fd)
		attr.UseCgroupFD = true
		attr.CgroupFD = fd
	}
	cmd.SysProcAttr = attr
	if err := cmd.Start(); err != nil {
		stdinW.Close()
		return nil, fmt.Errorf("start helper %s: %w", s.name, err)
	}
	c := &child{name: s.name, cmd: cmd, hold: stdinW, outPath: out.Name(), errPath: errf.Name(), exited: make(chan struct{})}
	go func() {
		c.waitErr = cmd.Wait()
		close(c.exited)
	}()
	return c, nil
}

// spawnChild starts a helper for a test. The helper is killed when the test
// ends, whatever happened.
func spawnChild(t *testing.T, s spawn) (*child, error) {
	t.Helper()
	c, err := startChild(t.TempDir(), s)
	if err != nil {
		return nil, err
	}
	t.Cleanup(c.stop)
	return c, nil
}

// pid is the helper's pid in the pid namespace of the test.
func (c *child) pid() int { return c.cmd.Process.Pid }

// release lets a helper blocked in waitRelease go on.
func (c *child) release() {
	if c.hold != nil {
		c.hold.Close()
		c.hold = nil
	}
}

// kill sends SIGKILL and waits for the helper to be reaped.
func (c *child) kill() {
	_ = c.cmd.Process.Kill()
	<-c.exited
}

// stop ends the helper if it still runs. It is the cleanup of spawnChild.
func (c *child) stop() {
	c.release()
	select {
	case <-c.exited:
	default:
		c.kill()
	}
}

// stderr is what the helper wrote on its standard error, bounded.
func (c *child) stderr() string {
	b, err := os.ReadFile(c.errPath)
	if err != nil {
		return "(cannot read the helper's stderr: " + err.Error() + ")"
	}
	return tail(string(bytes.TrimSpace(b)), 2000)
}

// tail keeps the end of a text.
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}

// wait waits for the helper to exit and kills it at the timeout.
func (c *child) wait(timeout time.Duration) error {
	select {
	case <-c.exited:
	case <-time.After(timeout):
		c.kill()
		return fmt.Errorf("helper %s did not finish within %v and was killed; its stderr: %q", c.name, timeout, c.stderr())
	}
	if c.waitErr != nil {
		return fmt.Errorf("helper %s: %w; its stderr: %q", c.name, c.waitErr, c.stderr())
	}
	return nil
}

// diedOf reports whether the helper, once waited for, was killed by sig. A
// helper whose wait failed has no status: nothing is known of its end.
func (c *child) diedOf(sig syscall.Signal) bool {
	ps := c.cmd.ProcessState
	if ps == nil {
		return false
	}
	ws, ok := ps.Sys().(syscall.WaitStatus)
	return ok && ws.Signaled() && ws.Signal() == sig
}

// findLine returns what follows prefix on the first complete line that
// starts with it.
func findLine(data []byte, prefix string) ([]byte, bool) {
	for len(data) > 0 {
		line, rest, complete := bytes.Cut(data, []byte{'\n'})
		if !complete {
			return nil, false
		}
		if p, ok := bytes.CutPrefix(line, []byte(prefix)); ok {
			return p, true
		}
		data = rest
	}
	return nil, false
}

// message waits for a line of the helper's standard output that starts
// with prefix and decodes what follows into v. It gives up when the helper
// exits without printing it.
func (c *child) message(prefix string, v any, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		// Read the state before the file: a line printed just before the
		// exit is then never missed.
		exited := false
		select {
		case <-c.exited:
			exited = true
		default:
		}
		data, err := os.ReadFile(c.outPath)
		if err != nil {
			return err
		}
		if p, ok := findLine(data, prefix); ok {
			if err := json.Unmarshal(p, v); err != nil {
				return fmt.Errorf("helper %s printed a %q line that does not decode: %w (%q)", c.name, prefix, err, p)
			}
			return nil
		}
		if exited {
			return fmt.Errorf("helper %s exited (%v) without printing a %q line; its stdout: %q; its stderr: %q",
				c.name, c.waitErr, prefix, tail(string(data), 500), c.stderr())
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("helper %s printed no %q line within %v; its stderr: %q", c.name, prefix, timeout, c.stderr())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// ready waits for the helper's ready message.
func (c *child) ready(v any) error { return c.message("ready ", v, readyTimeout) }

// result waits for the helper to exit and decodes its result message.
func (c *child) result(v any) error {
	if err := c.wait(resultTimeout); err != nil {
		return err
	}
	return c.message("result ", v, time.Second)
}

// runChild starts a helper that needs nothing from the test while it runs,
// and decodes its result.
func runChild(t *testing.T, s spawn, v any) error {
	t.Helper()
	c, err := spawnChild(t, s)
	if err != nil {
		return err
	}
	return c.result(v)
}

// scratch creates a directory for one test under the scratch root and
// removes it when the test ends. The directories can be searched by anyone
// and listed by root only: helpers that run as the shifted uid must be able
// to reach what a test puts there for them.
func scratch(t *testing.T, name string) string {
	t.Helper()
	if scratchRoot == "" {
		t.Fatalf("no scratch directory: the test asked for one before checking for root")
	}
	dir := filepath.Join(scratchRoot, name)
	if err := os.Mkdir(dir, 0o711); err != nil {
		t.Fatalf("scratch directory: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Errorf("remove the scratch directory of this test: %v", err)
		}
	})
	return dir
}

// poll calls cond every few milliseconds until it holds or the time is up.
func poll(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
}
