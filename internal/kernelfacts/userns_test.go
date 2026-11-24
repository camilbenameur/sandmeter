//go:build integration && linux

package kernelfacts

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// Nested user namespaces are refused without the syscall filter.
//
// The init writes 0 to user/max_user_namespaces of the sandbox's user
// namespace, through a procfs it mounted itself and checked with fstatfs,
// while it still holds CAP_SYS_RESOURCE there. The workload then gets
// ENOSPC from clone and unshare with CLONE_NEWUSER, and cannot write the
// value back. The limit applies to every user of the namespace, uid 0
// included (namespaces(7)).
//
// Kernel objects that are charged up the chain of namespace creators.
// The sandbox's user namespace was created by host root, so an inotify
// instance the workload creates inside is also counted against root in the
// initial namespace (kernel/ucount.c, inc_ucount). The init is meant to
// lower the per-namespace maxima at the same time as it writes the 0 above.

// procSys opens files of a procfs through a descriptor of its root, as the
// init does: never through a path the sandbox could have shaped.
type procSys struct{ fd int }

// mountOwnProc mounts a procfs for this process's pid namespace on /proc
// and returns a descriptor that is known to be a procfs.
func mountOwnProc() (procSys, error) {
	if err := outsideHost("mnt", hostMntEnv); err != nil {
		return procSys{}, err
	}
	if err := unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return procSys{}, fmt.Errorf("mount a procfs on /proc: %w", err)
	}
	return openProc("/proc")
}

// openProc opens a directory and accepts it only if the kernel says it is
// the root of a procfs: a directory that merely looks like /proc is how a
// sandbox would get a setting "written" into a plain file.
func openProc(path string) (procSys, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return procSys{}, fmt.Errorf("open %s: %w", path, err)
	}
	var st unix.Statfs_t
	if err := unix.Fstatfs(fd, &st); err != nil {
		unix.Close(fd)
		return procSys{}, fmt.Errorf("fstatfs %s: %w", path, err)
	}
	if st.Type != unix.PROC_SUPER_MAGIC {
		unix.Close(fd)
		return procSys{}, fmt.Errorf("fstatfs %s: filesystem type %#x, expected procfs (%#x)", path, st.Type, unix.PROC_SUPER_MAGIC)
	}
	return procSys{fd}, nil
}

// read returns the content of a file under the procfs root, or the errno.
func (p procSys) read(name string) string {
	fd, err := unix.Openat(p.fd, name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return errnoName(err)
	}
	defer unix.Close(fd)
	buf := make([]byte, 64)
	n, err := unix.Read(fd, buf)
	if err != nil {
		return errnoName(err)
	}
	return strings.TrimSpace(string(buf[:n]))
}

// write writes a value to a file under the procfs root and returns "ok" or
// the errno of the step that failed. The file is opened for each write, so
// the permission check sees the capabilities of the moment.
func (p procSys) write(name, value string) string {
	fd, err := unix.Openat(p.fd, name, unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return errnoName(err)
	}
	defer unix.Close(fd)
	if _, err := unix.Write(fd, []byte(value)); err != nil {
		return errnoName(err)
	}
	return "ok"
}

// capabilities returns the effective set of the calling thread.
func capabilities() (uint64, error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return 0, fmt.Errorf("capget: %w", err)
	}
	return uint64(data[0].Effective) | uint64(data[1].Effective)<<32, nil
}

// setCapabilities makes mask the effective and permitted sets of the
// calling thread and empties its inheritable set. Capabilities are per
// thread: the caller has locked its goroutine to this one.
func setCapabilities(mask uint64) error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{
		{Effective: uint32(mask), Permitted: uint32(mask)},
		{Effective: uint32(mask >> 32), Permitted: uint32(mask >> 32)},
	}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset %#x: %w", mask, err)
	}
	return nil
}

// unshareUser makes a fresh child of the calling thread call
// unshare(CLONE_NEWUSER) and reports "ok" or the errno.
//
// A Go program cannot make that call itself: the kernel refuses it in a
// process with several threads. Unshareflags makes the child do it between
// fork and execve, where it is alone, and a failure comes back as the error
// of Start. No other step of that path can answer ENOSPC.
func unshareUser() string {
	cmd := exec.Command("/proc/self/exe", childArg, "noop")
	cmd.SysProcAttr = &syscall.SysProcAttr{Unshareflags: unix.CLONE_NEWUSER}
	if err := cmd.Start(); err != nil {
		return errnoName(err)
	}
	_ = cmd.Wait()
	return "ok"
}

// usernsReport is what the stand-in for the init measured.
type usernsReport struct {
	Before      string `json:"before"`       // user/max_user_namespaces as the namespace was born
	Write       string `json:"write"`        // result of writing 0, or "skipped" in the control run
	After       string `json:"after"`        // the value read back
	WithCaps    string `json:"with_caps"`    // unshare(CLONE_NEWUSER) with every capability of the namespace
	Raise       string `json:"raise"`        // writing the first value back without CAP_SYS_RESOURCE and CAP_SYS_ADMIN
	AfterRaise  string `json:"after_raise"`  // the value after that attempt
	WithoutCaps string `json:"without_caps"` // unshare(CLONE_NEWUSER) with no capability at all
}

const maxUserNamespaces = "sys/user/max_user_namespaces"

// childUserns runs as PID 1 of new user, mount and pid namespaces, like the
// init. args[0] is "write" or "control".
func childUserns(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: userns write|control")
	}
	// Capabilities are per thread, and the processes forked below must
	// come from the thread that dropped them.
	runtime.LockOSThread()
	if os.Getpid() != 1 {
		return fmt.Errorf("pid %d: expected to be PID 1 of a new pid namespace", os.Getpid())
	}
	proc, err := mountOwnProc()
	if err != nil {
		return err
	}
	var rep usernsReport
	rep.Before = proc.read(maxUserNamespaces)
	rep.Write = "skipped"
	if args[0] == "write" {
		rep.Write = proc.write(maxUserNamespaces, "0")
	}
	rep.After = proc.read(maxUserNamespaces)
	rep.WithCaps = unshareUser()

	// What the workload is: no CAP_SYS_RESOURCE, no CAP_SYS_ADMIN.
	caps, err := capabilities()
	if err != nil {
		return err
	}
	if err := setCapabilities(caps &^ (1<<unix.CAP_SYS_RESOURCE | 1<<unix.CAP_SYS_ADMIN)); err != nil {
		return err
	}
	rep.Raise = proc.write(maxUserNamespaces, rep.Before)
	rep.AfterRaise = proc.read(maxUserNamespaces)

	if err := setCapabilities(0); err != nil {
		return err
	}
	rep.WithoutCaps = unshareUser()
	return sayResult(rep)
}

func TestNestedUserNamespaces(t *testing.T) {
	r := declare(t, "userns-nested-refused", "userns-limit-sealed", "userns-nested-control", "userns-nested-unprivileged")
	r.needRoot()

	standIn := spawn{name: "userns", clone: unix.CLONE_NEWNS | unix.CLONE_NEWPID, userns: true}

	var with usernsReport
	standIn.args = []string{"write"}
	if err := runChild(t, standIn, &with); err != nil {
		r.no("userns-nested-refused", "the stand-in for the init did not complete: %v", err)
	} else {
		r.judge("userns-nested-refused", with.Write == "ok" && with.After == "0" && with.WithCaps == "ENOSPC" && with.WithoutCaps == "ENOSPC",
			"value at birth %s; write of 0 through the init's own procfs: %s; read back: %s; unshare(CLONE_NEWUSER) with every capability: %s, with none: %s (expected ok, 0, ENOSPC, ENOSPC); kernel.unprivileged_userns_clone on the host: %s",
			with.Before, with.Write, with.After, with.WithCaps, with.WithoutCaps, readOr("/proc/sys/kernel/unprivileged_userns_clone"))
		refused := with.Raise == "EACCES" || with.Raise == "EPERM"
		r.judge("userns-limit-sealed", with.Write == "ok" && refused && with.AfterRaise == "0",
			"writing %s back without CAP_SYS_RESOURCE and CAP_SYS_ADMIN: %s; value afterwards: %s (expected EACCES or EPERM, and 0)",
			with.Before, with.Raise, with.AfterRaise)
	}

	var without usernsReport
	standIn.args = []string{"control"}
	if err := runChild(t, standIn, &without); err != nil {
		r.no("userns-nested-control", "the control run did not complete: %v", err)
		return
	}
	// The control is the errno, not the success: an LSM may have its own
	// reasons to refuse, and the helper its own trouble after the call, but
	// only the limit answers ENOSPC.
	r.judge("userns-nested-control", without.Write == "skipped" && without.WithCaps != "ENOSPC",
		"without the write the value stays %s and unshare(CLONE_NEWUSER) with every capability answers %s (expected ok, and in any case not ENOSPC)", without.After, without.WithCaps)
	r.judge("userns-nested-unprivileged", without.WithoutCaps == "ok",
		"without the write, unshare(CLONE_NEWUSER) with no capability answers %s; kernel.apparmor_restrict_unprivileged_userns=%s",
		without.WithoutCaps, readOr("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"))
}

// inotifyReady is what the helper holds while the test probes the host.
type inotifyReady struct {
	Limit    string `json:"limit"`    // user/max_inotify_instances of the namespace after the optional write
	Write    string `json:"write"`    // result of that write, or "skipped"
	Created  int    `json:"created"`  // inotify instances it holds
	Stop     string `json:"stop"`     // errno that stopped it, or "budget" when it reached the number asked
	FdsLeft  bool   `json:"fds_left"` // a descriptor could still be allocated when it stopped
	NoFile   uint64 `json:"no_file"`  // its RLIMIT_NOFILE
	Capacity int    `json:"capacity"` // how many it was asked to try
}

const maxInotifyInstances = "sys/user/max_inotify_instances"

// childInotify creates inotify instances in the sandbox's user namespace until
// the kernel refuses, then holds them until the test lets go.
// args: how many to try, and the limit to write first ("" for none).
func childInotify(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: inotify COUNT LIMIT")
	}
	budget, err := strconv.Atoi(args[0])
	if err != nil {
		return err
	}
	proc, err := mountOwnProc()
	if err != nil {
		return err
	}
	rdy := inotifyReady{Write: "skipped", Capacity: budget, Stop: "budget"}
	if args[1] != "" {
		rdy.Write = proc.write(maxInotifyInstances, args[1])
	}
	rdy.Limit = proc.read(maxInotifyInstances)
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err == nil {
		rdy.NoFile = lim.Cur
	}
	for rdy.Created < budget {
		// The descriptors stay open until this process exits.
		if _, err := unix.InotifyInit1(unix.IN_CLOEXEC); err != nil {
			rdy.Stop = errnoName(err)
			break
		}
		rdy.Created++
	}
	// EMFILE is also what a full descriptor table answers: tell the two apart.
	if fd, err := unix.Dup(0); err == nil {
		unix.Close(fd)
		rdy.FdsLeft = true
	}
	if err := sayReady(rdy); err != nil {
		return err
	}
	waitRelease()
	return nil
}

// hostInotify tries to create one inotify instance as the test process,
// which is root in the initial user namespace.
func hostInotify() string {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		return errnoName(err)
	}
	unix.Close(fd)
	return "ok"
}

// inotifyRun fills a sandbox user namespace with inotify instances and reports
// whether host root can still create one while they exist.
func inotifyRun(t *testing.T, budget int, limit string) (rdy inotifyReady, host string, err error) {
	t.Helper()
	c, err := spawnChild(t, spawn{
		name:   "inotify",
		args:   []string{strconv.Itoa(budget), limit},
		clone:  unix.CLONE_NEWNS | unix.CLONE_NEWPID,
		userns: true,
	})
	if err != nil {
		return rdy, "", err
	}
	defer c.stop()
	if err := c.ready(&rdy); err != nil {
		return rdy, "", err
	}
	return rdy, hostInotify(), nil
}

func TestInotifyCharged(t *testing.T) {
	r := declare(t, "inotify-charge-default", "inotify-charge-lowered")
	r.needRoot()

	hostLimit, err := strconv.Atoi(readOr("/proc/sys/fs/inotify/max_user_instances"))
	if err != nil {
		r.skipRest("fs.inotify.max_user_instances is not readable: %v", err)
		return
	}
	if first := hostInotify(); first != "ok" {
		r.skipRest("host root cannot create an inotify instance before the experiment starts (%s): nothing can be concluded", first)
		return
	}

	// Without a limit of its own, the sandbox can take every instance host
	// root is allowed. That starves root for a moment, so it is only tried
	// on a machine nobody else uses.
	const most = 60000
	switch {
	case !throwawayHost():
		r.skip("inotify-charge-default", "not a throwaway host: this experiment takes every inotify instance of host root for a moment (set CI=true and %s=1)", throwawayEnv)
		if requireLists("throwaway") {
			t.Errorf("%s lists throwaway but this host is not marked as one: CI=%q, %s=%q", requireEnv, os.Getenv("CI"), throwawayEnv, os.Getenv(throwawayEnv))
		}
	case hostLimit > most:
		r.skip("inotify-charge-default", "fs.inotify.max_user_instances is %d: too many descriptors to fill in a test (limit %d)", hostLimit, most)
	default:
		rdy, host, err := inotifyRun(t, hostLimit+64, "")
		switch {
		case err != nil:
			r.skip("inotify-charge-default", "the experiment did not complete: %v", err)
		case !rdy.FdsLeft || (rdy.Stop != "EMFILE" && rdy.Stop != "budget"):
			// Stopped by its own descriptor table, or by something else
			// than a limit on inotify instances: nothing was measured.
			r.skip("inotify-charge-default", "the sandbox was not stopped by a limit on inotify instances: created %d of %d, stopped by %s, descriptors left: %v, RLIMIT_NOFILE %d",
				rdy.Created, rdy.Capacity, rdy.Stop, rdy.FdsLeft, rdy.NoFile)
		default:
			// "budget" means it created more than the host allows one user
			// without ever being refused.
			r.judge("inotify-charge-default", host == "ok",
				"host limit %d; the sandbox (own limit %s) created %d instances and was stopped by %s; host root creating one meanwhile: %s; after the sandbox is gone: %s",
				hostLimit, rdy.Limit, rdy.Created, rdy.Stop, host, hostInotify())
		}
	}

	// With a small limit written in the sandbox's own user namespace.
	const lowered = 16
	rdy, host, err := inotifyRun(t, 4096, strconv.Itoa(lowered))
	if err != nil {
		r.skip("inotify-charge-lowered", "the experiment did not complete: %v", err)
		return
	}
	r.judge("inotify-charge-lowered", rdy.Write == "ok" && rdy.Stop == "EMFILE" && rdy.FdsLeft && rdy.Created <= lowered && host == "ok",
		"host limit %d; write of %d to user/max_inotify_instances in the sandbox: %s (reads %s); the sandbox created %d instances and was stopped by %s; host root creating one meanwhile: %s",
		hostLimit, lowered, rdy.Write, rdy.Limit, rdy.Created, rdy.Stop, host)
}

// The procfs half of the first test: a descriptor is accepted only for a
// real procfs, values are read through it, and without privilege a write is
// refused.
func TestSelfProcSys(t *testing.T) {
	p, err := openProc("/proc")
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(p.fd)
	value := p.read(maxUserNamespaces)
	if _, err := strconv.Atoi(value); err != nil {
		t.Errorf("user/max_user_namespaces read through the descriptor is %q, not a number", value)
	}
	if got := p.read("sys/user/no_such_setting"); got != "ENOENT" {
		t.Errorf("reading a setting that does not exist = %q, want ENOENT", got)
	}
	if q, err := openProc(t.TempDir()); err == nil {
		unix.Close(q.fd)
		t.Errorf("openProc accepted a directory that is not a procfs")
	}
	if os.Geteuid() != 0 {
		// The same answer the workload gets in userns-limit-sealed, for the same
		// reason: no CAP_SYS_RESOURCE in the namespace that owns the value.
		if got := p.write(maxUserNamespaces, value); got != "EACCES" && got != "EPERM" {
			t.Errorf("an unprivileged write to user/max_user_namespaces = %q, want EACCES or EPERM", got)
		}
	}
	if _, err := capabilities(); err != nil {
		t.Errorf("capabilities: %v", err)
	}
}
