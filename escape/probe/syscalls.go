package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// syscallCheckArg is the hidden subcommand name a child process is re-exec'd
// with to run exactly one syscall check in isolation.
const syscallCheckArg = "__syscall-check"

// syscallChecks is the batch "syscalls" probes. Each one is run in its own
// child process (see runSyscalls) because a seccomp filter may answer with
// SECCOMP_RET_KILL instead of an errno, which would otherwise take down the
// whole probe rather than just one line of its report.
var syscallChecks = []string{
	"bpf",
	"keyctl",
	"io_uring_setup",
	"perf_event_open",
	"userfaultfd",
	"unshare_newuser",
	"mount_tmpfs",
	"ptrace_traceme",
}

// runSyscalls prints one "name reachable|blocked <detail>" line per check in
// syscallChecks, in order.
func runSyscalls() error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("rfprobe: find own path: %w", err)
	}
	for _, name := range syscallChecks {
		fmt.Println(runOneSyscallCheck(self, name))
	}
	return nil
}

// runOneSyscallCheck re-execs self as "__syscall-check <name>" and turns the
// result (ordinary exit, non-zero exit, or death by signal) into a report
// line. It never returns an error: an unreachable syscall is a normal,
// expected result, not a failure of rfprobe itself.
func runOneSyscallCheck(self, name string) string {
	out, err := exec.Command(self, syscallCheckArg, name).Output()
	return formatCheckResult(name, out, err)
}

// formatCheckResult builds the report line from a child's stdout and exit
// status. The child prints "blocked <errno>" itself before exiting 1, so
// that text, not the bare exit code, is what the report must carry.
func formatCheckResult(name string, out []byte, err error) string {
	if err == nil {
		return fmt.Sprintf("%s %s", name, trimNL(out))
	}

	var exitErr *exec.ExitError
	if !asExitError(err, &exitErr) {
		return fmt.Sprintf("%s error %v", name, err)
	}
	if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return fmt.Sprintf("%s blocked killed-by-signal:%s", name, ws.Signal())
	}
	if text := trimNL(out); text != "" {
		return fmt.Sprintf("%s %s", name, text)
	}
	return fmt.Sprintf("%s blocked exit:%d stderr:%s", name, exitErr.ExitCode(), trimNL(exitErr.Stderr))
}

func asExitError(err error, target **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*target = e
	}
	return ok
}

func trimNL(b []byte) string {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return string(b)
}

// runSyscallCheck is the child side: it runs exactly one named check,
// prints "reachable" or "blocked <errno>" and exits 0 on success, or lets
// the process die (non-zero exit, or a signal) when the syscall itself is
// refused in a way that is not a plain errno.
func runSyscallCheck(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("rfprobe: %s: want exactly one check name", syscallCheckArg)
	}
	switch args[0] {
	case "bpf":
		return reportErrno(checkBPF())
	case "keyctl":
		return reportErrno(checkKeyctl())
	case "io_uring_setup":
		return reportErrno(checkIOUringSetup())
	case "perf_event_open":
		return reportErrno(checkPerfEventOpen())
	case "userfaultfd":
		return reportErrno(checkUserfaultfd())
	case "unshare_newuser":
		return reportErrno(checkUnshareNewuser())
	case "mount_tmpfs":
		return reportErrno(checkMountTmpfs())
	case "ptrace_traceme":
		return reportErrno(checkPtraceTraceme())
	default:
		return fmt.Errorf("rfprobe: %s: unknown check %q", syscallCheckArg, args[0])
	}
}

// reportErrno prints the outcome of one syscall attempt and maps it to a
// process exit code: 0 for "the syscall was reachable" (whatever it then
// did with the arguments), 1 for "the kernel refused it with an errno".
func reportErrno(errno unix.Errno, ok bool) error {
	if ok {
		fmt.Println("reachable")
		return nil
	}
	fmt.Println(blockedLine(errno))
	os.Exit(1)
	return nil
}

// blockedLine is "blocked <ERRNAME>", falling back to the message for
// errnos x/sys has no name for.
func blockedLine(errno unix.Errno) string {
	if n := unix.ErrnoName(errno); n != "" {
		return "blocked " + n
	}
	return "blocked " + errno.Error()
}

// checkBPF tries bpf(BPF_MAP_CREATE) with a 1-entry array map. Reachable
// means the syscall itself was not refused by seccomp or a kernel
// LSM; the map, if created, is closed immediately.
func checkBPF() (unix.Errno, bool) {
	type bpfAttr struct {
		MapType    uint32
		KeySize    uint32
		ValueSize  uint32
		MaxEntries uint32
	}
	attr := bpfAttr{
		MapType:    unix.BPF_MAP_TYPE_ARRAY,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	}
	fd, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(unix.BPF_MAP_CREATE), uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno != 0 {
		return errno, false
	}
	unix.Close(int(fd))
	return 0, true
}

// checkKeyctl tries keyctl(KEYCTL_GET_KEYRING_ID) on the thread keyring
// without creating it. That keyring usually does not exist, so the kernel
// answers ENOKEY: an answer from the keyctl handler itself, which proves
// the syscall was reachable. Only an errno that means "refused" counts as
// blocked (see keyctlReachable).
func checkKeyctl() (unix.Errno, bool) {
	_, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_THREAD_KEYRING, false)
	if err == nil {
		return 0, true
	}
	errno, ok := err.(unix.Errno)
	if !ok {
		return unix.EIO, false
	}
	return errno, keyctlReachable(errno)
}

// keyctlReachable reports whether errno came from the keyctl handler (the
// key just does not exist) rather than from a filter in front of it.
func keyctlReachable(errno unix.Errno) bool {
	return errno == unix.ENOKEY
}

// ioUringParams mirrors struct io_uring_params from <linux/io_uring.h>
// (120 bytes on every architecture Go supports: alignment of the trailing
// uint64 fields lines up the same way in Go as in C). Zero-valued flags
// ask the kernel for the plain setup path.
type ioUringParams struct {
	SQEntries    uint32
	CQEntries    uint32
	Flags        uint32
	SQThreadCPU  uint32
	SQThreadIdle uint32
	Features     uint32
	WQFd         uint32
	Resv         [3]uint32
	SQOff        ioSqringOffsets
	CQOff        ioCqringOffsets
}

type ioSqringOffsets struct {
	Head, Tail, RingMask, RingEntries, Flags, Dropped, Array, Resv1 uint32
	UserAddr                                                        uint64
}

type ioCqringOffsets struct {
	Head, Tail, RingMask, RingEntries, Overflow, Cqes, Flags, Resv1 uint32
	UserAddr                                                        uint64
}

// checkIOUringSetup tries io_uring_setup with a single submission queue
// entry, the smallest ring the kernel accepts. On success, the returned
// fd is a ring that is closed right away.
func checkIOUringSetup() (unix.Errno, bool) {
	var params ioUringParams
	fd, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, 1, uintptr(unsafe.Pointer(&params)), 0)
	if errno != 0 {
		return errno, false
	}
	unix.Close(int(fd))
	return 0, true
}

// checkPerfEventOpen tries a software cpu-clock counter, which needs no
// hardware PMU access and so is the lowest bar perf_event_open has.
func checkPerfEventOpen() (unix.Errno, bool) {
	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_SOFTWARE,
		Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Config: unix.PERF_COUNT_SW_CPU_CLOCK,
	}
	fd, err := unix.PerfEventOpen(&attr, 0, -1, -1, 0)
	if err != nil {
		if errno, ok := err.(unix.Errno); ok {
			return errno, false
		}
		return unix.EIO, false
	}
	unix.Close(fd)
	return 0, true
}

// checkUserfaultfd tries userfaultfd(0): no flags, so it asks for nothing
// beyond the fd itself.
func checkUserfaultfd() (unix.Errno, bool) {
	fd, _, errno := unix.Syscall(unix.SYS_USERFAULTFD, 0, 0, 0)
	if errno != 0 {
		return errno, false
	}
	unix.Close(int(fd))
	return 0, true
}

// checkUnshareNewuser tries to create a user namespace, and only that.
// unshare(CLONE_NEWUSER) fails with EINVAL in a multithreaded process and a
// Go program always is one, so the namespace is created at clone time in a
// re-exec'd child instead, which is also how real tools do it.
func checkUnshareNewuser() (unix.Errno, bool) {
	cmd, err := usernsCommand(noopArg)
	if err != nil {
		return unix.EIO, false
	}
	if err := cmd.Run(); err != nil {
		return startErrno(err), false
	}
	return 0, true
}

// checkMountTmpfs tries to mount a tmpfs onto a directory this process
// creates and removes itself. If the sandbox gives this process its own
// mount namespace (as it should), the mount never reaches the host; this
// check is exactly what would catch the case where it does not.
func checkMountTmpfs() (unix.Errno, bool) {
	dir, err := os.MkdirTemp("", "rfprobe-mount-*")
	if err != nil {
		return unix.EIO, false
	}
	defer os.RemoveAll(dir)

	merr := unix.Mount("none", dir, "tmpfs", 0, "")
	if merr != nil {
		if errno, ok := merr.(unix.Errno); ok {
			return errno, false
		}
		return unix.EIO, false
	}
	unix.Unmount(dir, 0)
	return 0, true
}

// checkPtraceTraceme tries ptrace(PTRACE_TRACEME). It runs in its own
// re-exec'd child so that turning itself into a tracee has no effect
// beyond that one short-lived process.
func checkPtraceTraceme() (unix.Errno, bool) {
	_, _, errno := unix.Syscall(unix.SYS_PTRACE, unix.PTRACE_TRACEME, 0, 0)
	if errno != 0 {
		return errno, false
	}
	return 0, true
}
