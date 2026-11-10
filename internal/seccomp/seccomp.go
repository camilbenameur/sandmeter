// Package seccomp builds and installs a seccomp-BPF deny-list filter by hand.
//
// The filter is classic BPF assembled in Go: no libseccomp, no cgo. It is meant
// for the last step before execve in the sandbox's child process.
//
// What this filter does:
//
//   - kills the process if the syscall ABI is not the native one;
//   - on amd64, refuses x32-ABI syscall numbers;
//   - makes a fixed list of syscalls fail with EPERM;
//   - optionally makes clone fail with EPERM when it asks for a new namespace,
//     and clone3 fail with ENOSYS so libc falls back to clone.
//
// What it does NOT do. This is a deny list: every syscall that is not named is
// allowed, including syscalls added by kernels newer than this list. It is not
// Docker's default profile, which is an allow list of a few hundred syscalls
// and fails closed. It does not inspect pointer arguments (the kernel copies
// them after the filter runs, so a filter cannot check them without races),
// does not restrict what files, sockets or devices are reachable, and does not
// stop attacks that stay inside allowed syscalls (kernel bugs in ioctl, futex,
// netfilter via netlink sockets, and so on). It reduces kernel attack surface
// a little; it is one layer next to namespaces and cgroups, not a boundary.
//
// The filter is attached to the calling thread only and is inherited by
// children and across execve. See Install.
package seccomp

import (
	"errors"
	"fmt"
	"runtime"
	"sort"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Profile selects what the filter denies.
type Profile struct {
	// Denied lists syscall names that fail with EPERM.
	Denied []string
	// DenyNamespaceFlags makes clone fail with EPERM when its flags create a
	// new namespace, and clone3 fail with ENOSYS (its flags live in a struct
	// in user memory that BPF cannot read).
	DenyNamespaceFlags bool
}

// Return values and seccomp_data offsets, from <linux/seccomp.h>.
const (
	retAllow       = unix.SECCOMP_RET_ALLOW
	retKillProcess = unix.SECCOMP_RET_KILL_PROCESS
	retEPERM       = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	retENOSYS      = unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)

	offNr   = 0  // int nr
	offArch = 4  // __u32 arch
	offArg0 = 16 // __u64 args[0]; the low word is first on little-endian
)

// cloneNSMask is every CLONE_NEW* flag. CLONE_NEWTIME (0x80) overlaps the
// low byte that legacy clone uses as exit signal; a signal that large is
// rejected by the kernel anyway, so refusing it costs nothing.
const cloneNSMask = unix.CLONE_NEWNS | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC |
	unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET |
	unix.CLONE_NEWCGROUP | unix.CLONE_NEWTIME

// maxInsns is the kernel's BPF_MAXINSNS, the longest classic BPF program.
const maxInsns = 4096

// archOptional names syscalls that exist only on some architectures or
// kernels. A profile may list them everywhere; they are skipped where the
// per-arch table has no number. Any other unknown name is an error, so a typo
// cannot silently weaken the filter.
var archOptional = map[string]bool{
	"iopl":       true, // x86 only
	"ioperm":     true, // x86 only
	"uselib":     true, // removed or absent on new ports
	"nfsservctl": true, // removed in Linux 3.1
	"_sysctl":    true, // removed in Linux 5.5, never on arm64
}

// Default returns the deny list used by the sandbox.
//
// chroot is denied. It needs CAP_SYS_CHROOT, which the sandboxed process
// should not hold anyway, and the sandbox already switches roots with
// pivot_root before the filter is installed. Allowing chroot would only
// matter to tools such as fakeroot or debootstrap, which are not what an
// agent sandbox runs.
//
// personality is denied, which also makes the harmless personality(0xffffffff)
// query fail with EPERM. A few tools (setarch, some test runners) call it; for
// this prototype that is an accepted cost, because personality flags such as
// ADDR_NO_RANDOMIZE and READ_IMPLIES_EXEC weaken exploit mitigations.
func Default() Profile {
	return Profile{Denied: append([]string(nil), defaultDenied...), DenyNamespaceFlags: true}
}

var defaultDenied = []string{
	// Mounts and root changes: the new mount API and the old one. The sandbox
	// sets up its own filesystem view before this filter is installed; after
	// that the workload has no reason to change it.
	"mount", "umount2", "pivot_root", "chroot",
	"mount_setattr", "move_mount", "open_tree", "fsopen", "fsconfig", "fsmount", "fspick",

	// Namespaces: creating or joining one gives access to capabilities inside
	// it, which widens kernel attack surface. clone with CLONE_NEW* is handled
	// by DenyNamespaceFlags.
	"unshare", "setns",

	// File handles: open_by_handle_at bypasses path-based access checks and is
	// the core of the "shocker" container escape.
	"open_by_handle_at", "name_to_handle_at",

	// Kernel code and machine state: loading modules or a new kernel, power,
	// swap.
	"init_module", "finit_module", "delete_module",
	"kexec_load", "kexec_file_load", "reboot", "swapon", "swapoff",

	// Large kernel attack surface that agents do not need: eBPF, perf,
	// userfaultfd (used to stall the kernel in exploits), io_uring (many
	// past local privilege escalations, and it bypasses syscall filtering
	// for the operations it performs).
	"bpf", "perf_event_open", "userfaultfd",
	"io_uring_setup", "io_uring_enter", "io_uring_register",

	// Kernel keyrings are not namespaced and have had several bugs.
	"keyctl", "add_key", "request_key",

	// Inspecting or modifying other processes. Yama may already limit ptrace;
	// denying it is belt and braces. pidfd_getfd copies a file descriptor out
	// of another process under the same ptrace access check, process_madvise
	// acts on another process's memory, and kcmp leaks kernel pointers and
	// object identity. Other cross-process calls remain allowed.
	"ptrace", "process_vm_readv", "process_vm_writev",
	"pidfd_getfd", "process_madvise", "kcmp",

	// Host-wide information and clocks.
	"syslog", "acct", "settimeofday", "clock_settime", "clock_adjtime", "adjtimex",
	"quotactl", "quotactl_fd", "lookup_dcookie", "vhangup",

	// Execution domain flags that weaken mitigations; see Default.
	"personality",

	// Raw port I/O (x86), and legacy syscalls that only exist on some kernels.
	"iopl", "ioperm", "uselib", "nfsservctl", "_sysctl",
}

// Names returns the denied syscall names, sorted and without duplicates.
func (p Profile) Names() []string {
	seen := make(map[string]bool, len(p.Denied))
	names := make([]string, 0, len(p.Denied))
	for _, n := range p.Denied {
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}

func stmt(code uint16, k uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, K: k}
}

func jump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

const (
	opLoad = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
	opRet  = unix.BPF_RET | unix.BPF_K
	opJeq  = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
	opJset = unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K
)

// Build assembles the filter for the architecture this binary runs on.
//
// Every test jumps over at most three instructions, so jump offsets stay far
// below the 255 limit of the uint8 jt/jf fields regardless of list length.
// The cost is two instructions per denied syscall, linear in the list size,
// which is fine for a list of a few dozen entries.
func (p Profile) Build() ([]unix.SockFilter, error) {
	nrs, err := p.numbers()
	if err != nil {
		return nil, err
	}
	prog := []unix.SockFilter{
		stmt(opLoad, offArch),
		jump(opJeq, nativeArch, 1, 0),
		stmt(opRet, retKillProcess),
		stmt(opLoad, offNr),
	}
	if x32Bit != 0 {
		prog = append(prog,
			jump(opJset, x32Bit, 0, 1),
			stmt(opRet, retEPERM),
		)
	}
	for _, nr := range nrs {
		prog = append(prog,
			jump(opJeq, nr, 0, 1),
			stmt(opRet, retEPERM),
		)
	}
	if p.DenyNamespaceFlags {
		prog = append(prog, cloneChecks()...)
	}
	prog = append(prog, stmt(opRet, retAllow))
	if len(prog) > maxInsns {
		return nil, fmt.Errorf("seccomp: program has %d instructions, kernel limit is %d", len(prog), maxInsns)
	}
	return prog, nil
}

// cloneChecks handles clone and clone3. It runs after the plain deny list and
// reloads the accumulator, so it must stay after every check on nr.
func cloneChecks() []unix.SockFilter {
	return []unix.SockFilter{
		// clone3 takes its flags through a pointer. Failing with ENOSYS makes
		// libc retry with clone, whose flags are in a register.
		jump(opJeq, syscallNumbers["clone3"], 0, 1),
		stmt(opRet, retENOSYS),
		// Not clone: skip the three instructions below and fall to ALLOW.
		jump(opJeq, syscallNumbers["clone"], 0, 3),
		stmt(opLoad, offArg0),
		jump(opJset, cloneNSMask, 0, 1),
		stmt(opRet, retEPERM),
	}
}

// numbers resolves Denied to syscall numbers for this architecture, in name
// order so the program is deterministic.
func (p Profile) numbers() ([]uint32, error) {
	var nrs []uint32
	for _, name := range p.Names() {
		nr, ok := syscallNumbers[name]
		switch {
		case ok:
			nrs = append(nrs, nr)
		case archOptional[name]:
			// Not present on this architecture: nothing to deny.
		default:
			return nil, fmt.Errorf("seccomp: unknown syscall %q on %s", name, runtime.GOARCH)
		}
	}
	return nrs, nil
}

// Install loads prog as a seccomp filter for the calling thread.
//
// The filter applies to the calling OS thread only, not to the whole process,
// and is inherited by children and kept across execve. The caller must
// therefore run runtime.LockOSThread, call Install, and then fork/exec or
// execve from the same goroutine without unlocking in between; otherwise the
// goroutine may continue on a thread that has no filter. Install sets
// no_new_privs first, which is required for an unprivileged process and also
// stops setuid binaries from regaining privileges after exec.
func Install(prog []unix.SockFilter) error {
	if len(prog) == 0 {
		return errors.New("seccomp: empty program")
	}
	// sock_fprog.len is a uint16: without this check a long program would wrap
	// around and a truncated filter would be installed instead of an error.
	if len(prog) > maxInsns {
		return fmt.Errorf("seccomp: program has %d instructions, kernel limit is %d", len(prog), maxInsns)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("seccomp: set no_new_privs: %w", err)
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	_, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(&fprog)))
	runtime.KeepAlive(prog)
	if errno != 0 {
		return fmt.Errorf("seccomp: install filter: %w", errno)
	}
	return nil
}
