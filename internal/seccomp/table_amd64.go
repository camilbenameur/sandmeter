package seccomp

import "golang.org/x/sys/unix"

// nativeArch is the AUDIT_ARCH value the filter accepts.
const nativeArch = unix.AUDIT_ARCH_X86_64

// x32Bit marks x32-ABI syscall numbers. They share AUDIT_ARCH_X86_64, so the
// arch check alone would let them bypass a number-based deny list.
const x32Bit = 0x40000000

// syscallNumbers maps syscall names to numbers for amd64. Names the kernel
// does not have on this architecture are absent; see archOptional.
var syscallNumbers = map[string]uint32{
	"mount":             unix.SYS_MOUNT,
	"umount2":           unix.SYS_UMOUNT2,
	"pivot_root":        unix.SYS_PIVOT_ROOT,
	"chroot":            unix.SYS_CHROOT,
	"unshare":           unix.SYS_UNSHARE,
	"setns":             unix.SYS_SETNS,
	"mount_setattr":     unix.SYS_MOUNT_SETATTR,
	"move_mount":        unix.SYS_MOVE_MOUNT,
	"open_tree":         unix.SYS_OPEN_TREE,
	"fsopen":            unix.SYS_FSOPEN,
	"fsconfig":          unix.SYS_FSCONFIG,
	"fsmount":           unix.SYS_FSMOUNT,
	"fspick":            unix.SYS_FSPICK,
	"open_by_handle_at": unix.SYS_OPEN_BY_HANDLE_AT,
	"name_to_handle_at": unix.SYS_NAME_TO_HANDLE_AT,
	"init_module":       unix.SYS_INIT_MODULE,
	"finit_module":      unix.SYS_FINIT_MODULE,
	"delete_module":     unix.SYS_DELETE_MODULE,
	"kexec_load":        unix.SYS_KEXEC_LOAD,
	"kexec_file_load":   unix.SYS_KEXEC_FILE_LOAD,
	"reboot":            unix.SYS_REBOOT,
	"swapon":            unix.SYS_SWAPON,
	"swapoff":           unix.SYS_SWAPOFF,
	"bpf":               unix.SYS_BPF,
	"perf_event_open":   unix.SYS_PERF_EVENT_OPEN,
	"userfaultfd":       unix.SYS_USERFAULTFD,
	"keyctl":            unix.SYS_KEYCTL,
	"add_key":           unix.SYS_ADD_KEY,
	"request_key":       unix.SYS_REQUEST_KEY,
	"ptrace":            unix.SYS_PTRACE,
	"process_vm_readv":  unix.SYS_PROCESS_VM_READV,
	"process_vm_writev": unix.SYS_PROCESS_VM_WRITEV,
	"io_uring_setup":    unix.SYS_IO_URING_SETUP,
	"io_uring_enter":    unix.SYS_IO_URING_ENTER,
	"io_uring_register": unix.SYS_IO_URING_REGISTER,
	"syslog":            unix.SYS_SYSLOG,
	"acct":              unix.SYS_ACCT,
	"settimeofday":      unix.SYS_SETTIMEOFDAY,
	"clock_settime":     unix.SYS_CLOCK_SETTIME,
	"clock_adjtime":     unix.SYS_CLOCK_ADJTIME,
	"adjtimex":          unix.SYS_ADJTIMEX,
	"quotactl":          unix.SYS_QUOTACTL,
	"quotactl_fd":       unix.SYS_QUOTACTL_FD,
	"lookup_dcookie":    unix.SYS_LOOKUP_DCOOKIE,
	"vhangup":           unix.SYS_VHANGUP,
	"personality":       unix.SYS_PERSONALITY,
	"clone":             unix.SYS_CLONE,
	"clone3":            unix.SYS_CLONE3,
	"nfsservctl":        unix.SYS_NFSSERVCTL,
	"iopl":              unix.SYS_IOPL,
	"ioperm":            unix.SYS_IOPERM,
	"uselib":            unix.SYS_USELIB,
	"_sysctl":           unix.SYS__SYSCTL,
}
