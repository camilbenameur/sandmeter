//go:build linux

package native

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// keptCaps is the capability set root keeps inside the sandbox. It is close
// to the default set of container runtimes, minus CAP_MKNOD, CAP_NET_RAW and
// CAP_SETFCAP. These capabilities apply in the sandbox's user namespace only:
// on the host, sandbox root is an unprivileged uid.
var keptCaps = []uintptr{
	unix.CAP_CHOWN,
	unix.CAP_DAC_OVERRIDE,
	unix.CAP_FOWNER,
	unix.CAP_FSETID,
	unix.CAP_KILL,
	unix.CAP_SETGID,
	unix.CAP_SETUID,
	unix.CAP_SETPCAP,
	unix.CAP_NET_BIND_SERVICE,
	unix.CAP_SYS_CHROOT,
	unix.CAP_AUDIT_WRITE,
}

// KeptCapabilityNames lists keptCaps for documentation and receipts.
func KeptCapabilityNames() []string {
	return []string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "SETGID", "SETUID",
		"SETPCAP", "NET_BIND_SERVICE", "SYS_CHROOT", "AUDIT_WRITE"}
}

func capLast() (uintptr, error) {
	b, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return 0, fmt.Errorf("%w: %v", errNoCapLast, err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || n < 0 || n > 63 {
		return 0, fmt.Errorf("%w: %q", errNoCapLast, b)
	}
	return uintptr(n), nil
}

// dropCapabilities shrinks the bounding set, clears ambient capabilities and
// sets permitted, effective and inheritable to keptCaps, on the calling
// thread. When root execs a program, its new permitted set is the bounding
// set, so the bounding set is what limits the sandboxed command.
func dropCapabilities() error {
	last, err := capLast()
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}
	keep := map[uintptr]bool{}
	var mask uint64
	for _, c := range keptCaps {
		keep[c] = true
		mask |= 1 << c
	}
	for c := uintptr(0); c <= last; c++ {
		if keep[c] {
			continue
		}
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, c, 0, 0, 0); err != nil {
			return fmt.Errorf("init: drop bounding cap %d: %w", c, err)
		}
	}
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("init: clear ambient caps: %w", err)
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{
		{Effective: uint32(mask), Permitted: uint32(mask), Inheritable: uint32(mask)},
		{Effective: uint32(mask >> 32), Permitted: uint32(mask >> 32), Inheritable: uint32(mask >> 32)},
	}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("init: capset: %w", err)
	}
	return nil
}
