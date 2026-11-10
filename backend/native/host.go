//go:build linux

package native

import (
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Host is what the native backend learned about the machine it runs on.
type Host struct {
	Root                    bool
	Cgroup2                 bool
	AppArmorRestrictsUserns bool
}

// ProbeHost reads the host state. It changes nothing.
func ProbeHost() Host {
	var h Host
	h.Root = os.Geteuid() == 0
	var st unix.Statfs_t
	if unix.Statfs("/sys/fs/cgroup", &st) == nil && st.Type == unix.CGROUP2_SUPER_MAGIC {
		h.Cgroup2 = true
	}
	if b, err := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"); err == nil {
		h.AppArmorRestrictsUserns = strings.TrimSpace(string(b)) == "1"
	}
	return h
}
