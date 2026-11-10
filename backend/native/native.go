//go:build linux

// Package native is the backend written directly on Linux primitives:
// namespaces, pivot_root, cgroups v2, seccomp, capabilities, netns and nftables.
// It does not use runc or any container runtime.
package native

import (
	"context"
	"fmt"

	"github.com/camilbenameur/ringfence/sandbox"
)

// Backend is the native backend. The zero value is not usable: call New.
type Backend struct {
	host Host
}

// New probes the host and returns a backend.
func New() *Backend {
	return &Backend{host: ProbeHost()}
}

// Capabilities reports what this backend enforces today on this host.
// Features are switched on here only once they are implemented and tested.
func (b *Backend) Capabilities() sandbox.Capabilities {
	c := sandbox.Capabilities{
		Backend:   "native",
		Isolation: "linux-namespaces",
		NeedsRoot: true,
	}
	if !b.host.Root {
		c.Notes = append(c.Notes, "not running as root: the native backend cannot start")
	}
	if !b.host.Cgroup2 {
		c.Notes = append(c.Notes, "cgroup v2 is not mounted at /sys/fs/cgroup")
	}
	if b.host.AppArmorRestrictsUserns {
		c.Notes = append(c.Notes, "kernel.apparmor_restrict_unprivileged_userns=1: rootless mode is unavailable on this host")
	}
	return c
}

// Start is implemented from milestone 2 on.
func (b *Backend) Start(ctx context.Context, spec sandbox.Spec) (sandbox.Sandbox, error) {
	return nil, fmt.Errorf("native: start: %w", sandbox.ErrNotImplemented)
}
