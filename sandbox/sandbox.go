// Package sandbox defines the contract every isolation backend implements.
//
// A backend declares what it can enforce through Capabilities. The policy
// package refuses a policy that asks for something the chosen backend cannot
// enforce, before anything starts. This keeps "the policy says X" and "the
// backend does X" from drifting apart silently.
package sandbox

import (
	"context"
	"errors"
	"time"
)

// ErrNotImplemented is returned by backends for operations they do not support yet.
var ErrNotImplemented = errors.New("not implemented")

// NetworkMode is the network a sandbox gets.
type NetworkMode string

const (
	// NetworkNone gives the sandbox a network namespace with only loopback.
	NetworkNone NetworkMode = "none"
	// NetworkAllowlist gives the sandbox outbound access to listed destinations only.
	NetworkAllowlist NetworkMode = "allowlist"
)

// Capabilities is what a backend can enforce on the host it runs on.
// A field is true only if the backend enforces it, not if it merely accepts it.
type Capabilities struct {
	// Backend is the backend name, such as "native" or "gvisor".
	Backend string `json:"backend"`
	// Isolation names the mechanism, such as "linux-namespaces" or "user-space-kernel".
	Isolation string `json:"isolation"`

	CPULimit    bool `json:"cpu_limit"`
	MemoryLimit bool `json:"memory_limit"`
	PIDsLimit   bool `json:"pids_limit"`
	WallTimeout bool `json:"wall_timeout"`

	// Networks lists the network modes the backend can set up.
	Networks []NetworkMode `json:"networks"`

	ReadOnlyRoot bool `json:"read_only_root"`
	Seccomp      bool `json:"seccomp"`
	DropCaps     bool `json:"drop_capabilities"`
	Snapshot     bool `json:"snapshot"`

	// NeedsRoot is true when the backend must run as root on this host.
	NeedsRoot bool `json:"needs_root"`
	// Notes are host-specific caveats found while computing the capabilities.
	Notes []string `json:"notes,omitempty"`
}

// SupportsNetwork reports whether the backend can set up network mode m.
func (c Capabilities) SupportsNetwork(m NetworkMode) bool {
	for _, n := range c.Networks {
		if n == m {
			return true
		}
	}
	return false
}

// Limits are resource limits applied to the whole sandbox.
// A zero value means "no limit requested".
type Limits struct {
	// CPU is a number of cores, such as 0.5 or 2.
	CPU float64
	// MemoryBytes is the hard memory limit.
	MemoryBytes int64
	// PIDs is the maximum number of tasks.
	PIDs int64
	// Wall is the maximum run time of one Exec.
	Wall time.Duration
}

// Spec is everything a backend needs to start a sandbox. It is built from a
// validated policy, so backends may assume every requested feature is in
// their Capabilities.
type Spec struct {
	// RootFS is a directory holding the root filesystem, used read-only as the lower layer.
	RootFS string
	// Limits apply to the sandbox as a whole.
	Limits Limits
	// Network is the network mode.
	Network NetworkMode
	// Allow lists "host:port" or "ip:port" destinations for NetworkAllowlist.
	Allow []string
	// ReadOnlyRoot makes the root filesystem read-only; writes go to /tmp only.
	ReadOnlyRoot bool
	// Env is the environment of executed commands.
	Env []string
	// Hostname is the UTS hostname inside the sandbox.
	Hostname string
}

// Result is the outcome of one command.
type Result struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
	Duration time.Duration
	// Killed is set when the sandbox killed the command, and why
	// ("wall-timeout", "oom", ...). Empty otherwise.
	Killed string
}

// Backend starts sandboxes.
type Backend interface {
	// Capabilities reports what the backend can enforce on this host.
	Capabilities() Capabilities
	// Start creates a sandbox. The caller must call Stop.
	Start(ctx context.Context, spec Spec) (Sandbox, error)
}

// SnapshotID identifies a frozen filesystem state of a sandbox.
type SnapshotID string

// Sandbox is a running isolated environment.
type Sandbox interface {
	// ID is unique for the lifetime of the host process.
	ID() string
	// Exec runs argv inside the sandbox and waits for it.
	Exec(ctx context.Context, argv []string) (Result, error)
	// Snapshot freezes the current writable layer.
	Snapshot(ctx context.Context) (SnapshotID, error)
	// Restore resets the writable layer to a snapshot.
	Restore(ctx context.Context, id SnapshotID) error
	// Stop kills every process and releases every host resource. It is idempotent.
	Stop(ctx context.Context) error
}
