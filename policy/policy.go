// Package policy loads a sandbox policy and checks it against what a backend
// can enforce.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/camilbenameur/ringfence/sandbox"
)

// Policy is the on-disk policy format (TOML).
type Policy struct {
	Limits     Limits     `toml:"limits" json:"limits"`
	Network    Network    `toml:"network" json:"network"`
	Filesystem Filesystem `toml:"filesystem" json:"filesystem"`
	Syscalls   Syscalls   `toml:"syscalls" json:"syscalls"`
}

// Limits are resource limits. Empty strings and zeros mean "no limit".
type Limits struct {
	CPU    float64 `toml:"cpu" json:"cpu,omitempty"`
	Memory string  `toml:"memory" json:"memory,omitempty"`
	PIDs   int64   `toml:"pids" json:"pids,omitempty"`
	Wall   string  `toml:"wall" json:"wall,omitempty"`
}

// Network selects the network mode and its allowlist.
type Network struct {
	Mode  string   `toml:"mode" json:"mode"`
	Allow []string `toml:"allow" json:"allow,omitempty"`
}

// Filesystem selects how the root filesystem is exposed.
type Filesystem struct {
	ReadOnlyRoot bool `toml:"read_only_root" json:"read_only_root"`
}

// Syscalls selects the system call filter.
type Syscalls struct {
	// Filter is "default" (block a deny list) or "off".
	Filter string `toml:"filter" json:"filter"`
}

// Default is the policy used when none is given: no network, read-only root,
// syscall filter on, and limits small enough that a fork bomb or a memory
// hog does not hurt the host.
func Default() Policy {
	return Policy{
		Limits:     Limits{CPU: 1, Memory: "512MiB", PIDs: 256, Wall: "60s"},
		Network:    Network{Mode: string(sandbox.NetworkNone)},
		Filesystem: Filesystem{ReadOnlyRoot: true},
		Syscalls:   Syscalls{Filter: "default"},
	}
}

// Load reads a TOML policy. Fields missing from the file keep their Default value.
func Load(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, err
	}
	return Parse(data)
}

// Parse decodes a TOML policy on top of Default and rejects unknown keys,
// so a typo cannot silently disable a restriction.
func Parse(data []byte) (Policy, error) {
	p := Default()
	md, err := toml.Decode(string(data), &p)
	if err != nil {
		return Policy{}, fmt.Errorf("policy: %w", err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		return Policy{}, fmt.Errorf("policy: unknown keys: %s", strings.Join(keys, ", "))
	}
	return p, nil
}

// Violation is one reason a policy cannot run on a backend.
type Violation struct {
	Field  string
	Reason string
}

func (v Violation) Error() string { return v.Field + ": " + v.Reason }

// Validate checks the policy on its own and against caps, and returns the
// matching sandbox limits and settings. All violations are returned at once,
// joined with errors.Join; each one is a Violation.
func (p Policy) Validate(caps sandbox.Capabilities) (sandbox.Spec, error) {
	var errs []error
	bad := func(field, format string, args ...any) {
		errs = append(errs, Violation{Field: field, Reason: fmt.Sprintf(format, args...)})
	}
	var spec sandbox.Spec

	// Limits.
	if p.Limits.CPU < 0 {
		bad("limits.cpu", "must be >= 0, got %v", p.Limits.CPU)
	} else if p.Limits.CPU > 0 {
		spec.Limits.CPU = p.Limits.CPU
		if !caps.CPULimit {
			bad("limits.cpu", "backend %q cannot limit CPU", caps.Backend)
		}
	}
	if p.Limits.Memory != "" {
		n, err := ParseBytes(p.Limits.Memory)
		switch {
		case err != nil:
			bad("limits.memory", "%v", err)
		case n < 4<<20:
			bad("limits.memory", "below 4MiB is not usable, got %d bytes", n)
		default:
			spec.Limits.MemoryBytes = n
			if !caps.MemoryLimit {
				bad("limits.memory", "backend %q cannot limit memory", caps.Backend)
			}
		}
	}
	if p.Limits.PIDs < 0 {
		bad("limits.pids", "must be >= 0, got %d", p.Limits.PIDs)
	} else if p.Limits.PIDs > 0 {
		spec.Limits.PIDs = p.Limits.PIDs
		if !caps.PIDsLimit {
			bad("limits.pids", "backend %q cannot limit the number of processes", caps.Backend)
		}
	}
	if p.Limits.Wall != "" {
		d, err := time.ParseDuration(p.Limits.Wall)
		switch {
		case err != nil:
			bad("limits.wall", "%v", err)
		case d <= 0:
			bad("limits.wall", "must be positive, got %s", d)
		default:
			spec.Limits.Wall = d
			if !caps.WallTimeout {
				bad("limits.wall", "backend %q cannot enforce a timeout", caps.Backend)
			}
		}
	}

	// Network.
	mode := sandbox.NetworkMode(p.Network.Mode)
	switch mode {
	case sandbox.NetworkNone:
		if len(p.Network.Allow) > 0 {
			bad("network.allow", "must be empty when network.mode is %q", mode)
		}
	case sandbox.NetworkAllowlist:
		if len(p.Network.Allow) == 0 {
			bad("network.allow", "is empty: use mode \"none\" to deny all traffic")
		}
		for _, a := range p.Network.Allow {
			if err := checkDestination(a); err != nil {
				bad("network.allow", "%q: %v", a, err)
			}
		}
	default:
		bad("network.mode", "must be \"none\" or \"allowlist\", got %q", p.Network.Mode)
	}
	if (mode == sandbox.NetworkNone || mode == sandbox.NetworkAllowlist) && !caps.SupportsNetwork(mode) {
		bad("network.mode", "backend %q cannot provide network mode %q", caps.Backend, mode)
	}
	spec.Network = mode
	spec.Allow = append([]string(nil), p.Network.Allow...)

	// Filesystem.
	if p.Filesystem.ReadOnlyRoot && !caps.ReadOnlyRoot {
		bad("filesystem.read_only_root", "backend %q cannot mount the root read-only", caps.Backend)
	}
	spec.ReadOnlyRoot = p.Filesystem.ReadOnlyRoot

	// Syscalls.
	switch p.Syscalls.Filter {
	case "default":
		spec.Seccomp = true
		if !caps.Seccomp {
			bad("syscalls.filter", "backend %q has no syscall filter", caps.Backend)
		}
	case "off":
	default:
		bad("syscalls.filter", "must be \"default\" or \"off\", got %q", p.Syscalls.Filter)
	}

	if len(errs) > 0 {
		return sandbox.Spec{}, errors.Join(errs...)
	}
	return spec, nil
}

// checkDestination accepts "host:port" where host is a DNS name or an IP and
// port is 1-65535. Wildcards and CIDR ranges are refused on purpose.
func checkDestination(s string) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("want host:port: %w", err)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("bad port %q", port)
	}
	if host == "" || strings.ContainsAny(host, "*/ ") {
		return fmt.Errorf("bad host %q (no wildcards or ranges)", host)
	}
	return nil
}

// ParseBytes parses sizes like "512MiB", "1GiB", "64M" or "1048576".
// Decimal (KB, MB, GB) and binary (KiB, MiB, GiB) suffixes are both accepted;
// a bare K, M or G is binary.
func ParseBytes(s string) (int64, error) {
	s = strings.TrimSpace(s)
	units := []struct {
		suffix string
		mult   int64
	}{
		{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30},
		{"KB", 1000}, {"MB", 1000 * 1000}, {"GB", 1000 * 1000 * 1000},
		{"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30}, {"B", 1},
	}
	mult := int64(1)
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			mult = u.mult
			s = strings.TrimSpace(strings.TrimSuffix(s, u.suffix))
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("bad size %q", s)
	}
	if n > (1<<62)/mult {
		return 0, fmt.Errorf("size %q overflows", s)
	}
	return n * mult, nil
}

// Hash is the SHA-256 of the policy in canonical JSON form. Two policies with
// the same effective settings have the same hash, whatever their TOML layout.
func (p Policy) Hash() string {
	b, err := json.Marshal(p)
	if err != nil {
		panic(err) // Policy has only plain fields: Marshal cannot fail.
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
