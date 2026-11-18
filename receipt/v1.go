package receipt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// This file is the frozen definition of schema "sandmeter.receipt/v1".
//
// Receipts of this schema exist outside this repository and must keep
// verifying. Every struct below is therefore a copy and not an alias: the
// types the rest of the code works with (Receipt, sandbox.Capabilities,
// policy.Policy and so on) are free to change, and changing them cannot
// change how a v1 receipt is decoded.
//
// Nothing here may be edited, reordered or re-tagged, and no field may be
// added: a new field is a new schema. No method may be attached to one of
// these structs either: a method such as UnmarshalJSON would decide how its
// struct is decoded. The recordings in testdata/v1 and the tests in
// v1_test.go pin every name, type, tag and position; a change that makes
// them fail is a change to a published format.

// ReceiptV1 is the signed payload of a schema v1 receipt: the record of one
// command run. Every field is a struct, slice or scalar, never a map, so
// encoding/json writes it back byte for byte.
type ReceiptV1 struct {
	// Schema is SchemaV1.
	Schema string `json:"schema"`
	// ID is 32 hex digits chosen at random for this receipt.
	ID string `json:"id"`
	// Backend is the backend name: "native" or "gvisor".
	Backend string `json:"backend"`
	// Capabilities is what the backend said it enforced on the host.
	Capabilities CapabilitiesV1 `json:"capabilities"`
	// PolicySHA256 is the hex SHA-256 of the bytes of Policy as signed. Check
	// it with PolicyHashV1, never by encoding a decoded policy again.
	PolicySHA256 string `json:"policy_sha256"`
	// Policy is the policy the command ran under, kept as the signed bytes.
	// DecodePolicyV1 reads it.
	Policy json.RawMessage `json:"policy"`
	Image  ImageRefV1      `json:"image"`
	// Argv is the command, verbatim.
	Argv     []string `json:"argv"`
	ExitCode int      `json:"exit_code"`
	// Killed is empty unless the sandbox killed the command; then it is the
	// reason, such as "wall-timeout", "oom" or "cancelled".
	Killed string `json:"killed"`

	// StartedAt and FinishedAt are host clock readings in UTC, taken around
	// the command. DurationMS is measured separately, inside the backend.
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	DurationMS int64     `json:"duration_ms"`

	// StdoutSHA256 and StderrSHA256 are hex SHA-256 sums of the output that
	// was kept. The Truncated flags say when output went over the capture
	// limit and the sums cover only the part before it.
	StdoutSHA256    string `json:"stdout_sha256"`
	StderrSHA256    string `json:"stderr_sha256"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`

	Diff DiffV1 `json:"diff"`
	// Connections lists the outbound flows the host firewall saw, allowed
	// or not. It is an empty list, never null, in receipts the engine wrote.
	Connections []ConnectionV1 `json:"connections"`
	Cgroup      CgroupStatsV1  `json:"cgroup"`
	Host        HostV1         `json:"host"`
}

// CapabilitiesV1 is what a backend declared it could enforce, as schema v1
// records it. A field is true if the backend said it enforced the control.
type CapabilitiesV1 struct {
	// Backend is the backend name, such as "native" or "gvisor".
	Backend string `json:"backend"`
	// Isolation names the mechanism, such as "linux-namespaces".
	Isolation string `json:"isolation"`

	CPULimit    bool `json:"cpu_limit"`
	MemoryLimit bool `json:"memory_limit"`
	PIDsLimit   bool `json:"pids_limit"`
	WallTimeout bool `json:"wall_timeout"`

	// Networks lists the network modes the backend could set up: "none"
	// and "allowlist".
	Networks []string `json:"networks"`

	ReadOnlyRoot bool `json:"read_only_root"`
	Seccomp      bool `json:"seccomp"`
	DropCaps     bool `json:"drop_capabilities"`
	Snapshot     bool `json:"snapshot"`

	// NeedsRoot is true when the backend had to run as root on the host.
	NeedsRoot bool `json:"needs_root"`
	// Notes are host-specific caveats. The field is absent when there are
	// none.
	Notes []string `json:"notes,omitempty"`
}

// ImageRefV1 names the root filesystem image a run started from.
type ImageRefV1 struct {
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
}

// HostV1 describes the machine that ran the sandbox.
type HostV1 struct {
	// Kernel is the system name and release, such as "Linux 6.8.0-generic".
	Kernel string `json:"kernel"`
	// Arch is the GOARCH of the host binary, such as "amd64".
	Arch             string `json:"arch"`
	SandmeterVersion string `json:"sandmeter_version"`
	// BackendVersion is the version of the external runtime a backend
	// wraps, and empty for the native backend.
	BackendVersion string `json:"backend_version"`
}

// DiffV1 is the change set of the writable overlay layer.
type DiffV1 struct {
	// SHA256 is the hex SHA-256 of the JSON encoding (encoding/json, no
	// indentation) of Entries, an empty list being "[]".
	SHA256 string `json:"sha256"`
	// Truncated is set when the entry limit or a hashing budget was reached:
	// the list is then incomplete or holds entries without a content hash.
	Truncated bool      `json:"truncated"`
	Entries   []EntryV1 `json:"entries"`
}

// EntryV1 is one changed path. Path is slash separated and relative to the
// root of the sandbox filesystem.
type EntryV1 struct {
	Path string `json:"path"`
	// Op is "add", "modify", "delete" or "opaque".
	Op string `json:"op"`
	// Type is "file", "dir", "symlink" or "other".
	Type string `json:"type"`
	// Mode holds the permission, setuid, setgid and sticky bits.
	Mode uint32 `json:"mode"`
	Size int64  `json:"size"`
	// SHA256 is the hex SHA-256 of a regular file's content, else empty.
	SHA256 string `json:"sha256"`
	// Target is a symlink target, verbatim.
	Target string `json:"target"`

	// PathEscaped and TargetEscaped are set when the name or the link target
	// was not valid UTF-8. The field then holds the strconv.Quote form of
	// the raw bytes, quotes included.
	PathEscaped   bool `json:"path_escaped,omitempty"`
	TargetEscaped bool `json:"target_escaped,omitempty"`

	// Skipped is empty for a normal entry. Otherwise the entry was recorded
	// without content: "unreadable" or "too_large".
	Skipped string `json:"skipped,omitempty"`
}

// ConnectionV1 is one outbound flow seen by the host firewall.
type ConnectionV1 struct {
	// Proto is "tcp", "udp", "icmp" or the protocol number.
	Proto string `json:"proto"`
	DstIP string `json:"dst_ip"`
	// DstPort is absent for protocols without ports.
	DstPort uint16 `json:"dst_port,omitempty"`
	Allowed bool   `json:"allowed"`
}

// CgroupStatsV1 are the cgroup v2 counters read after the command ended.
type CgroupStatsV1 struct {
	MemoryPeakBytes int64 `json:"memory_peak_bytes"`
	OOMKills        int64 `json:"oom_kills"`
	CPUUsageUsec    int64 `json:"cpu_usage_usec"`
	PIDsPeak        int64 `json:"pids_peak"`
	// PIDsMaxHits counts fork and clone calls refused by pids.max.
	PIDsMaxHits int64 `json:"pids_max_hits"`
}

// PolicyV1 is the policy as a v1 receipt signs it: the JSON form of the
// policy file of the builds that emit schema v1. Zero values that those
// builds leave out of the JSON ("no limit") stay zero here.
type PolicyV1 struct {
	Limits     PolicyLimitsV1     `json:"limits"`
	Network    PolicyNetworkV1    `json:"network"`
	Filesystem PolicyFilesystemV1 `json:"filesystem"`
	Syscalls   PolicySyscallsV1   `json:"syscalls"`
}

// PolicyLimitsV1 are the resource limits of a PolicyV1. An absent field
// means that no limit was asked for.
type PolicyLimitsV1 struct {
	// CPU is a number of cores.
	CPU float64 `json:"cpu,omitempty"`
	// Memory is a size such as "512MiB".
	Memory string `json:"memory,omitempty"`
	PIDs   int64  `json:"pids,omitempty"`
	// Wall is a duration such as "60s".
	Wall string `json:"wall,omitempty"`
}

// PolicyNetworkV1 is the network part of a PolicyV1.
type PolicyNetworkV1 struct {
	// Mode is "none" or "allowlist".
	Mode string `json:"mode"`
	// Allow lists "host:port" destinations for mode "allowlist".
	Allow []string `json:"allow,omitempty"`
}

// PolicyFilesystemV1 is the filesystem part of a PolicyV1.
type PolicyFilesystemV1 struct {
	ReadOnlyRoot bool `json:"read_only_root"`
}

// PolicySyscallsV1 is the system call part of a PolicyV1.
type PolicySyscallsV1 struct {
	// Filter is "default" (a deny list) or "off".
	Filter string `json:"filter"`
}

// DecodeV1 decodes the signed payload of a schema v1 receipt. It is strict:
// an unknown field, data after the receipt or another schema string is an
// error. It does not check the signature; Verify does, then calls it.
func DecodeV1(payload []byte) (ReceiptV1, error) {
	var r ReceiptV1
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return ReceiptV1{}, fmt.Errorf("decode receipt: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return ReceiptV1{}, errors.New("decode receipt: trailing data")
	}
	if r.Schema != SchemaV1 {
		return ReceiptV1{}, fmt.Errorf("unsupported schema %q", r.Schema)
	}
	return r, nil
}

// PolicyHashV1 returns the value the policy_sha256 field of a v1 receipt
// must hold for the given policy field: the hex SHA-256 of the bytes exactly
// as they stand in the signed payload.
//
// The hash is over bytes on purpose. Decoding the policy into a struct and
// encoding it again gives the same bytes only for as long as that struct
// never changes: the day it gains a field, every receipt written before
// would stop matching its own hash.
func PolicyHashV1(policy []byte) string {
	sum := sha256.Sum256(policy)
	return hex.EncodeToString(sum[:])
}

// DecodePolicyV1 decodes the policy field of a v1 receipt. It is strict in
// the same way as DecodeV1. Fields the receipt leaves out are zero, which
// in a v1 policy means "no limit".
func DecodePolicyV1(policy []byte) (PolicyV1, error) {
	var p PolicyV1
	dec := json.NewDecoder(bytes.NewReader(policy))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return PolicyV1{}, fmt.Errorf("decode v1 policy: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return PolicyV1{}, errors.New("decode v1 policy: trailing data")
	}
	return p, nil
}
