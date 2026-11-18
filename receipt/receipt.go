// Package receipt records one command run in a sandbox as a signed file.
//
// A receipt holds the policy, image, command, exit status, resource counters,
// network flows and a diff of the writable overlay layer. It is wrapped in a
// DSSE envelope and signed with an Ed25519 key.
//
// What a signature proves: the receipt was not modified after the host signed
// it, and which key signed it. What it does NOT prove: that the host was
// honest, that the sandbox held, or that the recorded facts are true. There
// is no attestation of the host or the backend here. This is an educational
// prototype.
package receipt

import (
	"encoding/json"
	"time"

	"github.com/camilbenameur/sandmeter/internal/prototype/sandbox"
)

// SchemaV1 is the value of Receipt.Schema for this format.
const SchemaV1 = "sandmeter.receipt/v1"

// ImageRef names the root filesystem image a run started from.
type ImageRef struct {
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
}

// Host describes the machine that ran the sandbox.
type Host struct {
	Kernel           string `json:"kernel"`
	Arch             string `json:"arch"`
	SandmeterVersion string `json:"sandmeter_version"`
	BackendVersion   string `json:"backend_version"`
}

// Receipt is the record of one command run, in the form the rest of the code
// works with.
//
// It is not the form that is signed. Canonical encodes ReceiptV1, the frozen
// copy in v1.go, so a change to this struct or to a type it embeds does not
// by itself change a signed byte.
type Receipt struct {
	Schema       string               `json:"schema"`
	ID           string               `json:"id"`
	Backend      string               `json:"backend"`
	Capabilities sandbox.Capabilities `json:"capabilities"`
	PolicySHA256 string               `json:"policy_sha256"`
	Policy       json.RawMessage      `json:"policy"`
	Image        ImageRef             `json:"image"`
	Argv         []string             `json:"argv"`
	ExitCode     int                  `json:"exit_code"`
	Killed       string               `json:"killed"`

	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	DurationMS int64     `json:"duration_ms"`

	StdoutSHA256    string `json:"stdout_sha256"`
	StderrSHA256    string `json:"stderr_sha256"`
	StdoutTruncated bool   `json:"stdout_truncated"`
	StderrTruncated bool   `json:"stderr_truncated"`

	Diff        Diff                 `json:"diff"`
	Connections []sandbox.Connection `json:"connections"`
	Cgroup      sandbox.CgroupStats  `json:"cgroup"`
	Host        Host                 `json:"host"`
}

// Diff is the change set of a writable overlay layer.
type Diff struct {
	// SHA256 is the hex sha256 of the canonical JSON (encoding/json, no
	// indentation) of Entries in the form a receipt signs them, EntryV1,
	// with a nil slice encoded as [].
	SHA256    string  `json:"sha256"`
	Truncated bool    `json:"truncated"`
	Entries   []Entry `json:"entries"`
}

// Entry is one changed path. Path is slash separated and relative to the root.
type Entry struct {
	Path string `json:"path"`
	// Op is "add", "modify", "delete" or "opaque".
	Op string `json:"op"`
	// Type is "file", "dir", "symlink" or "other".
	Type   string `json:"type"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	// Target is a symlink target, verbatim. It is never resolved or opened.
	Target string `json:"target"`

	// PathEscaped and TargetEscaped are set when the name or link target is
	// not valid UTF-8. JSON would silently replace the bad bytes, so two
	// different names could collide in the signed record. The field then holds
	// the strconv.Quote form (\xff style escapes) instead of the raw bytes.
	PathEscaped   bool `json:"path_escaped,omitempty"`
	TargetEscaped bool `json:"target_escaped,omitempty"`

	// Skipped is empty for a normal entry. Otherwise the entry is recorded
	// without content: "unreadable" (permission error, type swapped during
	// the walk, I/O error) or "too_large" (over the hashing budget). A
	// hostile program must not be able to suppress the diff by making one
	// entry hard to read, so such entries are listed instead of failing.
	Skipped string `json:"skipped,omitempty"`
}

// Canonical returns the bytes that get signed: encoding/json of the frozen
// v1 form of the receipt, without indentation. It is deterministic because
// ReceiptV1 holds only structs, slices and scalars (field order is the
// declaration order, and there are no maps). Policy is a RawMessage, which
// encoding/json compacts.
//
// What is signed goes through the frozen structs so that it is always
// something DecodeV1 reads back: a field that Receipt or a type it embeds
// gains later cannot slip into a receipt that says it is v1.
//
// Timestamps are converted to UTC first, so the signed bytes do not depend on
// the host time zone.
func Canonical(r Receipt) ([]byte, error) {
	v := toV1(r)
	v.StartedAt = v.StartedAt.UTC()
	v.FinishedAt = v.FinishedAt.UTC()
	return json.Marshal(v)
}

// fromV1 and toV1 carry a receipt between its frozen v1 form, which is what
// is signed and decoded, and the type the rest of the code works with. While
// that type can hold everything a v1 receipt does, the two are inverses and
// nothing is lost either way: Canonical(fromV1(r)) is the payload r was
// decoded from, which the tests check on the recordings in testdata/v1.
//
// A nested struct is converted whole wherever its two shapes agree type for
// type, on purpose: the day the live one gains, loses, renames or retypes a
// field, the conversion stops compiling. Three structs cannot be converted
// whole and are copied field by field: the receipt itself, the capabilities
// (their network modes have a type of their own) and the diff (so have its
// entries). The declarations under the two functions do for those three what
// the conversions do for the others. Either way, what a v1 receipt holds for
// a new shape has to be decided here instead of happening by accident.

// fromV1 gives a decoded v1 receipt the type the rest of the code works with.
func fromV1(r ReceiptV1) Receipt {
	caps := r.Capabilities
	return Receipt{
		Schema:  r.Schema,
		ID:      r.ID,
		Backend: r.Backend,
		Capabilities: sandbox.Capabilities{
			Backend:      caps.Backend,
			Isolation:    caps.Isolation,
			CPULimit:     caps.CPULimit,
			MemoryLimit:  caps.MemoryLimit,
			PIDsLimit:    caps.PIDsLimit,
			WallTimeout:  caps.WallTimeout,
			Networks:     mapSlice(caps.Networks, func(m string) sandbox.NetworkMode { return sandbox.NetworkMode(m) }),
			ReadOnlyRoot: caps.ReadOnlyRoot,
			Seccomp:      caps.Seccomp,
			DropCaps:     caps.DropCaps,
			Snapshot:     caps.Snapshot,
			NeedsRoot:    caps.NeedsRoot,
			Notes:        caps.Notes,
		},
		PolicySHA256:    r.PolicySHA256,
		Policy:          r.Policy,
		Image:           ImageRef(r.Image),
		Argv:            r.Argv,
		ExitCode:        r.ExitCode,
		Killed:          r.Killed,
		StartedAt:       r.StartedAt,
		FinishedAt:      r.FinishedAt,
		DurationMS:      r.DurationMS,
		StdoutSHA256:    r.StdoutSHA256,
		StderrSHA256:    r.StderrSHA256,
		StdoutTruncated: r.StdoutTruncated,
		StderrTruncated: r.StderrTruncated,
		Diff: Diff{
			SHA256:    r.Diff.SHA256,
			Truncated: r.Diff.Truncated,
			Entries:   mapSlice(r.Diff.Entries, func(e EntryV1) Entry { return Entry(e) }),
		},
		Connections: mapSlice(r.Connections, func(c ConnectionV1) sandbox.Connection { return sandbox.Connection(c) }),
		Cgroup:      sandbox.CgroupStats(r.Cgroup),
		Host:        Host(r.Host),
	}
}

// toV1 gives a receipt its frozen v1 form, the one Canonical encodes.
func toV1(r Receipt) ReceiptV1 {
	caps := r.Capabilities
	return ReceiptV1{
		Schema:  r.Schema,
		ID:      r.ID,
		Backend: r.Backend,
		Capabilities: CapabilitiesV1{
			Backend:      caps.Backend,
			Isolation:    caps.Isolation,
			CPULimit:     caps.CPULimit,
			MemoryLimit:  caps.MemoryLimit,
			PIDsLimit:    caps.PIDsLimit,
			WallTimeout:  caps.WallTimeout,
			Networks:     mapSlice(caps.Networks, func(m sandbox.NetworkMode) string { return string(m) }),
			ReadOnlyRoot: caps.ReadOnlyRoot,
			Seccomp:      caps.Seccomp,
			DropCaps:     caps.DropCaps,
			Snapshot:     caps.Snapshot,
			NeedsRoot:    caps.NeedsRoot,
			Notes:        caps.Notes,
		},
		PolicySHA256:    r.PolicySHA256,
		Policy:          r.Policy,
		Image:           ImageRefV1(r.Image),
		Argv:            r.Argv,
		ExitCode:        r.ExitCode,
		Killed:          r.Killed,
		StartedAt:       r.StartedAt,
		FinishedAt:      r.FinishedAt,
		DurationMS:      r.DurationMS,
		StdoutSHA256:    r.StdoutSHA256,
		StderrSHA256:    r.StderrSHA256,
		StdoutTruncated: r.StdoutTruncated,
		StderrTruncated: r.StderrTruncated,
		Diff: DiffV1{
			SHA256:    r.Diff.SHA256,
			Truncated: r.Diff.Truncated,
			Entries:   mapSlice(r.Diff.Entries, func(e Entry) EntryV1 { return EntryV1(e) }),
		},
		Connections: mapSlice(r.Connections, func(c sandbox.Connection) ConnectionV1 { return ConnectionV1(c) }),
		Cgroup:      CgroupStatsV1(r.Cgroup),
		Host:        HostV1(r.Host),
	}
}

// The three live structs that fromV1 and toV1 copy field by field have
// exactly the fields listed here, in this order and with these types (tags
// do not count): the conversions below do not compile otherwise.
//
// A keyed literal alone does not notice a new field. It would compile, and
// the field would silently be zero in every v1 receipt that Verify returns
// and absent from every receipt that is signed. When one of these stops
// compiling, decide in fromV1 and toV1 what a v1 receipt holds for the new
// shape, then bring the list in line.
var (
	_ = struct {
		Schema          string
		ID              string
		Backend         string
		Capabilities    sandbox.Capabilities
		PolicySHA256    string
		Policy          json.RawMessage
		Image           ImageRef
		Argv            []string
		ExitCode        int
		Killed          string
		StartedAt       time.Time
		FinishedAt      time.Time
		DurationMS      int64
		StdoutSHA256    string
		StderrSHA256    string
		StdoutTruncated bool
		StderrTruncated bool
		Diff            Diff
		Connections     []sandbox.Connection
		Cgroup          sandbox.CgroupStats
		Host            Host
	}(Receipt{})
	_ = struct {
		Backend      string
		Isolation    string
		CPULimit     bool
		MemoryLimit  bool
		PIDsLimit    bool
		WallTimeout  bool
		Networks     []sandbox.NetworkMode
		ReadOnlyRoot bool
		Seccomp      bool
		DropCaps     bool
		Snapshot     bool
		NeedsRoot    bool
		Notes        []string
	}(sandbox.Capabilities{})
	_ = struct {
		SHA256    string
		Truncated bool
		Entries   []Entry
	}(Diff{})
)

// mapSlice converts a slice element by element and keeps nil apart from
// empty: the two encode differently ("null" and "[]") and a signed receipt
// can hold either.
func mapSlice[A, B any](in []A, f func(A) B) []B {
	if in == nil {
		return nil
	}
	out := make([]B, len(in))
	for i, v := range in {
		out[i] = f(v)
	}
	return out
}
