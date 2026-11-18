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

	"github.com/camilbenameur/sandmeter/sandbox"
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

// Receipt is the record of one command run.
//
// Every field is a struct, slice or scalar, never a map, so encoding/json
// output is deterministic. Keep it that way: Canonical relies on it.
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

// Canonical returns the bytes that get signed: encoding/json of the struct,
// without indentation. It is deterministic because Receipt holds only
// structs, slices and scalars (field order is the declaration order, and
// there are no maps). Policy is a RawMessage, which encoding/json compacts.
//
// Timestamps are converted to UTC first, so the signed bytes do not depend on
// the host time zone.
func Canonical(r Receipt) ([]byte, error) {
	r.StartedAt = r.StartedAt.UTC()
	r.FinishedAt = r.FinishedAt.UTC()
	return json.Marshal(r)
}

// fromV1 gives a decoded v1 receipt the type the rest of the code works
// with. Nothing is lost on the way while that type still has the v1 shape:
// Canonical(fromV1(r)) is the payload r was decoded from, which the tests
// check on the recordings in testdata/v1.
//
// Where the shapes allow it (everywhere but the capabilities, whose network
// modes have a type of their own) a nested struct is converted whole, on
// purpose. The day one of those live types gains, loses or renames a field,
// the conversion stops compiling, and what a v1 receipt means for the new
// shape has to be decided here instead of happening by accident.
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
