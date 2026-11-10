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

	"github.com/camilbenameur/ringfence/sandbox"
)

// SchemaV1 is the value of Receipt.Schema for this format.
const SchemaV1 = "ringfence.receipt/v1"

// ImageRef names the root filesystem image a run started from.
type ImageRef struct {
	Ref    string `json:"ref"`
	Digest string `json:"digest"`
}

// Host describes the machine that ran the sandbox.
type Host struct {
	Kernel           string `json:"kernel"`
	Arch             string `json:"arch"`
	RingfenceVersion string `json:"ringfence_version"`
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
