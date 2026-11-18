// Package policy defines the sandbox policy: what a command may consume, what
// it may reach, and which protections surround it.
//
// A policy is a TOML file. Three forms of it exist in this package:
//
//   - Policy is the file as written, schema v2. A field that the file leaves
//     out is zero here and means "the built-in default, clamped to the
//     operator's ceiling"; it never means "no limit".
//   - Ceiling is the operator's maximum: a policy read as upper bounds. It
//     lives in the operator file, which only root can write. A client policy
//     is accepted only if Within finds nothing above it.
//   - Normal is the policy in force: every field resolved, every size in
//     bytes, every duration in nanoseconds, destinations parsed, sorted and
//     de-duplicated. A receipt embeds the canonical bytes of the Normal the
//     command ran under, and the policy hash is taken over those bytes.
//
// # Who decides what
//
// The policy is checked on the root side, for the calling user, whatever the
// client did before: a client may check its own file to print a good message,
// and that check counts for nothing. A policy is refused, before anything
// runs, when one of these finds a reason:
//
//  1. Parse: an unknown key, a wrong type, a value that is not a finite
//     number.
//  2. Within: a field above the ceiling. Every such field is listed.
//  3. Check: a control the policy needs that the chosen backend does not
//     enforce on this host, or a value under the backend's minimum. The input
//     is a Capabilities value, which a host probe produced.
//
// "Unlimited" is never a default. It has to be written, as the word
// "unlimited", in the policy and in the ceiling above it.
//
// # Schema versions
//
// A file with version = 2 is schema v2 and decodes into Policy. Unknown keys
// are errors in every version, so that a typo cannot switch a protection off.
//
// A file with no version key, or with version = 1, is schema v1. It keeps
// working, mapped onto v2 as follows:
//
//   - limits.cpu, limits.memory, limits.pids and limits.wall keep their
//     meaning. In v1 a limit written as zero or as an empty string meant "no
//     limit": it maps to "unlimited", which the ceiling must grant. A limit
//     the file leaves out takes the built-in default, as before.
//   - network.mode = "none" keeps its meaning. network.mode = "allowlist" is
//     refused with a message that names mode = "proxy": the v1 list allowed
//     addresses for any TCP client, the v2 list allows names through an HTTP
//     proxy, and one cannot be read as the other.
//   - filesystem.read_only_root keeps its meaning.
//   - syscalls.filter = "default" maps to syscalls.profile = "default" and
//     "off" to "off". The default profile of v2 is stricter than the v1
//     filter; a tool it breaks can ask for profile = "compat".
//
// The Normal of a v1 file is a v2 Normal like any other. Receipts of schema
// v1, written by earlier builds, embed the v1 policy in its own frozen form
// and are verified against those bytes; nothing here re-encodes them.
//
// # Stability
//
// This package and package receipt are the only parts of sandmeter that
// other programs may import. They import nothing from sandmeter's internal
// packages and none of their exported identifiers mentions an internal type.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// Version2 is the value of the version key of a schema v2 policy file.
const Version2 = 2

// Unlimited is the word that asks for, or grants, the absence of a limit.
// It is accepted wherever a limit is written.
const Unlimited = "unlimited"

// Network modes, the values of network.mode.
const (
	// NetworkNone gives the sandbox a network namespace with a loopback
	// interface and nothing else. No packet leaves it.
	NetworkNone = "none"
	// NetworkProxy adds one way out: an HTTP proxy listening on the sandbox's
	// loopback, which forwards CONNECT and plain HTTP requests to the names
	// in network.allow and to no other. There is still no route: a program
	// that does not use the proxy reaches nothing.
	NetworkProxy = "proxy"
)

// Storage modes, the values of storage.upper: where the writable layer of
// the sandbox lives.
const (
	// UpperDisk keeps the writable layer in a directory of the state
	// filesystem. There is no per-sandbox quota in this mode; a free-space
	// floor on that filesystem guards the host. limits.disk is refused.
	UpperDisk = "disk"
	// UpperTmpfs keeps the writable layer in memory, on a tmpfs whose size
	// and inode count are limits.disk. It is a hard quota, and it is charged
	// to the sandbox's memory limit.
	UpperTmpfs = "tmpfs"
)

// Syscall profiles, the values of syscalls.profile, from strictest to
// weakest.
const (
	// ProfileDefault is an allow list: a system call that is not listed is
	// refused.
	ProfileDefault = "default"
	// ProfileCompat is a deny list: a system call that is not listed is
	// allowed. It is for tools the default profile breaks.
	ProfileCompat = "compat"
	// ProfileOff installs no filter. Only a ceiling can grant it.
	ProfileOff = "off"
)

// Policy is a policy file of schema v2, as written. The zero Policy is the
// file with nothing in it: every field takes its built-in default.
//
// The TOML tags are the keys of the file. The JSON tags give the same
// document a JSON form for tools; that form is not what a receipt embeds
// (see Normal).
type Policy struct {
	// Version is 2. Parse sets it to 2 for a v1 file it mapped.
	Version    int        `toml:"version" json:"version"`
	Limits     Limits     `toml:"limits" json:"limits"`
	Storage    Storage    `toml:"storage" json:"storage"`
	Network    Network    `toml:"network" json:"network"`
	Filesystem Filesystem `toml:"filesystem" json:"filesystem"`
	Syscalls   Syscalls   `toml:"syscalls" json:"syscalls"`
	Process    Process    `toml:"process" json:"process"`
	Workspace  Workspace  `toml:"workspace" json:"workspace"`
}

// Limits are the resource limits of a sandbox. Each one is a value, the word
// "unlimited", or absent. They bound the session as a whole (every process
// of every command), except Wall, which bounds one command.
type Limits struct {
	// CPU is a number of cores, such as 0.5 or 2. Built-in default: 1.
	CPU Number `toml:"cpu" json:"cpu,omitzero"`
	// Memory is a size such as "512MiB", or "unlimited". Swap is always
	// refused to the sandbox, so this is its whole memory. Built-in
	// default: "512MiB".
	Memory string `toml:"memory" json:"memory,omitempty"`
	// PIDs is the maximum number of tasks (processes and threads), a whole
	// number. Built-in default: 256.
	PIDs Number `toml:"pids" json:"pids,omitzero"`
	// Wall is the longest one command may run, as a duration such as "60s"
	// or "10m", or "unlimited". Built-in default: "60s".
	Wall string `toml:"wall" json:"wall,omitempty"`
	// Disk is the size of the writable layer, such as "1GiB". It is a hard
	// quota and exists only with storage.upper = "tmpfs"; with any other
	// storage mode a policy that sets it is refused. Absent by default,
	// which with storage.upper = "tmpfs" means the ceiling's value.
	Disk string `toml:"disk" json:"disk,omitempty"`
}

// Storage selects where the writable layer lives.
type Storage struct {
	// Upper is UpperDisk or UpperTmpfs. Built-in default: UpperDisk.
	Upper string `toml:"upper" json:"upper,omitempty"`
}

// Network selects what the sandbox can reach.
type Network struct {
	// Mode is NetworkNone or NetworkProxy. Built-in default: NetworkNone.
	Mode string `toml:"mode" json:"mode,omitempty"`
	// Allow lists the destinations the proxy forwards to, in the grammar of
	// ParseDest: "name", "name:port", "*.suffix:port". It must be empty
	// unless Mode is NetworkProxy, and must not be empty when it is.
	Allow []string `toml:"allow" json:"allow,omitempty"`
}

// Filesystem selects how the root filesystem is exposed.
type Filesystem struct {
	// ReadOnlyRoot, when true, makes the root filesystem read-only except
	// /tmp and /workspace. Nil is the built-in default, true. A policy that
	// writes false asks for a writable root, which the ceiling must grant.
	ReadOnlyRoot *bool `toml:"read_only_root" json:"read_only_root,omitempty"`
}

// Syscalls selects the system call filter.
type Syscalls struct {
	// Profile is ProfileDefault, ProfileCompat or ProfileOff. Built-in
	// default: ProfileDefault.
	Profile string `toml:"profile" json:"profile,omitempty"`
}

// Process describes the commands that run in the sandbox.
type Process struct {
	// Env sets environment variables to literal values. The values are part
	// of the policy: they are hashed, embedded in receipts and readable by
	// whoever reads those. A secret does not belong here; see EnvPass.
	Env map[string]string `toml:"env" json:"env,omitempty"`
	// EnvPass names variables whose values are taken from the environment of
	// the client that starts the session. A receipt records the names, never
	// the values. Each name must be granted by the ceiling. An agent that
	// reaches sandmeter through MCP cannot add a name: the list comes from
	// the policy file a human chose when registering the server.
	EnvPass []string `toml:"env_pass" json:"env_pass,omitempty"`
	// Workdir is the working directory of commands, an absolute path inside
	// the sandbox. Empty means the image's own, or /workspace when a project
	// was imported.
	Workdir string `toml:"workdir" json:"workdir,omitempty"`
}

// Workspace describes the import of the project directory.
type Workspace struct {
	// Exclude lists patterns of paths, relative to the project directory,
	// that the client leaves out when it packs the project. The client
	// applies them; the root side never sees the excluded files. The order
	// is kept as written.
	Exclude []string `toml:"exclude" json:"exclude,omitempty"`
}

// Ceiling is the operator's maximum: the keys of a policy read as upper
// bounds. It is the [ceiling] table of the operator file and is decoded with
// the same tags.
//
// How each field bounds a policy:
//
//   - Limits: a policy value must be at most the ceiling's. "unlimited" in a
//     policy needs "unlimited" here. A field this struct leaves unset takes a
//     finite built-in value; it never means unlimited.
//   - Storage.Upper: UpperTmpfs grants both storage modes; UpperDisk, or
//     nothing, grants UpperDisk only.
//   - Network.Mode: NetworkProxy grants both modes; NetworkNone, or nothing,
//     grants NetworkNone only. Network.Allow lists the destinations a policy
//     may name: every entry of the policy must be covered by an entry here
//     (see Dest.Covers).
//   - Filesystem.ReadOnlyRoot: false grants a writable root; true, or
//     nothing, requires a read-only one.
//   - Syscalls.Profile: the weakest profile a policy may ask for.
//   - Process.EnvPass: the names a policy may pass from the client's
//     environment, each written out in full. There is no pattern.
//
// The built-in ceiling, used when there is no operator file, is what
// BuiltinCeiling returns: the default limits, no network, no passed variable,
// ProfileCompat at the weakest and a read-only root.
type Ceiling struct {
	Limits     Limits         `toml:"limits" json:"limits"`
	Storage    Storage        `toml:"storage" json:"storage"`
	Network    Network        `toml:"network" json:"network"`
	Filesystem Filesystem     `toml:"filesystem" json:"filesystem"`
	Syscalls   Syscalls       `toml:"syscalls" json:"syscalls"`
	Process    CeilingProcess `toml:"process" json:"process"`
}

// CeilingProcess is the part of Process that a ceiling bounds.
type CeilingProcess struct {
	// EnvPass lists the variable names a policy may pass. Empty grants none.
	EnvPass []string `toml:"env_pass" json:"env_pass,omitempty"`
}

// Violation is one reason a policy is refused.
type Violation struct {
	// Key is the policy key at fault in dotted form, such as "limits.memory"
	// or "network.allow[2]". It is a key of the schema, never text taken
	// from the policy.
	Key string `json:"key"`
	// Reason says in one sentence what is wrong and what refuses it: the
	// bound of the ceiling, or the fact about this host.
	Reason string `json:"reason"`
}

// Error implements error.
func (v Violation) Error() string { return v.Key + ": " + v.Reason }

// Violations is every reason a policy is refused, in the order of the keys
// in the schema. An empty list means the policy is accepted.
//
// Functions return it as a Violations, not as an error, because a nil
// Violations stored in an error is not a nil error. Use Err to get one.
type Violations []Violation

// Err returns nil when the list is empty and the list as an error otherwise.
func (vs Violations) Err() error {
	if len(vs) == 0 {
		return nil
	}
	return vs
}

// Error implements error: one violation per line.
func (vs Violations) Error() string {
	lines := make([]string, len(vs))
	for i, v := range vs {
		lines[i] = v.Error()
	}
	return strings.Join(lines, "\n")
}

// Keys returns the violated keys, in order.
func (vs Violations) Keys() []string {
	keys := make([]string, len(vs))
	for i, v := range vs {
		keys[i] = v.Key
	}
	return keys
}

// Normal is a policy in normalised form: the policy in force for a session,
// with nothing left to resolve. Effective produces it from a Policy and a
// Ceiling.
//
// Its canonical encoding (Canonical) is what a receipt embeds, and Hash is
// taken over those bytes. A verifier checks the hash against the embedded
// bytes as they stand in the signed payload and never encodes a decoded
// policy again: the bytes are the policy.
//
// In a limit, nil means "unlimited": the policy asked for it and the ceiling
// granted it. No field of a Normal means "not set".
type Normal struct {
	// Version is 2.
	Version    int              `json:"version"`
	Limits     NormalLimits     `json:"limits"`
	Storage    Storage          `json:"storage"`
	Network    NormalNetwork    `json:"network"`
	Filesystem NormalFilesystem `json:"filesystem"`
	Syscalls   Syscalls         `json:"syscalls"`
	Process    NormalProcess    `json:"process"`
	Workspace  NormalWorkspace  `json:"workspace"`
}

// NormalLimits are resolved limits. Nil is unlimited.
type NormalLimits struct {
	// CPUMillis is the CPU limit in thousandths of a core: 1500 is one core
	// and a half. Whole numbers keep the canonical bytes free of floating
	// point spellings.
	CPUMillis *int64 `json:"cpu_millis"`
	// MemoryBytes is the memory limit in bytes.
	MemoryBytes *int64 `json:"memory_bytes"`
	// PIDs is the maximum number of tasks.
	PIDs *int64 `json:"pids"`
	// WallNanos is the longest a command may run, in nanoseconds.
	WallNanos *int64 `json:"wall_ns"`
	// DiskBytes is the quota of the writable layer in bytes. Nil means no
	// quota, which is the only possible value with Storage.Upper = UpperDisk.
	DiskBytes *int64 `json:"disk_bytes"`
}

// NormalNetwork is the resolved network part.
type NormalNetwork struct {
	// Mode is NetworkNone or NetworkProxy.
	Mode string `json:"mode"`
	// Allow is the allow list, parsed, de-duplicated and sorted by its
	// canonical text. It is empty, never nil, with NetworkNone.
	Allow []Dest `json:"allow"`
}

// NormalFilesystem is the resolved filesystem part.
type NormalFilesystem struct {
	ReadOnlyRoot bool `json:"read_only_root"`
}

// NormalProcess is the resolved process part.
type NormalProcess struct {
	// Env holds the literal variables of the policy. encoding/json writes
	// the keys of a map in sorted order, so the bytes are deterministic. It
	// is empty, never nil.
	Env map[string]string `json:"env"`
	// EnvPass holds the names passed from the client's environment, sorted
	// and de-duplicated. Never the values. It is empty, never nil.
	EnvPass []string `json:"env_pass"`
	// Workdir is the working directory, or empty for the image's own.
	Workdir string `json:"workdir"`
}

// NormalWorkspace is the resolved workspace part.
type NormalWorkspace struct {
	// Exclude holds the exclusion patterns in the order written. It is
	// empty, never nil.
	Exclude []string `json:"exclude"`
}

// Canonical returns the canonical bytes of n: its encoding/json form without
// indentation. It is deterministic because Normal holds structs, sorted
// slices, scalars and one map, whose keys encoding/json sorts.
//
// The producer of a receipt calls this once and embeds the result. Nobody
// who verifies a receipt needs to reproduce it.
func (n Normal) Canonical() ([]byte, error) {
	if n.Network.Allow == nil {
		n.Network.Allow = []Dest{}
	}
	if n.Process.Env == nil {
		n.Process.Env = map[string]string{}
	}
	if n.Process.EnvPass == nil {
		n.Process.EnvPass = []string{}
	}
	if n.Workspace.Exclude == nil {
		n.Workspace.Exclude = []string{}
	}
	return json.Marshal(n)
}

// Hash returns the policy hash of n: the lower-case hexadecimal SHA-256 of
// Canonical.
func (n Normal) Hash() (string, error) {
	b, err := n.Canonical()
	if err != nil {
		return "", err
	}
	return HashBytes(b), nil
}

// HashBytes returns the policy hash of canonical policy bytes as they stand
// in a signed payload: their lower-case hexadecimal SHA-256. This is the
// function a verifier uses.
func HashBytes(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}
