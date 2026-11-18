package receipt

import (
	"encoding/json"
	"time"
)

// This file declares schema "sandmeter.receipt/v2": the wire structs, and
// nothing that decides how they are produced or checked.
//
// Every struct here is owned by this package. None is an alias of a type the
// engine or a backend works with, so that a change over there cannot change a
// signed byte.
//
// Schema v2 is under the rule the package comment states: no field is added
// to these structs, none is removed, renamed, re-tagged or given another
// type. A change of any kind is schema v3, in a file of its own.
//
// # What a v2 receipt is
//
// A session is a chain of records. Each record is one DSSE envelope whose
// payload is the JSON encoding of a RecordV2. The first record of a session
// has sequence number 1; each later one carries the SHA-256 of the payload
// bytes of the record before it, exactly as they were signed. A record that
// is missing in the middle, reordered or replaced breaks the chain. A record
// missing at the end does not: a chain proves nothing about what came after
// its last record, and a session whose last record is not of kind "stop"
// may have lost its tail.
//
// There are six kinds of record:
//
//   - "command": a command ran, or was to run and the sandbox could not be
//     set up. One is written for every command for which a sandbox was
//     created, whatever failed afterwards.
//   - "snapshot" and "restore": the writable layer was frozen, or reset.
//   - "export": the changes of the workspace left the service as a change
//     set, whose manifest hash the record carries.
//   - "stop": the session ended in an orderly way.
//   - "interrupted": a command was about to start and no record of its end
//     exists, because the service died. The record is written at the next
//     start from the intent that was put on disk before the command began
//     (IntentV2), and it takes the sequence number the command would have
//     had.
//
// # Three values, never a zero that means "unknown"
//
// A measurement that could not be taken is null, and where a list could be
// incomplete a field says so. A verifier must treat null as "not measured"
// and must not read it as zero.
//
// # What only the service saw
//
// Every record states what the root side observed. Nothing a client reports
// about itself (that it applied a change set, for instance) is ever signed
// here.

// SchemaV2 is the value of RecordV2.Schema.
const SchemaV2 = "sandmeter.receipt/v2"

// IntentSchemaV2 is the value of IntentV2.Schema.
const IntentSchemaV2 = "sandmeter.intent/v2"

// Record kinds, the values of RecordV2.Kind.
const (
	KindCommand     = "command"
	KindSnapshot    = "snapshot"
	KindRestore     = "restore"
	KindExport      = "export"
	KindStop        = "stop"
	KindInterrupted = "interrupted"
)

// Statuses of a command, the values of OutcomeV2.Status.
const (
	// StatusExited: the command ran and ended by itself. ExitCode is set.
	StatusExited = "exited"
	// StatusSignalled: a signal that the sandbox did not send ended the
	// command. Signal is set.
	StatusSignalled = "signalled"
	// StatusKilled: the sandbox ended the command. KillReason is set.
	StatusKilled = "killed"
	// StatusExecFailed: the sandbox was set up and the command could not be
	// started in it. ExitCode is 126 (found, cannot be executed) or 127 (not
	// found), and Error says why.
	StatusExecFailed = "exec-failed"
	// StatusSetupFailed: the sandbox could not be set up. No process of the
	// command existed. Error says why.
	StatusSetupFailed = "setup-failed"
)

// Reasons the sandbox ended a command, the values of OutcomeV2.KillReason.
const (
	// KillWallTimeout: the command ran longer than its time limit.
	KillWallTimeout = "wall-timeout"
	// KillOOM: the kernel killed the sandbox for exceeding its memory limit.
	KillOOM = "oom"
	// KillCancelled: the client cancelled the command, or went away.
	KillCancelled = "cancelled"
	// KillStopped: the session was stopped while the command ran.
	KillStopped = "stopped"
	// KillDiskFloor: free space on the state filesystem fell under the
	// operator's floor while the command ran.
	KillDiskFloor = "disk-floor"
	// KillSupervisorLost: the process that supervised the sandbox from the
	// host went away, and the sandbox ended itself.
	KillSupervisorLost = "supervisor-lost"
	// KillInitLost: the first process of the sandbox ended without reporting
	// how the command ended. What the command did before is unknown.
	KillInitLost = "init-lost"
)

// Scopes of the counters, the values of CountersV2.Scope: which processes the
// numbers cover besides the command itself.
const (
	ScopeWorkload        = "workload"
	ScopeInitAndWorkload = "init+workload"
	ScopeRuntimeAndLoad  = "runtime+workload"
)

// Verdicts of a flow, the values of FlowV2.Verdict.
const (
	VerdictAllowed = "allowed"
	VerdictDenied  = "denied"
)

// Reasons of a denied or failed flow, the values of FlowV2.Reason. An allowed
// flow that completed has an empty reason.
const (
	// FlowNotAllowed: the name and port are not in the allow list. No name
	// was resolved and no connection was made.
	FlowNotAllowed = "not-allowed"
	// FlowSpecialAddress: the address about to be dialled is a loopback,
	// link-local, private, shared, reserved, multicast or metadata address,
	// one of the host's own, or one the operator denies.
	FlowSpecialAddress = "special-address"
	// FlowSNIMismatch: the TLS handshake inside the tunnel named another
	// server than the request did.
	FlowSNIMismatch = "sni-mismatch"
	// FlowNotTLS: the destination requires TLS and the first bytes of the
	// tunnel were not a TLS handshake.
	FlowNotTLS = "not-tls"
	// FlowBadRequest: the request was not one the proxy serves, or its
	// target is not a valid destination.
	FlowBadRequest = "bad-request"
	// FlowResolveFailed: the name is allowed and did not resolve.
	FlowResolveFailed = "resolve-failed"
	// FlowDialFailed: the name is allowed and the connection failed.
	FlowDialFailed = "dial-failed"
	// FlowLimit: a bound of the proxy was reached (concurrent tunnels,
	// header size, a timeout).
	FlowLimit = "limit"
)

// Operations, types and statuses of a diff.
const (
	OpAdd    = "add"
	OpModify = "modify"
	OpDelete = "delete"
	OpOpaque = "opaque"

	TypeFile    = "file"
	TypeDir     = "dir"
	TypeSymlink = "symlink"
	TypeOther   = "other"

	// DiffComplete: every change is listed.
	DiffComplete = "complete"
	// DiffTruncated: a budget was reached. The counts are exact; the list of
	// entries is not, or holds entries without a content hash.
	DiffTruncated = "truncated"
	// DiffError: the diff could not be computed. Reason says why.
	DiffError = "error"

	// BaseImage: the diff is relative to the image and the imported
	// workspace.
	BaseImage = "image"
	// BaseSnapshot: the diff is relative to a snapshot of the session.
	BaseSnapshot = "snapshot"
)

// Reasons a session ended, the values of StopV2.Reason.
const (
	// StopRequested: the client asked for it.
	StopRequested = "requested"
	// StopClientGone: the client's connection closed.
	StopClientGone = "client-gone"
	// StopError: the session could not go on. Error says why.
	StopError = "error"
)

// RecordV2 is the signed payload of one record of schema v2. Exactly one of
// the six blocks is present: the one Kind names.
type RecordV2 struct {
	// Schema is SchemaV2.
	Schema string `json:"schema"`
	// Kind is one of the Kind constants.
	Kind string `json:"kind"`
	// ID is 32 hexadecimal digits chosen at random for this record.
	ID string `json:"id"`
	// Chain places the record in its session.
	Chain ChainV2 `json:"chain"`
	// Time is the host clock, in UTC, when the record was built. It is the
	// host's word and nothing checks it.
	Time time.Time `json:"time"`
	Host HostV2    `json:"host"`

	Command     *CommandV2     `json:"command,omitempty"`
	Snapshot    *SnapshotV2    `json:"snapshot,omitempty"`
	Restore     *RestoreV2     `json:"restore,omitempty"`
	Export      *ExportV2      `json:"export,omitempty"`
	Stop        *StopV2        `json:"stop,omitempty"`
	Interrupted *InterruptedV2 `json:"interrupted,omitempty"`
}

// ChainV2 links a record to the one before it in the same session.
type ChainV2 struct {
	// Session is the session identifier: 32 lower-case hexadecimal digits.
	Session string `json:"session"`
	// Seq is the position of the record in the session, starting at 1 and
	// growing by one with every record of any kind.
	Seq uint64 `json:"seq"`
	// PrevSHA256 is the lower-case hexadecimal SHA-256 of the payload bytes
	// of record Seq-1 as they were signed. It is empty when Seq is 1.
	PrevSHA256 string `json:"prev_sha256"`
}

// HostV2 describes the machine and the software that wrote the record.
type HostV2 struct {
	// Kernel is the system name and release, such as "Linux 6.8.0-generic".
	Kernel string `json:"kernel"`
	// Arch is the architecture of the binaries, such as "amd64".
	Arch string `json:"arch"`
	// SandmeterVersion and Commit identify the build of the root side.
	SandmeterVersion string `json:"sandmeter_version"`
	Commit           string `json:"commit"`
	// Backend is "native" or "gvisor". BackendVersion is the release of the
	// external runtime a backend wraps, and empty for the native backend.
	Backend        string `json:"backend"`
	BackendVersion string `json:"backend_version"`
}

// CommandV2 is the block of a "command" record.
type CommandV2 struct {
	// Argv is the command, verbatim. Every element is valid UTF-8 without a
	// NUL byte: the service refuses anything else before it runs.
	Argv []string `json:"argv"`
	// EnvNames lists the names of the environment variables the command was
	// given, sorted. Values are never recorded.
	EnvNames []string `json:"env_names"`
	// Workdir is the working directory of the command inside the sandbox.
	Workdir string `json:"workdir"`

	// Policy is the policy in force, as the canonical bytes of its resolved
	// form. PolicySHA256 is the lower-case hexadecimal SHA-256 of those bytes
	// as they stand here: a verifier hashes the bytes of this field and
	// never encodes a decoded policy again.
	Policy       json.RawMessage `json:"policy"`
	PolicySHA256 string          `json:"policy_sha256"`
	// CeilingSHA256 identifies the operator ceiling the policy was checked
	// against.
	CeilingSHA256 string `json:"ceiling_sha256"`

	Image   ImageV2   `json:"image"`
	Outcome OutcomeV2 `json:"outcome"`

	// StartedAt and FinishedAt are host clock readings in UTC, taken around
	// the command. DurationMS is measured separately, on a monotonic clock.
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	DurationMS int64     `json:"duration_ms"`

	Stdout StreamV2 `json:"stdout"`
	Stderr StreamV2 `json:"stderr"`

	Counters    CountersV2    `json:"counters"`
	Network     NetworkV2     `json:"network"`
	Enforcement EnforcementV2 `json:"enforcement"`
	Storage     StorageV2     `json:"storage"`
	// Workspace is null when the session has no imported project.
	Workspace *WorkspaceV2 `json:"workspace"`
	Diff      DiffV2       `json:"diff"`

	// Errors lists what failed on the host while the command was torn down
	// and this record was built: a counter that could not be read, a mount
	// that would not go away. It is empty, never null, when nothing did. The
	// parts of the record such a failure affects say so themselves.
	Errors []string `json:"errors"`
}

// ImageV2 names the root filesystem image of the session.
type ImageV2 struct {
	// RequestedRef is the reference the session was started with.
	RequestedRef string `json:"requested_ref"`
	// Digest is the digest of the image manifest that was used.
	Digest string `json:"digest"`
}

// OutcomeV2 is how a command ended. Status decides which other fields are
// set; the others are null or empty.
type OutcomeV2 struct {
	// Status is one of the Status constants.
	Status string `json:"status"`
	// ExitCode is the exit status of the command, with StatusExited and
	// StatusExecFailed. Null otherwise.
	ExitCode *int `json:"exit_code"`
	// Signal is the number of the signal that ended the command, with
	// StatusSignalled, and with StatusKilled when a signal did the killing.
	// Null otherwise.
	Signal *int `json:"signal"`
	// KillReason is one of the Kill constants with StatusKilled, else empty.
	KillReason string `json:"kill_reason"`
	// Error is the reason of StatusExecFailed or StatusSetupFailed, else
	// empty.
	Error string `json:"error"`
}

// StreamV2 describes one output stream of a command.
type StreamV2 struct {
	// SHA256 is the lower-case hexadecimal SHA-256 of every byte the command
	// wrote to the stream, whether or not it was delivered.
	SHA256 string `json:"sha256"`
	// Bytes is the number of bytes the command wrote to the stream.
	Bytes int64 `json:"bytes"`
	// Delivered is the number of those bytes that were handed to the client.
	// It is less than Bytes when the client stopped reading.
	Delivered int64 `json:"delivered"`
}

// CountersV2 are resource counters of a command. Each is null when the
// kernel or the backend could not provide it.
type CountersV2 struct {
	// Scope is one of the Scope constants: what the numbers cover.
	Scope           string `json:"scope"`
	MemoryPeakBytes *int64 `json:"memory_peak_bytes"`
	OOMKills        *int64 `json:"oom_kills"`
	CPUUsageUsec    *int64 `json:"cpu_usage_usec"`
	PIDsPeak        *int64 `json:"pids_peak"`
	// PIDsMaxHits counts the forks the task limit refused.
	PIDsMaxHits *int64 `json:"pids_max_hits"`
	// Error says why counters are null when reading them failed. It is empty
	// when the kernel simply does not have them.
	Error string `json:"error"`
}

// NetworkV2 is what the command did on the network, as far as the host
// could see.
type NetworkV2 struct {
	// Mode is the network mode of the policy: "none" or "proxy".
	Mode string `json:"mode"`
	// Recorded is false when nothing recorded flows: with mode "none" there
	// is no proxy and nothing leaves the sandbox. Flows is then empty and
	// that emptiness is not evidence.
	Recorded bool `json:"recorded"`
	// Complete is true when every request the proxy received is in Flows.
	// It is false when the record of the proxy was cut short; Incomplete
	// then says why.
	Complete   bool   `json:"complete"`
	Incomplete string `json:"incomplete"`
	// Flows lists the requests the proxy received, allowed or not, in the
	// order they arrived. The list is the proxy's own account. A program
	// that does not use the proxy has no route out of the sandbox and
	// leaves no entry here.
	Flows []FlowV2 `json:"flows"`
}

// FlowV2 is one request to the egress proxy.
type FlowV2 struct {
	// Name is the host of the request in normalised form: a lower-case DNS
	// name or an IPv4 address. It is chosen by the program in the sandbox
	// and is data, not a statement of the service. It is empty when the
	// target of the request was not a valid destination; InvalidBytes and
	// InvalidSHA256 then describe what was sent, without repeating it.
	Name string `json:"name"`
	Port uint16 `json:"port"`
	// InvalidBytes is the length of a target that was not valid and
	// InvalidSHA256 its lower-case hexadecimal SHA-256; zero and empty
	// otherwise.
	InvalidBytes  int64  `json:"invalid_bytes"`
	InvalidSHA256 string `json:"invalid_sha256"`
	// Address is the address that was dialled, and empty when none was.
	Address string `json:"address"`
	// Verdict is VerdictAllowed or VerdictDenied.
	Verdict string `json:"verdict"`
	// Reason is one of the Flow constants, or empty.
	Reason string `json:"reason"`
	// BytesUp and BytesDown count the bytes relayed from and to the sandbox.
	BytesUp   int64 `json:"bytes_up"`
	BytesDown int64 `json:"bytes_down"`
}

// EnforcementV2 says what was in force around the command.
type EnforcementV2 struct {
	// Controls lists every control the policy required, with what the host
	// probe found for it before the session started.
	Controls []ControlV2 `json:"controls"`
	// SyscallProfile is the profile of the policy. SeccompSHA256 is the
	// lower-case hexadecimal SHA-256 of the filter program that was
	// installed, and empty with profile "off".
	SyscallProfile string `json:"syscall_profile"`
	SeccompSHA256  string `json:"seccomp_sha256"`
	// Observed holds what was read back from the kernel for this command.
	Observed ObservedV2 `json:"observed"`
}

// ControlV2 is the state of one control.
type ControlV2 struct {
	// ID names the control, such as "limits.memory" or "network.proxy".
	ID       string `json:"id"`
	Enforced bool   `json:"enforced"`
	// Reason says why the control is not enforced; empty when it is.
	Reason string `json:"reason"`
}

// ObservedV2 is the posture of the command as the host read it back from the
// kernel after setting it. A field that could not be read is null, or empty
// for the fields that are copies of kernel text.
type ObservedV2 struct {
	// Tasks is the number of tasks of the sandbox whose posture was read.
	// The fields below hold a value only if all of them agreed on it.
	Tasks *int `json:"tasks"`
	// SeccompMode is the Seccomp field of /proc/<pid>/status: 2 with a
	// filter, 0 without.
	SeccompMode *int `json:"seccomp_mode"`
	// NoNewPrivs is the NoNewPrivs field of the same file.
	NoNewPrivs *bool `json:"no_new_privs"`
	// The capability sets, as the hexadecimal masks of the same file.
	CapEff string `json:"cap_eff"`
	CapPrm string `json:"cap_prm"`
	CapInh string `json:"cap_inh"`
	CapBnd string `json:"cap_bnd"`
	CapAmb string `json:"cap_amb"`
	// UIDMap and GIDMap are the lines of /proc/<pid>/uid_map and gid_map,
	// fields separated by one space and lines by a newline.
	UIDMap string `json:"uid_map"`
	GIDMap string `json:"gid_map"`
	// The limits as read from the cgroup files, verbatim and trimmed.
	CPUMax        string `json:"cpu_max"`
	MemoryMax     string `json:"memory_max"`
	MemorySwapMax string `json:"memory_swap_max"`
	PIDsMax       string `json:"pids_max"`
	// MountOptions are the options of the root overlay as the kernel reports
	// them in mountinfo.
	MountOptions string `json:"mount_options"`
}

// StorageV2 describes the writable layer of the session after the command.
type StorageV2 struct {
	// Upper is the storage mode of the policy: "disk" or "tmpfs".
	Upper string `json:"upper"`
	// QuotaBytes and QuotaInodes are the hard quota of the layer. Null with
	// "disk", where there is none.
	QuotaBytes  *int64 `json:"quota_bytes"`
	QuotaInodes *int64 `json:"quota_inodes"`
	// UsedBytes and UsedInodes are what the layer holds. Null when it could
	// not be measured.
	UsedBytes  *int64 `json:"used_bytes"`
	UsedInodes *int64 `json:"used_inodes"`
}

// WorkspaceV2 describes the imported project the command saw.
type WorkspaceV2 struct {
	// ManifestSHA256 is the hash of the import manifest the service computed
	// from what it extracted: the project exactly as this command saw it.
	ManifestSHA256 string `json:"manifest_sha256"`
	// Entries and Bytes are the size of the import.
	Entries int64 `json:"entries"`
	Bytes   int64 `json:"bytes"`
	// Superseded lists what the session had written at a path that then
	// changed on the host, and that was dropped before this command so that
	// the host's version is the one it saw. It is empty, never null, when
	// nothing was.
	Superseded []SupersededV2 `json:"superseded"`
}

// SupersededV2 is one path of the writable layer that was dropped in favour
// of the host's newer version.
type SupersededV2 struct {
	// Path is relative to the workspace. PathEscaped is set when the name is
	// not valid UTF-8; Path then holds its quoted form.
	Path        string `json:"path"`
	PathEscaped bool   `json:"path_escaped"`
	// Type is one of the Type constants.
	Type string `json:"type"`
	// SHA256 is the hash of the content that was dropped, for a regular file
	// that could be hashed, else empty.
	SHA256 string `json:"sha256"`
}

// DiffV2 is the change set of the writable layer: everything the session
// wrote since Base, not only what the last command wrote. SinceSeq on each
// entry tells the two apart.
type DiffV2 struct {
	Base DiffBaseV2 `json:"base"`
	// Status is DiffComplete, DiffTruncated or DiffError, and Reason says
	// which budget was reached or what failed.
	Status string `json:"status"`
	Reason string `json:"reason"`
	// Counts are exact with DiffComplete and DiffTruncated: they include the
	// entries a budget kept out of the list.
	Counts  DiffCountsV2  `json:"counts"`
	Budget  DiffBudgetV2  `json:"budget"`
	Entries []DiffEntryV2 `json:"entries"`
}

// DiffBaseV2 says what a diff is relative to.
type DiffBaseV2 struct {
	// Kind is BaseImage or BaseSnapshot.
	Kind string `json:"kind"`
	// Snapshot is the snapshot identifier with BaseSnapshot, else empty.
	Snapshot string `json:"snapshot"`
}

// DiffCountsV2 counts the changed paths by operation.
type DiffCountsV2 struct {
	Added    int64 `json:"added"`
	Modified int64 `json:"modified"`
	Deleted  int64 `json:"deleted"`
	Opaque   int64 `json:"opaque"`
}

// DiffBudgetV2 is the budget the diff was computed under.
type DiffBudgetV2 struct {
	// Entries is the largest number of entries listed.
	Entries int64 `json:"entries"`
	// Bytes is the largest size of the encoded list.
	Bytes int64 `json:"bytes"`
	// Depth is the deepest directory level walked.
	Depth int64 `json:"depth"`
}

// DiffEntryV2 is one changed path. Path is slash separated and relative to
// the root of the sandbox filesystem.
type DiffEntryV2 struct {
	Path string `json:"path"`
	// PathEscaped and TargetEscaped are set when the name or the link target
	// is not valid UTF-8. The field then holds the strconv.Quote form of the
	// raw bytes, quotes included, so that two different names never collide
	// in a signed record.
	PathEscaped   bool `json:"path_escaped"`
	TargetEscaped bool `json:"target_escaped"`
	// Op is one of the Op constants and Type one of the Type constants.
	Op   string `json:"op"`
	Type string `json:"type"`
	// Mode holds the permission, setuid, setgid and sticky bits.
	Mode uint32 `json:"mode"`
	// UID and GID are the owner as the sandbox sees it: 0 is its root.
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
	// Size is the apparent size of a regular file.
	Size int64 `json:"size"`
	// SHA256 is the lower-case hexadecimal SHA-256 of a regular file's
	// content, else empty. An entry without it carries Skipped.
	SHA256 string `json:"sha256"`
	// Target is a symlink target, verbatim. It is never resolved.
	Target string `json:"target"`
	// SinceSeq is the sequence number of the record after which the path was
	// first seen in this state: the changes of the command with sequence
	// number n are the entries whose SinceSeq is n.
	SinceSeq uint64 `json:"since_seq"`
	// Skipped is empty for a normal entry. Otherwise the entry is recorded
	// without content: "unreadable" or "too_large". A program in the sandbox
	// cannot suppress the diff by making one entry hard to read.
	Skipped string `json:"skipped"`
}

// SnapshotV2 is the block of a "snapshot" record.
type SnapshotV2 struct {
	// Snapshot is the identifier of the snapshot that was taken.
	Snapshot string `json:"snapshot"`
	// Parent is what the snapshot was taken on top of.
	Parent DiffBaseV2 `json:"parent"`
}

// RestoreV2 is the block of a "restore" record.
type RestoreV2 struct {
	// To is the state the writable layer was reset to.
	To DiffBaseV2 `json:"to"`
}

// ExportV2 is the block of an "export" record. It binds a change set that
// left the service to the chain: a client applies a change set only after
// checking its manifest against this hash, under a key it has pinned.
type ExportV2 struct {
	// ManifestSHA256 is the hash of the manifest of the change set.
	ManifestSHA256 string `json:"manifest_sha256"`
	// WorkspaceManifestSHA256 is the import manifest the changes are
	// relative to.
	WorkspaceManifestSHA256 string `json:"workspace_manifest_sha256"`
	// Entries is the number of entries of the manifest and Bytes the sum of
	// the sizes of the bodies that were sent.
	Entries int64 `json:"entries"`
	Bytes   int64 `json:"bytes"`
	// Skipped is the number of entries listed without a body: special files,
	// entries over a budget.
	Skipped int64 `json:"skipped"`
}

// StopV2 is the block of a "stop" record.
type StopV2 struct {
	// Reason is one of the Stop constants.
	Reason string `json:"reason"`
	// Error is the failure with StopError, and any failure to release what
	// the session held; empty when there was none.
	Error string `json:"error"`
}

// InterruptedV2 is the block of an "interrupted" record: what is known of a
// command that was about to start when the service died. Whether it ran, and
// what it did, is not known.
type InterruptedV2 struct {
	// The fields below are those of the intent, as it was written before the
	// command started.
	Argv         []string  `json:"argv"`
	EnvNames     []string  `json:"env_names"`
	Workdir      string    `json:"workdir"`
	PolicySHA256 string    `json:"policy_sha256"`
	IntentTime   time.Time `json:"intent_time"`
}

// IntentV2 is what the service writes to its own disk, and syncs, before it
// lets a command start. It is not signed and never leaves the service. If no
// record of the command follows, the next start of the service turns it into
// an "interrupted" record, so that a command cannot run and leave no trace
// by taking the service down. When the intent cannot be written the command
// does not start.
type IntentV2 struct {
	// Schema is IntentSchemaV2.
	Schema string `json:"schema"`
	// Chain is the place the command's record will take.
	Chain ChainV2 `json:"chain"`
	// Time is the host clock, in UTC, when the intent was written.
	Time         time.Time `json:"time"`
	Argv         []string  `json:"argv"`
	EnvNames     []string  `json:"env_names"`
	Workdir      string    `json:"workdir"`
	PolicySHA256 string    `json:"policy_sha256"`
}
