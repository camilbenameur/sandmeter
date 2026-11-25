package ctl

import (
	"encoding/json"
	"time"

	"github.com/camilbenameur/sandmeter/internal/exit"
	"github.com/camilbenameur/sandmeter/internal/hostprobe"
	"github.com/camilbenameur/sandmeter/internal/ids"
	"github.com/camilbenameur/sandmeter/policy"
	"github.com/camilbenameur/sandmeter/receipt"
)

// This file declares the messages and the order of the conversation.
//
// # The conversation
//
// A connection is served by one worker, which was started for it and ends
// with it. A connection has at most one session in its whole life. The
// client speaks first and the worker answers; the worker never sends a
// message that is not an answer. One request is served at a time.
//
// The worker is in one of these states, and the table Kinds says for every
// message in which states it is legal. A message that is not legal in the
// current state ends the conversation with CodeProtocol: it is never
// queued, ignored or answered as if it had been understood. One message is
// legal where it has nothing left to do: a cancel that arrives after its
// command ended is dropped (see Cancel).
//
//   - Before the hello (StateHello). The client sends hello; the worker
//     answers with its own hello, or with an error when the protocol numbers
//     differ. Nothing else is legal.
//   - No session (StateOpen). The questions: info, probe, check, images,
//     sessions, records and record; and start.
//   - A stream from the client is expected (StateStream). The worker has
//     answered a start that announced a project, or a refresh, with accept.
//     The client sends data frames and one end frame, or the message abort.
//     Then the worker sends the answer to the request that opened the
//     stream: started or refreshed, or an error.
//   - Session at rest (StateIdle). The questions again, and refresh, run,
//     snapshot, restore, changes, export and stop. A cancel is dropped.
//   - A command runs (StateRunning). The worker sends output frames, then
//     one result. The only message the client may send is cancel, which has
//     no answer of its own: the result says that the command was cancelled.
//   - The session is over (StateEnded), after stop. The questions only: this
//     is when a client fetches the last records of its session. A cancel is
//     dropped. A second start is refused; a client that wants another
//     session opens another connection.
//
// Three answers are followed by a stream from the worker: record-reply (the
// bytes of one signed record), changes-reply (the canonical bytes of an
// export manifest) and export-reply (a change-set stream). The worker sends
// data frames and one end frame; if it cannot complete the stream it sends
// an error message instead of the end frame, and the client discards what it
// received. After the end frame of an export the worker sends exported.
//
// Any request may be answered with an error message instead of its answer.
// An error leaves the state as it was before the request, except where the
// error says the session is gone.
//
// Closing the connection is always allowed and always means the same thing:
// the running command is killed, the session is ended and everything it held
// is released, as if the client had sent cancel and stop. A client that is
// killed leaks nothing.
//
// # Who checks what
//
// Everything a client sends is checked on the root side, for the user the
// kernel reported at the other end of the socket: the policy against the
// operator's ceiling, the image against the operator's list, every budget of
// that user. A client that checked first did so to print a better message,
// and that check counts for nothing.
//
// Everything a worker sends about a command is also in a signed record, and
// a client that needs to rely on it fetches the record and verifies it under
// a key it pinned. The fields of a result are a convenience.

// Kind names a message. The list is closed: see Kinds.
type Kind string

// The kinds a client sends.
const (
	KindHello    Kind = "hello"
	KindInfo     Kind = "info"
	KindProbe    Kind = "probe"
	KindCheck    Kind = "check"
	KindImages   Kind = "images"
	KindSessions Kind = "sessions"
	KindRecords  Kind = "records"
	KindRecord   Kind = "record"
	KindStart    Kind = "start"
	KindAbort    Kind = "abort"
	KindRefresh  Kind = "refresh"
	KindRun      Kind = "run"
	KindCancel   Kind = "cancel"
	KindSnapshot Kind = "snapshot"
	KindRestore  Kind = "restore"
	KindChanges  Kind = "changes"
	KindExport   Kind = "export"
	KindStop     Kind = "stop"
)

// The kinds a worker sends. Its hello has the kind KindHello too.
const (
	KindInfoReply     Kind = "info-reply"
	KindProbeReply    Kind = "probe-reply"
	KindCheckReply    Kind = "check-reply"
	KindImagesReply   Kind = "images-reply"
	KindSessionsReply Kind = "sessions-reply"
	KindRecordsReply  Kind = "records-reply"
	KindRecordReply   Kind = "record-reply"
	KindAccept        Kind = "accept"
	KindStarted       Kind = "started"
	KindRefreshed     Kind = "refreshed"
	KindResult        Kind = "result"
	KindSnapshotted   Kind = "snapshotted"
	KindRestored      Kind = "restored"
	KindChangesReply  Kind = "changes-reply"
	KindExportReply   Kind = "export-reply"
	KindExported      Kind = "exported"
	KindStopped       Kind = "stopped"
	KindError         Kind = "error"
)

// State is where a conversation stands, seen from the worker.
type State int

const (
	// StateHello: the client's hello has not arrived.
	StateHello State = iota
	// StateOpen: no session yet.
	StateOpen
	// StateStream: the worker accepted a stream and the client is sending
	// it.
	StateStream
	// StateIdle: the session exists and no command runs.
	StateIdle
	// StateRunning: a command runs.
	StateRunning
	// StateEnded: the session was stopped.
	StateEnded
)

// String names the state for messages and logs.
func (s State) String() string {
	switch s {
	case StateHello:
		return "before the hello"
	case StateOpen:
		return "no session"
	case StateStream:
		return "receiving a stream"
	case StateIdle:
		return "session at rest"
	case StateRunning:
		return "command running"
	case StateEnded:
		return "session ended"
	}
	return "unknown state"
}

// Message is implemented by the Go type of every kind of message.
type Message interface {
	// Kind returns the kind of the message.
	Kind() Kind
}

// Envelope is the JSON object of a message frame: the kind, and the message
// itself encoded as the object of its Go type.
type Envelope struct {
	Kind Kind            `json:"kind"`
	Body json.RawMessage `json:"body"`
}

// KindSpec is the fixed description of one kind of message.
type KindSpec struct {
	Kind Kind
	// FromClient is true for a message the client sends and false for one
	// the worker sends. The hello is sent by both and listed as the
	// client's.
	FromClient bool
	// States lists, for a message the client sends, the states in which it
	// is legal. It is nil for a message the worker sends.
	States []State
	// New returns a new, zero message of the kind, for a decoder.
	New func() Message
}

// questions are the states in which a client may ask about the service and
// about its own sessions and records.
var questions = []State{StateOpen, StateIdle, StateEnded}

// Kinds is the closed list of message kinds.
var Kinds = []KindSpec{
	{KindHello, true, []State{StateHello}, func() Message { return new(Hello) }},
	{KindInfo, true, questions, func() Message { return new(Info) }},
	{KindProbe, true, questions, func() Message { return new(Probe) }},
	{KindCheck, true, questions, func() Message { return new(Check) }},
	{KindImages, true, questions, func() Message { return new(Images) }},
	{KindSessions, true, questions, func() Message { return new(Sessions) }},
	{KindRecords, true, questions, func() Message { return new(Records) }},
	{KindRecord, true, questions, func() Message { return new(Record) }},
	{KindStart, true, []State{StateOpen}, func() Message { return new(Start) }},
	{KindAbort, true, []State{StateStream}, func() Message { return new(Abort) }},
	{KindRefresh, true, []State{StateIdle}, func() Message { return new(Refresh) }},
	{KindRun, true, []State{StateIdle}, func() Message { return new(Run) }},
	{KindCancel, true, []State{StateIdle, StateRunning, StateEnded}, func() Message { return new(Cancel) }},
	{KindSnapshot, true, []State{StateIdle}, func() Message { return new(Snapshot) }},
	{KindRestore, true, []State{StateIdle}, func() Message { return new(Restore) }},
	{KindChanges, true, []State{StateIdle}, func() Message { return new(Changes) }},
	{KindExport, true, []State{StateIdle}, func() Message { return new(Export) }},
	{KindStop, true, []State{StateIdle}, func() Message { return new(Stop) }},

	{KindInfoReply, false, nil, func() Message { return new(InfoReply) }},
	{KindProbeReply, false, nil, func() Message { return new(ProbeReply) }},
	{KindCheckReply, false, nil, func() Message { return new(CheckReply) }},
	{KindImagesReply, false, nil, func() Message { return new(ImagesReply) }},
	{KindSessionsReply, false, nil, func() Message { return new(SessionsReply) }},
	{KindRecordsReply, false, nil, func() Message { return new(RecordsReply) }},
	{KindRecordReply, false, nil, func() Message { return new(RecordReply) }},
	{KindAccept, false, nil, func() Message { return new(Accept) }},
	{KindStarted, false, nil, func() Message { return new(Started) }},
	{KindRefreshed, false, nil, func() Message { return new(Refreshed) }},
	{KindResult, false, nil, func() Message { return new(Result) }},
	{KindSnapshotted, false, nil, func() Message { return new(Snapshotted) }},
	{KindRestored, false, nil, func() Message { return new(Restored) }},
	{KindChangesReply, false, nil, func() Message { return new(ChangesReply) }},
	{KindExportReply, false, nil, func() Message { return new(ExportReply) }},
	{KindExported, false, nil, func() Message { return new(Exported) }},
	{KindStopped, false, nil, func() Message { return new(Stopped) }},
	{KindError, false, nil, func() Message { return new(Error) }},
}

// SpecOf returns the description of a kind, and false for a kind that is not
// in Kinds.
func SpecOf(k Kind) (KindSpec, bool) {
	for _, s := range Kinds {
		if s.Kind == k {
			return s, true
		}
	}
	return KindSpec{}, false
}

// Legal reports whether a client may send a message of kind k while the
// conversation is in state s. It is false for a kind only the worker sends
// and for a kind that does not exist.
func Legal(s State, k Kind) bool {
	spec, ok := SpecOf(k)
	if !ok || !spec.FromClient {
		return false
	}
	for _, st := range spec.States {
		if st == s {
			return true
		}
	}
	return false
}

// Build identifies the build of one end. It is informational: it is shown
// when the protocol numbers differ and written to the logs.
type Build struct {
	// Version is the release version, such as "0.1.0", or "dev".
	Version string `json:"version"`
	// Commit is the commit the binary was built from, or empty.
	Commit string `json:"commit"`
}

// Hello is the first message of each end.
type Hello struct {
	// Protocol is the Protocol constant of the sender's build.
	Protocol int   `json:"protocol"`
	Build    Build `json:"build"`
}

// Info asks for what the service is and what it grants the caller.
type Info struct{}

// Modes of the root side, the values of InfoReply.Mode.
const (
	// ModeService: the worker was started by the service for a connection to
	// its socket.
	ModeService = "service"
	// ModeDirect: root started the worker itself, without the service.
	ModeDirect = "direct"
)

// InfoReply answers Info. Everything in it is the root side's word about
// itself; none of it was chosen by a sandbox.
type InfoReply struct {
	// Mode is ModeService or ModeDirect.
	Mode  string `json:"mode"`
	Build Build  `json:"build"`
	// UID is the caller as the root side sees it: the uid the kernel
	// reported for the other end of the socket, which is the only thing any
	// decision about the caller rests on.
	UID uint32 `json:"uid"`
	// Backends lists the backends the operator enabled, the default first.
	Backends []BackendInfo `json:"backends"`
	// DefaultImage is the image a session gets when it names none: a
	// reference pinned by digest.
	DefaultImage string `json:"default_image"`
	// Ceiling is the operator's ceiling, resolved: what the largest policy
	// this caller may ask for looks like. CeilingSHA256 is the hash a record
	// carries for it.
	Ceiling       policy.Ceiling `json:"ceiling"`
	CeilingSHA256 string         `json:"ceiling_sha256"`
	// Budgets are the caller's budgets.
	Budgets Budgets `json:"budgets"`
	// KeyID and PublicKey identify the key the service signs records with:
	// the key identifier of the envelopes, and the public key as a PKIX PEM
	// block. A client pins the key the first time it sees it and treats a
	// different one later as an alarm, not as an update.
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

// BackendInfo describes one enabled backend.
type BackendInfo struct {
	// Name is "native" or "gvisor".
	Name string `json:"name"`
	// Isolation names the mechanism in a few words.
	Isolation string `json:"isolation"`
	// Version is the release of the external runtime the backend wraps, or
	// empty.
	Version string `json:"version"`
	// Scope is what the counters of this backend cover: one of the Scope
	// constants of package receipt.
	Scope string `json:"scope"`
}

// Budgets are the limits the operator sets for one user. Zero means that the
// operator set no limit of that kind.
type Budgets struct {
	// Sessions is how many sessions the user may have at once, and Commands
	// how many commands may run at once across them.
	Sessions int `json:"sessions"`
	Commands int `json:"commands"`
	// WorkspaceBytes and WorkspaceEntries bound one imported project.
	WorkspaceBytes   int64 `json:"workspace_bytes"`
	WorkspaceEntries int64 `json:"workspace_entries"`
	// ReceiptBytes bounds the records the service keeps for the user. When
	// it is reached new commands are refused; no record is ever deleted to
	// make room.
	ReceiptBytes int64 `json:"receipt_bytes"`
	// Connections is how many connections the user may hold at once.
	Connections int `json:"connections"`
}

// Probe asks for the report of the host probe.
type Probe struct{}

// ProbeReply answers Probe.
type ProbeReply struct {
	// Report is what the probe found on this host, run by the root side.
	Report hostprobe.Report `json:"report"`
	// Capabilities holds, for each enabled backend in the order of
	// InfoReply.Backends, what that backend enforces here.
	Capabilities []policy.Capabilities `json:"capabilities"`
}

// Check asks whether a session with this policy, backend and image would be
// started for the caller, without starting anything. It runs the checks of a
// start, in the same code.
type Check struct {
	// Policy is the text of a policy file. Empty means the default policy.
	Policy string `json:"policy"`
	// Backend is a backend name, or empty for the default.
	Backend string `json:"backend"`
	// Image is an image reference, or empty for the default.
	Image string `json:"image"`
}

// CheckReply answers Check. A policy that would be refused is an answer, not
// an error.
type CheckReply struct {
	// Reasons lists every reason the start would be refused, each with the
	// code a start would give it. Empty when it would be accepted.
	Reasons []Reason `json:"reasons"`
	// Backend is the backend that would run the session.
	Backend string `json:"backend"`
	// Policy holds the canonical bytes of the policy that would be in force,
	// and PolicySHA256 their hash. When the policy itself was refused, Policy
	// is the JSON value null and PolicySHA256 is empty.
	Policy       json.RawMessage `json:"policy"`
	PolicySHA256 string          `json:"policy_sha256"`
	// CeilingSHA256 identifies the ceiling the policy was checked against.
	CeilingSHA256 string `json:"ceiling_sha256"`
}

// Images asks for the images a session of the caller may use.
type Images struct{}

// ImagesReply answers Images.
type ImagesReply struct {
	// Default is the reference of the default image.
	Default string `json:"default"`
	// Images lists what the store holds and the caller may use.
	Images []ImageInfo `json:"images"`
	// Allow lists the operator's patterns of references a member may use
	// besides the default image, as the operator file writes them. Empty,
	// never null, when the default image is the only one.
	Allow []string `json:"allow"`
	// PullAllowed says whether the operator lets a session of this caller
	// trigger a pull of an image that matches Allow and is not in the store
	// yet. The default image may always be pulled.
	PullAllowed bool `json:"pull_allowed"`
}

// ImageInfo describes one image of the store.
type ImageInfo struct {
	// Reference is the reference the image was pulled under.
	Reference string `json:"reference"`
	// Digest is the digest of its manifest.
	Digest string `json:"digest"`
}

// Sessions asks for the caller's sessions that the root side still knows.
type Sessions struct{}

// SessionsReply answers Sessions.
type SessionsReply struct {
	Sessions []SessionInfo `json:"sessions"`
}

// SessionInfo describes one session of the caller.
type SessionInfo struct {
	ID ids.ID `json:"id"`
	// Created is when the session was started, by the host's clock.
	Created time.Time `json:"created"`
	// Live is true while a worker holds the session. A session that is not
	// live cannot be entered again: its records can be fetched, and what it
	// left on disk is removed by the operator's clean-up.
	Live bool `json:"live"`
	// LastSeq is the sequence number of the last record of the session.
	LastSeq uint64 `json:"last_seq"`
}

// Records asks for the list of the records of one session of the caller,
// live or not.
type Records struct {
	Session ids.ID `json:"session"`
	// From is the first sequence number wanted; 0 and 1 both mean all.
	From uint64 `json:"from"`
}

// MaxRecordsPerReply is the largest number of records one RecordsReply
// lists. A client asks again, from the sequence number after the last one,
// while More is set.
const MaxRecordsPerReply = 10_000

// RecordsReply answers Records.
type RecordsReply struct {
	Session ids.ID       `json:"session"`
	Records []RecordInfo `json:"records"`
	// More is true when the session has records after the last one listed.
	More bool `json:"more"`
	// Pending lists the sequence numbers for which the service wrote down,
	// before the command started, that a command was about to run, and holds
	// no record yet: a command that is running now, or one that was cut
	// short and will be recorded as interrupted.
	Pending []uint64 `json:"pending"`
}

// RecordInfo describes one stored record.
type RecordInfo struct {
	Seq uint64 `json:"seq"`
	// Kind is one of the Kind constants of package receipt.
	Kind string `json:"kind"`
	// Bytes is the size of the envelope.
	Bytes int64 `json:"bytes"`
}

// Record asks for one record of one session of the caller, by sequence
// number. Records are never addressed any other way.
type Record struct {
	Session ids.ID `json:"session"`
	Seq     uint64 `json:"seq"`
}

// RecordReply answers Record. It is followed by a stream: the envelope of
// the record, byte for byte as the service stored it.
type RecordReply struct {
	RecordInfo
}

// EnvVar is one environment variable.
type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Start asks for a session.
type Start struct {
	// Policy is the text of a policy file, as the client read it. Empty
	// means the default policy. The root side parses it, checks it against
	// the ceiling and against what the backend enforces on this host, and
	// refuses it with every reason at once.
	Policy string `json:"policy"`
	// Image is an image reference, or empty for the default image.
	Image string `json:"image"`
	// Backend is a backend name, or empty for the default backend.
	Backend string `json:"backend"`
	// Workspace announces a project: when it is true and the request is
	// acceptable, the worker answers accept and the client then sends the
	// project as a stream, a tar archive it packed from its own files.
	Workspace bool `json:"workspace"`
	// Env gives the values of variables taken from the client's environment.
	// Each name must be one the policy in force lists under process.env_pass,
	// which the ceiling must grant; any other name refuses the start. The
	// names end up in the records, the values never do.
	Env []EnvVar `json:"env"`
}

// Accept tells the client to send the stream it announced, and what the
// stream may hold at most.
type Accept struct {
	// MaxBytes and MaxEntries are the budget of the stream: the sum of the
	// sizes of its files and the number of its entries. A stream beyond
	// either is refused whole.
	MaxBytes   int64 `json:"max_bytes"`
	MaxEntries int64 `json:"max_entries"`
}

// Abort tells the worker that the client cannot complete the stream it was
// sending. The worker discards what it received and answers with an error of
// code CodeAborted; a start then leaves no session, a refresh leaves the
// session as it was before.
type Abort struct {
	// Reason says why, for the service's log.
	Reason string `json:"reason"`
}

// WorkspaceInfo describes the project of a session as the root side holds
// it.
type WorkspaceInfo struct {
	// ManifestSHA256 is the hash of the import manifest the root side
	// computed from what it extracted. The client compares it with its own
	// before it relies on its own manifest.
	ManifestSHA256 string `json:"manifest_sha256"`
	Entries        int64  `json:"entries"`
	Bytes          int64  `json:"bytes"`
}

// Started answers Start, after the stream when there was one.
type Started struct {
	// Session is the identifier of the new session.
	Session ids.ID `json:"session"`
	// Backend and BackendVersion say what runs the session.
	Backend        string `json:"backend"`
	BackendVersion string `json:"backend_version"`
	// ImageRequested is the reference that was asked for, or the default,
	// and ImageDigest the digest of the image that was used.
	ImageRequested string `json:"image_requested"`
	ImageDigest    string `json:"image_digest"`
	// Policy holds the canonical bytes of the policy in force and
	// PolicySHA256 their hash, as every record of the session will carry
	// them. What is off, or wider than the default, is read from here.
	Policy       json.RawMessage `json:"policy"`
	PolicySHA256 string          `json:"policy_sha256"`
	// CeilingSHA256 identifies the ceiling the policy was checked against.
	CeilingSHA256 string `json:"ceiling_sha256"`
	// Workspace describes the imported project; null without one.
	Workspace *WorkspaceInfo `json:"workspace"`
}

// Refresh announces a stream that brings the session's copy of the project
// up to date with the host: the worker answers accept, the client sends the
// stream, the worker answers refreshed. It is legal only for a session that
// was started with a project.
type Refresh struct{}

// Refreshed answers Refresh, after the stream.
type Refreshed struct {
	// Workspace describes the project after the refresh.
	Workspace WorkspaceInfo `json:"workspace"`
	// Superseded lists what the session had written at a path that changed
	// on the host, and that was dropped so that the host's version is the
	// one the next command sees. The names in it were chosen in the sandbox:
	// they are data. The record of the next command carries the same list.
	Superseded []receipt.SupersededV2 `json:"superseded"`
}

// Run asks for one command in the session.
type Run struct {
	// Argv is the command: at least one argument, each valid UTF-8 without a
	// NUL byte.
	Argv []string `json:"argv"`
	// TimeoutMS shortens the time limit of the policy for this command, in
	// milliseconds. Zero means the policy's limit; a value above it is
	// refused.
	TimeoutMS int64 `json:"timeout_ms"`
	// Workdir is the working directory of the command, a path inside the
	// sandbox. Empty means the session's.
	Workdir string `json:"workdir"`
	// Env adds variables for this command, with the values given here. They
	// are the client's own literals, not values taken from the service's
	// side; the names end up in the record.
	Env []EnvVar `json:"env"`
}

// Cancel asks the worker to kill the running command. It has no answer: the
// result of the command follows, and says that it was cancelled.
//
// A cancel can cross the result of the command it was sent for: the client
// sends it while the result is already on its way. The worker then reads it
// with the session at rest, or over, where no command runs. It drops it:
// there a cancel is legal and does nothing. A client that cancels a moment
// too late therefore keeps its session and what the session holds.
//
// A late cancel never reaches a later command. A client sends a cancel only
// while it waits for the result of a run, so every cancel is on the
// connection before the client's next request, and the worker reads them in
// that order.
type Cancel struct{}

// Result ends a run. A record with the same facts, and many more, is stored
// under Seq.
type Result struct {
	// Seq is the sequence number of the command's record, or 0 when no
	// record could be stored (RecordError then says why).
	Seq uint64 `json:"seq"`
	// Outcome is how the command ended.
	Outcome    receipt.OutcomeV2 `json:"outcome"`
	DurationMS int64             `json:"duration_ms"`
	// Stdout and Stderr account for the two streams: what the command wrote
	// and how much of it was sent on this connection.
	Stdout receipt.StreamV2 `json:"stdout"`
	Stderr receipt.StreamV2 `json:"stderr"`
	// CleanupError is not empty when the sandbox of the command could not be
	// taken down completely. The outcome stands; something may be left on
	// the host.
	CleanupError string `json:"cleanup_error"`
	// RecordError is not empty when the record of the command could not be
	// signed or stored. The session then refuses further commands.
	RecordError string `json:"record_error"`
}

// Snapshot asks the worker to freeze the writable layer of the session.
type Snapshot struct{}

// Snapshotted answers Snapshot.
type Snapshotted struct {
	// Snapshot identifies the snapshot, for Restore.
	Snapshot ids.ID `json:"snapshot"`
	// Seq is the sequence number of the snapshot's record.
	Seq uint64 `json:"seq"`
}

// Restore asks the worker to discard the writable layer and to go back to a
// snapshot of this session, or to the state before the first command.
type Restore struct {
	// Snapshot is the snapshot to go back to. It is left out to go back to
	// the image and the imported project.
	Snapshot ids.ID `json:"snapshot,omitzero"`
}

// Restored answers Restore.
type Restored struct {
	// Seq is the sequence number of the restore's record.
	Seq uint64 `json:"seq"`
}

// Changes asks what the session changed under the project directory so far,
// without taking the changes out: no record is written.
type Changes struct{}

// ChangesReply answers Changes. It is followed by a stream: the canonical
// bytes of an export manifest (package changeset) that lists the changes.
type ChangesReply struct {
	// Entries is the number of entries of the manifest and Bytes the size of
	// its canonical bytes.
	Entries int64 `json:"entries"`
	Bytes   int64 `json:"bytes"`
}

// Export asks for the changes themselves, as a change set, and binds them to
// the session's chain of records.
type Export struct{}

// ExportReply answers Export. It is followed by a stream, the change set in
// the stream format of package changeset, and after the end of the stream by
// the message exported.
type ExportReply struct {
	// ManifestSHA256 is the hash of the export manifest the stream starts
	// with.
	ManifestSHA256 string `json:"manifest_sha256"`
}

// Exported ends an export.
type Exported struct {
	// Seq is the sequence number of the signed export record. The client
	// fetches that record and applies nothing it has not checked against it.
	Seq            uint64 `json:"seq"`
	ManifestSHA256 string `json:"manifest_sha256"`
	// Entries, Skipped and Bytes are those of the export record.
	Entries int64 `json:"entries"`
	Skipped int64 `json:"skipped"`
	Bytes   int64 `json:"bytes"`
}

// Stop asks the worker to end the session.
type Stop struct{}

// Stopped answers Stop. The session is over whatever it says.
type Stopped struct {
	// Seq is the sequence number of the stop record, or 0 when it could not
	// be stored.
	Seq uint64 `json:"seq"`
	// CleanupError is not empty when something the session held could not be
	// released. The message names it and what reclaims it.
	CleanupError string `json:"cleanup_error"`
	// RecordError is not empty when the stop record could not be signed or
	// stored.
	RecordError string `json:"record_error"`
}

// Code classifies an error. The list is closed.
type Code string

// The codes.
const (
	// CodeProtocol: a frame or a message was malformed, or not legal in the
	// state of the conversation. The connection is closed after it.
	CodeProtocol Code = "protocol"
	// CodeVersion: the two ends are not from the same release.
	CodeVersion Code = "version"
	// CodeInvalid: a request is well formed and holds a value that is not
	// acceptable: an empty command, a bound of this package exceeded, a
	// timeout above the policy's, an unknown backend name.
	CodeInvalid Code = "invalid"
	// CodeNotFound: the caller has no session, snapshot or record of that
	// identifier. One that exists and belongs to another user gets the same
	// answer.
	CodeNotFound Code = "not-found"
	// CodePolicyRefused: the policy does not parse, asks for more than the
	// operator's ceiling grants, or needs a control this host does not
	// enforce. The reasons list every violated key.
	CodePolicyRefused Code = "policy-refused"
	// CodeHost: the backend cannot run on this host at all. The reasons are
	// the problems the host probe found, each with its fix.
	CodeHost Code = "host"
	// CodeImage: the image is not one the operator allows for the caller, is
	// not in the store and may not be pulled, or could not be pulled.
	CodeImage Code = "image"
	// CodeBudget: a budget of the calling user is spent. The reason names
	// the budget, its limit and its current use.
	CodeBudget Code = "budget"
	// CodeDiskFloor: free space or free inodes on the state filesystem are
	// under the operator's floor.
	CodeDiskFloor Code = "disk-floor"
	// CodeWorkspace: the stream of a project or of a refresh was refused:
	// over its budget, or holding an entry that is never imported.
	CodeWorkspace Code = "workspace"
	// CodeAborted: the client aborted the stream it was sending.
	CodeAborted Code = "aborted"
	// CodeSessionFailed: the session cannot go on, for instance because a
	// record could not be stored. It must be stopped.
	CodeSessionFailed Code = "session-failed"
	// CodeNotBuilt: the request is for something this build, or this backend
	// on this host, does not provide.
	CodeNotBuilt Code = "not-built"
	// CodeShutdown: the service is stopping and takes no new work.
	CodeShutdown Code = "shutdown"
	// CodeInternal: the root side failed. The text of the failure stays in
	// the service's log, under the incident identifier of the message.
	CodeInternal Code = "internal"
)

// Codes is the closed list of codes.
var Codes = []Code{
	CodeProtocol, CodeVersion, CodeInvalid, CodeNotFound, CodePolicyRefused, CodeHost, CodeImage, CodeBudget,
	CodeDiskFloor, CodeWorkspace, CodeAborted, CodeSessionFailed, CodeNotBuilt, CodeShutdown, CodeInternal,
}

// ExitStatus returns the exit status a command that was refused with this
// code ends with.
func (c Code) ExitStatus() int {
	switch c {
	case CodeInvalid:
		return exit.Usage
	case CodePolicyRefused:
		return exit.PolicyRefused
	case CodeHost, CodeVersion, CodeShutdown:
		return exit.HostCannotRun
	case CodeImage, CodeBudget, CodeDiskFloor, CodeWorkspace:
		return exit.Denied
	case CodeNotFound, CodeAborted:
		return exit.Failed
	}
	return exit.Failure
}

// Reason is one reason of a refusal.
type Reason struct {
	// Code is the code of the error this reason belongs to. In an Error it
	// repeats the error's own; in a CheckReply it says what a start would
	// have answered.
	Code Code `json:"code"`
	// Key names what the reason is about, in the vocabulary of the thing
	// refused: a policy key in dotted form such as "limits.memory", the
	// identifier of a host check, the name of a budget. It is never text a
	// client or a sandbox chose.
	Key string `json:"key"`
	// Text says, in one sentence of the root side's own, what is wrong and
	// what would be accepted.
	Text string `json:"text"`
}

// Error is the answer to a request that was refused or that failed.
type Error struct {
	Code Code `json:"code"`
	// Message says in one sentence what happened and what to do next.
	Message string `json:"message"`
	// Reasons lists every reason of a refusal, so that the caller can fix
	// all of them at once. It is empty, never null, when the message says it
	// all.
	Reasons []Reason `json:"reasons"`
	// Incident is set with CodeInternal: a random identifier under which the
	// service logged what failed. The client shows it; the text of the
	// failure does not leave the root side.
	Incident string `json:"incident"`
}

// Kind implements Message.
func (*Hello) Kind() Kind { return KindHello }

// Kind implements Message.
func (*Info) Kind() Kind { return KindInfo }

// Kind implements Message.
func (*InfoReply) Kind() Kind { return KindInfoReply }

// Kind implements Message.
func (*Probe) Kind() Kind { return KindProbe }

// Kind implements Message.
func (*ProbeReply) Kind() Kind { return KindProbeReply }

// Kind implements Message.
func (*Check) Kind() Kind { return KindCheck }

// Kind implements Message.
func (*CheckReply) Kind() Kind { return KindCheckReply }

// Kind implements Message.
func (*Images) Kind() Kind { return KindImages }

// Kind implements Message.
func (*ImagesReply) Kind() Kind { return KindImagesReply }

// Kind implements Message.
func (*Sessions) Kind() Kind { return KindSessions }

// Kind implements Message.
func (*SessionsReply) Kind() Kind { return KindSessionsReply }

// Kind implements Message.
func (*Records) Kind() Kind { return KindRecords }

// Kind implements Message.
func (*RecordsReply) Kind() Kind { return KindRecordsReply }

// Kind implements Message.
func (*Record) Kind() Kind { return KindRecord }

// Kind implements Message.
func (*RecordReply) Kind() Kind { return KindRecordReply }

// Kind implements Message.
func (*Start) Kind() Kind { return KindStart }

// Kind implements Message.
func (*Accept) Kind() Kind { return KindAccept }

// Kind implements Message.
func (*Abort) Kind() Kind { return KindAbort }

// Kind implements Message.
func (*Started) Kind() Kind { return KindStarted }

// Kind implements Message.
func (*Refresh) Kind() Kind { return KindRefresh }

// Kind implements Message.
func (*Refreshed) Kind() Kind { return KindRefreshed }

// Kind implements Message.
func (*Run) Kind() Kind { return KindRun }

// Kind implements Message.
func (*Cancel) Kind() Kind { return KindCancel }

// Kind implements Message.
func (*Result) Kind() Kind { return KindResult }

// Kind implements Message.
func (*Snapshot) Kind() Kind { return KindSnapshot }

// Kind implements Message.
func (*Snapshotted) Kind() Kind { return KindSnapshotted }

// Kind implements Message.
func (*Restore) Kind() Kind { return KindRestore }

// Kind implements Message.
func (*Restored) Kind() Kind { return KindRestored }

// Kind implements Message.
func (*Changes) Kind() Kind { return KindChanges }

// Kind implements Message.
func (*ChangesReply) Kind() Kind { return KindChangesReply }

// Kind implements Message.
func (*Export) Kind() Kind { return KindExport }

// Kind implements Message.
func (*ExportReply) Kind() Kind { return KindExportReply }

// Kind implements Message.
func (*Exported) Kind() Kind { return KindExported }

// Kind implements Message.
func (*Stop) Kind() Kind { return KindStop }

// Kind implements Message.
func (*Stopped) Kind() Kind { return KindStopped }

// Kind implements Message.
func (*Error) Kind() Kind { return KindError }
