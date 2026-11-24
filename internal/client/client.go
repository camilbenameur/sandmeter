// Package client is how the unprivileged side of sandmeter reaches the root
// side: the command line, the MCP server and the escape harness all work
// through the two interfaces of this file and see nothing else of the
// service.
//
// This file is the contract. Two implementations exist beside it: one that
// dials the service's socket, and one that, for root, starts a worker
// itself. Both speak the control protocol of package ctl and behave alike. A
// third, in package clienttest, is an in-memory double for tests.
//
// # What a caller can and cannot do through it
//
// A caller hands over bytes and values, never a name of something on the
// host. The project goes in as a stream the caller packed from its own
// files; changes come out as a stream the caller writes itself; a session, a
// snapshot or a record is named by an identifier the service generated.
// Nothing in these interfaces lets a caller name a host path, widen the
// operator's ceiling, or act on another user's session: each of those is
// decided on the root side, for the user the kernel reported, whatever the
// caller sent.
//
// # What the answers are worth
//
// The answers are the root side's word, received over a socket. A caller
// that must rely on what a command did (a gate in CI, an apply) fetches the
// signed record with Record and verifies it under a key it pinned. Text and
// names that a program in a sandbox chose travel in these answers as data
// (the superseded paths of a refresh, the entries of a change set, the reason
// an exec failed): a caller shows them as data and never as its own words.
package client

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/camilbenameur/sandmeter/internal/changeset"
	"github.com/camilbenameur/sandmeter/internal/ctl"
	"github.com/camilbenameur/sandmeter/internal/exit"
	"github.com/camilbenameur/sandmeter/internal/ids"
)

// Errors of the client itself. Refusals of the root side are *Error.
var (
	// ErrNotBuilt is returned by a constructor or a method that this build
	// does not provide yet. Nothing was attempted.
	ErrNotBuilt = errors.New("not built in this version")
	// ErrUnavailable is wrapped by every failure to reach the root side: no
	// socket, no permission to connect, a socket that root does not serve, a
	// worker that could not be started, a hello that was not answered. The
	// message it is wrapped in says which and what to do.
	ErrUnavailable = errors.New("the sandmeter service cannot be reached")
	// ErrClosed is returned by a call on a client or a session whose
	// connection is closed, and by a call that was under way when it closed.
	ErrClosed = errors.New("the connection to the sandmeter service is closed")
)

// Error is a refusal or a failure the root side reported. It carries
// everything the root side said: the code, one sentence, every reason, and
// for an internal failure the incident under which the service logged it.
type Error struct {
	Code     ctl.Code
	Message  string
	Reasons  []ctl.Reason
	Incident string
}

// Error implements error: the message, then one line per reason.
func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString(e.Message)
	if e.Message == "" {
		b.WriteString("refused by the service (" + string(e.Code) + ")")
	}
	for _, r := range e.Reasons {
		b.WriteString("\n  ")
		if r.Key != "" {
			b.WriteString(r.Key + ": ")
		}
		b.WriteString(r.Text)
	}
	if e.Incident != "" {
		b.WriteString("\n  incident " + e.Incident + " in the service's log")
	}
	return b.String()
}

// FromMessage turns an error message of the protocol into an *Error.
func FromMessage(m ctl.Error) *Error {
	return &Error{Code: m.Code, Message: m.Message, Reasons: m.Reasons, Incident: m.Incident}
}

// CodeOf returns the code of the refusal err wraps, or the empty code when
// err is not a refusal of the root side.
func CodeOf(err error) ctl.Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// ExitStatus returns the exit status of a command that failed with err: the
// status of the code for a refusal of the root side, exit.HostCannotRun when
// the root side could not be reached, exit.Failure for anything else, and
// exit.OK for nil.
func ExitStatus(err error) int {
	switch {
	case err == nil:
		return exit.OK
	case errors.Is(err, ErrUnavailable):
		return exit.HostCannotRun
	}
	if code := CodeOf(err); code != "" {
		return code.ExitStatus()
	}
	return exit.Failure
}

// Connect opens a client. The command line picks one (the socket for a
// user, direct mode for root) and hands it to whatever needs the service, so
// that nothing else knows how the root side is reached.
type Connect func(ctx context.Context) (Client, error)

// StartRequest is what a caller gives to start a session.
type StartRequest struct {
	// Policy is the text of a policy file, as read. Empty means the default
	// policy. The root side decides whether it is accepted.
	Policy string
	// Image is an image reference, or empty for the service's default.
	Image string
	// Backend is a backend name, or empty for the service's default.
	Backend string
	// Workspace is the project, as the tar stream package workspace packs,
	// or nil for a session without a project. It is read to its end, or
	// until the root side refuses it; the caller closes whatever is behind
	// it.
	Workspace io.Reader
	// Env gives values for the variables the policy passes from the
	// caller's environment (process.env_pass). A name the policy in force
	// does not pass refuses the start.
	Env []ctl.EnvVar
}

// RunRequest is one command.
type RunRequest struct {
	// Argv is the command. Every argument must be valid UTF-8 without a NUL
	// byte; a client refuses anything else itself, naming the argument,
	// rather than send bytes that would be rewritten on the way.
	Argv []string
	// Timeout shortens the policy's time limit for this command; zero means
	// the policy's. It can never lengthen it.
	Timeout time.Duration
	// Workdir is the working directory inside the sandbox, or empty for the
	// session's.
	Workdir string
	// Env adds variables for this command, with these literal values.
	Env []ctl.EnvVar
	// Stdout and Stderr receive the output as it is produced, before Run
	// returns. Nil discards a stream. A writer that fails stops receiving;
	// the command goes on, and the result says how much was delivered.
	Stdout, Stderr io.Writer
}

// Client is a conversation with the root side that has no session yet, or
// needs none. It is safe for concurrent use; calls are served one at a time.
//
// Every method takes a context. A cancelled context abandons the call; when
// that leaves the conversation in an unknown state the client closes it and
// later calls return ErrClosed.
type Client interface {
	// Info returns what the service is and what it grants the caller: mode,
	// build, enabled backends, the ceiling, the budgets, the default image
	// and the key it signs with.
	Info(ctx context.Context) (ctl.InfoReply, error)
	// Probe returns the host report of the root side and what each enabled
	// backend enforces on this host.
	Probe(ctx context.Context) (ctl.ProbeReply, error)
	// Check asks whether a session would be started, without starting one.
	// A refusal is in the reply, not in the error.
	Check(ctx context.Context, req ctl.Check) (ctl.CheckReply, error)
	// Images lists the images a session of the caller may use.
	Images(ctx context.Context) (ctl.ImagesReply, error)
	// Sessions lists the caller's sessions the root side still knows, live
	// or not.
	Sessions(ctx context.Context) ([]ctl.SessionInfo, error)
	// Records lists the records of one session of the caller from a
	// sequence number on (0 for all), following the paging of the protocol
	// to the end.
	Records(ctx context.Context, session ids.ID, from uint64) (ctl.RecordsReply, error)
	// Record returns one record of one session of the caller: the signed
	// envelope, byte for byte as the service stored it. It is not verified
	// here.
	Record(ctx context.Context, session ids.ID, seq uint64) ([]byte, error)
	// Start starts a session and returns it. The session has a connection
	// of its own: it outlives this Client and is ended by its own Stop or
	// Close.
	Start(ctx context.Context, req StartRequest) (Session, error)
	// Close ends the conversation. Sessions started through the client are
	// not affected.
	Close() error
}

// Session is one session on the root side, and the connection that holds
// it. One call is served at a time: a session runs one command at a time,
// and a second call while one is under way waits for it or, for Run, is
// refused by the root side.
//
// The session lives exactly as long as its connection. Stop ends it in an
// orderly way and leaves the connection open for the last records; Close
// drops the connection, which ends the session on the root side whatever it
// was doing. A process that dies has closed its connections: nothing is
// left running.
type Session interface {
	// ID returns the identifier of the session.
	ID() ids.ID
	// Started returns what the root side answered to the start: the policy
	// in force, the image, the backend, the project as it was imported.
	Started() ctl.Started
	// Refresh brings the session's copy of the project up to date. delta is
	// the stream package workspace makes from the project as it is now. The
	// reply lists what the session had written at paths that changed on the
	// host and that was dropped in favour of the host's version.
	Refresh(ctx context.Context, delta io.Reader) (ctl.Refreshed, error)
	// Run runs one command and returns when it has ended and its record is
	// stored. Output reaches the request's writers while the command runs.
	//
	// Cancelling ctx kills the command: Run then returns the result, which
	// says that it was cancelled, with a nil error. The error is not nil
	// only when there is no result: the request was refused, or the
	// connection was lost.
	Run(ctx context.Context, req RunRequest) (ctl.Result, error)
	// Snapshot freezes the writable layer and returns the identifier of the
	// snapshot.
	Snapshot(ctx context.Context) (ctl.Snapshotted, error)
	// Restore discards the writable layer and goes back to a snapshot of
	// this session, or, with the zero identifier, to the state before the
	// first command.
	Restore(ctx context.Context, snapshot ids.ID) (ctl.Restored, error)
	// Changes returns the manifest of what the session changed under the
	// project directory so far. Nothing leaves the service and no record is
	// written. Every name in it was chosen in the sandbox.
	Changes(ctx context.Context) (changeset.Export, error)
	// Export writes the change set of the session to w, in the stream
	// format of package changeset, and returns the sequence number of the
	// signed export record that vouches for it. What was written to w is to
	// be trusted only after it has been checked against that record.
	Export(ctx context.Context, w io.Writer) (ctl.Exported, error)
	// Records and Record are those of Client for this session. They work
	// after Stop, until Close.
	Records(ctx context.Context, from uint64) (ctl.RecordsReply, error)
	Record(ctx context.Context, seq uint64) ([]byte, error)
	// Stop ends the session: a running command is cancelled first, then
	// everything the session held is released and a stop record is written.
	// The session is over whatever Stop returns; the reply says whether
	// something could not be released.
	Stop(ctx context.Context) (ctl.Stopped, error)
	// Close drops the connection. Without a Stop before it, the root side
	// ends the session as it does for a client that vanished. Close is
	// idempotent and may be called while another call is under way, which
	// then returns ErrClosed.
	Close() error
}
