// Package clienttest is an in-memory double of the root side, behind the
// interfaces of package client. It lets the command line, the MCP server and
// the escape harness be tested without a service, without root and without a
// socket.
//
// The double keeps the promises of the real client that callers lean on:
//
//   - output reaches the writers of a run while the step that plays the
//     command is still going;
//   - cancelling the context of Run gives a result that says cancelled, with
//     a nil error; closing the session under a run gives client.ErrClosed;
//   - Stop and Close end a running command however closely they race with
//     its start: when either has returned, no step is left running;
//   - every operation that the root side records (a command, a snapshot, a
//     restore, an export, a stop) takes the next sequence number of the
//     session, and the record can be fetched under it; the record of a
//     command that a Stop ended comes before the stop record;
//   - a session is over after Stop, answers its records until Close, and
//     refuses everything after;
//   - a refusal is a *client.Error with a code.
//
// It checks nothing the root side checks: no ceiling, no image list, no
// budget. A test that needs a refusal scripts one with Fail.
package clienttest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/camilbenameur/sandmeter/internal/changeset"
	"github.com/camilbenameur/sandmeter/internal/client"
	"github.com/camilbenameur/sandmeter/internal/ctl"
	"github.com/camilbenameur/sandmeter/internal/hostprobe"
	"github.com/camilbenameur/sandmeter/internal/ids"
	"github.com/camilbenameur/sandmeter/internal/iox"
	"github.com/camilbenameur/sandmeter/policy"
	"github.com/camilbenameur/sandmeter/receipt"
)

// RunCall is one command given to a fake session.
type RunCall struct {
	Request client.RunRequest
	Session *Session
}

// Step plays one command. It writes the command's output to the writers of
// the request and returns how the command ended. It returns when the command
// ends by itself or when ctx is done because the command was cancelled or
// its session closed.
//
// An outcome with a status stands. An outcome without one is completed by
// the fake: killed and cancelled when ctx was done, exited with status 0
// otherwise.
type Step func(ctx context.Context, call RunCall) receipt.OutcomeV2

// Exit returns a step that ends at once with the given exit status.
func Exit(code int) Step {
	return func(context.Context, RunCall) receipt.OutcomeV2 {
		return receipt.OutcomeV2{Status: receipt.StatusExited, ExitCode: &code}
	}
}

// Output returns a step that writes to the two streams, then exits with the
// given status.
func Output(stdout, stderr string, code int) Step {
	return func(_ context.Context, c RunCall) receipt.OutcomeV2 {
		if c.Request.Stdout != nil {
			_, _ = io.WriteString(c.Request.Stdout, stdout)
		}
		if c.Request.Stderr != nil {
			_, _ = io.WriteString(c.Request.Stderr, stderr)
		}
		return receipt.OutcomeV2{Status: receipt.StatusExited, ExitCode: &code}
	}
}

// Block is a step that runs until it is cancelled.
func Block(ctx context.Context, _ RunCall) receipt.OutcomeV2 {
	<-ctx.Done()
	return receipt.OutcomeV2{}
}

// Sequence returns a step that plays the given steps in turn, one per
// command, and the last one for every command after that.
func Sequence(steps ...Step) Step {
	if len(steps) == 0 {
		return Exit(0)
	}
	var mu sync.Mutex
	next := 0
	return func(ctx context.Context, c RunCall) receipt.OutcomeV2 {
		mu.Lock()
		s := steps[next]
		if next < len(steps)-1 {
			next++
		}
		mu.Unlock()
		return s(ctx, c)
	}
}

// Refusal returns the error the root side gives for a refused request.
func Refusal(code ctl.Code, message string, reasons ...ctl.Reason) error {
	return &client.Error{Code: code, Message: message, Reasons: reasons}
}

// Fake is the double. The zero value is not usable: call New. Its exported
// fields are read at the calls they affect and may be changed between calls.
type Fake struct {
	// InfoReply, ProbeReply and ImagesReply are what the questions answer.
	// New fills them with a plausible service: service mode, the native
	// backend, the built-in ceiling, a host on which every check passed.
	InfoReply   ctl.InfoReply
	ProbeReply  ctl.ProbeReply
	ImagesReply ctl.ImagesReply
	// CheckFunc answers Check; when nil, every check is accepted.
	CheckFunc func(ctl.Check) (ctl.CheckReply, error)
	// Step plays every command of every session; Exit(0) when nil.
	Step Step
	// OnStart, when not nil, is called with each new session before Start
	// returns it: a test sets up there what the session will answer (its
	// change set, what a refresh supersedes). An error refuses the start.
	OnStart func(*Session) error
	// MakeRecord builds the envelope stored for a record. When nil the fake
	// stores a small JSON object that is not a signed envelope; a test that
	// verifies records supplies real ones here. detail is the message the
	// operation answered with (a ctl.Result for a command, and so on).
	MakeRecord func(session ids.ID, seq uint64, kind string, detail any) []byte

	mu       sync.Mutex
	failures map[string][]error
	sessions []*Session
	calls    []string
	closed   bool
}

var _ client.Client = (*Fake)(nil)

// New returns a fake of a service with the default behaviour.
func New() *Fake {
	const image = "registry.test/base@sha256:0000000000000000000000000000000000000000000000000000000000000000"
	report := hostprobe.Blank()
	report.Kernel = "0.0.0-clienttest"
	for _, s := range hostprobe.Checks {
		report.Set(hostprobe.Check{ID: s.ID, Outcome: hostprobe.Yes, Detail: "clienttest"})
	}
	return &Fake{
		ProbeReply: ctl.ProbeReply{Report: report, Capabilities: []policy.Capabilities{report.Capabilities(policy.BackendNative)}},
		InfoReply: ctl.InfoReply{
			Mode:         ctl.ModeService,
			Build:        ctl.Build{Version: "0.0.0-clienttest"},
			UID:          1000,
			Backends:     []ctl.BackendInfo{{Name: policy.BackendNative, Isolation: "none (test double)", Scope: receipt.ScopeInitAndWorkload}},
			DefaultImage: image,
			Ceiling:      policy.BuiltinCeiling(),
			KeyID:        "clienttest",
		},
		ImagesReply: ctl.ImagesReply{Default: image, Images: []ctl.ImageInfo{{Reference: image, Digest: image[len(image)-71:]}}, Allow: []string{}},
	}
}

// Connect returns a client.Connect that hands out the fake.
func (f *Fake) Connect() client.Connect {
	return func(ctx context.Context) (client.Client, error) {
		if err := f.enter(ctx, "Connect"); err != nil {
			return nil, err
		}
		return f, nil
	}
}

// Fail makes the next call of the named method fail with err, once. The
// names are those of the methods of client.Client and client.Session, and
// "Connect". Several calls queue several failures.
func (f *Fake) Fail(method string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failures == nil {
		f.failures = map[string][]error{}
	}
	f.failures[method] = append(f.failures[method], err)
}

// Calls returns the names of the methods called so far, in order, on the
// fake and on its sessions.
func (f *Fake) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// Started returns every session started so far, oldest first.
func (f *Fake) Started() []*Session {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*Session(nil), f.sessions...)
}

// enter records a call and returns the failure scripted for it, if any.
func (f *Fake) enter(ctx context.Context, method string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, method)
	if q := f.failures[method]; len(q) > 0 {
		f.failures[method] = q[1:]
		return q[0]
	}
	if f.closed && method != "Connect" {
		return client.ErrClosed
	}
	return ctx.Err()
}

// Info implements client.Client.
func (f *Fake) Info(ctx context.Context) (ctl.InfoReply, error) {
	if err := f.enter(ctx, "Info"); err != nil {
		return ctl.InfoReply{}, err
	}
	return f.InfoReply, nil
}

// Probe implements client.Client.
func (f *Fake) Probe(ctx context.Context) (ctl.ProbeReply, error) {
	if err := f.enter(ctx, "Probe"); err != nil {
		return ctl.ProbeReply{}, err
	}
	return f.ProbeReply, nil
}

// Check implements client.Client.
func (f *Fake) Check(ctx context.Context, req ctl.Check) (ctl.CheckReply, error) {
	if err := f.enter(ctx, "Check"); err != nil {
		return ctl.CheckReply{}, err
	}
	if f.CheckFunc != nil {
		return f.CheckFunc(req)
	}
	return ctl.CheckReply{Reasons: []ctl.Reason{}, Backend: policy.BackendNative, Policy: json.RawMessage(`{"version":2}`)}, nil
}

// Images implements client.Client.
func (f *Fake) Images(ctx context.Context) (ctl.ImagesReply, error) {
	if err := f.enter(ctx, "Images"); err != nil {
		return ctl.ImagesReply{}, err
	}
	return f.ImagesReply, nil
}

// Sessions implements client.Client: every session started through the
// fake, live until it is stopped or closed.
func (f *Fake) Sessions(ctx context.Context) ([]ctl.SessionInfo, error) {
	if err := f.enter(ctx, "Sessions"); err != nil {
		return nil, err
	}
	out := []ctl.SessionInfo{}
	for _, s := range f.Started() {
		s.mu.Lock()
		out = append(out, ctl.SessionInfo{ID: s.id, Created: s.created, Live: !s.stopped && !s.closed, LastSeq: s.seq})
		s.mu.Unlock()
	}
	return out, nil
}

func (f *Fake) find(id ids.ID) *Session {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.sessions {
		if s.id == id {
			return s
		}
	}
	return nil
}

// Records implements client.Client. A session the fake does not know gets
// the answer the root side gives for one that is unknown or somebody else's.
func (f *Fake) Records(ctx context.Context, session ids.ID, from uint64) (ctl.RecordsReply, error) {
	if err := f.enter(ctx, "Records"); err != nil {
		return ctl.RecordsReply{}, err
	}
	s := f.find(session)
	if s == nil {
		return ctl.RecordsReply{}, Refusal(ctl.CodeNotFound, "no such session")
	}
	return s.list(from), nil
}

// Record implements client.Client.
func (f *Fake) Record(ctx context.Context, session ids.ID, seq uint64) ([]byte, error) {
	if err := f.enter(ctx, "Record"); err != nil {
		return nil, err
	}
	s := f.find(session)
	if s == nil {
		return nil, Refusal(ctl.CodeNotFound, "no such session")
	}
	return s.record(seq)
}

// Start implements client.Client. It reads the project stream to its end and
// keeps the bytes. The fake computes no import manifest: the hash it reports
// for the project is that of the stream itself, a stand-in that is the same
// wherever the fake names the project.
func (f *Fake) Start(ctx context.Context, req client.StartRequest) (client.Session, error) {
	if err := f.enter(ctx, "Start"); err != nil {
		return nil, err
	}
	id, err := ids.New()
	if err != nil {
		return nil, err
	}
	s := &Session{fake: f, id: id, created: time.Now().UTC(), Request: req, records: map[uint64]stored{}}
	backend := req.Backend
	if backend == "" {
		backend = policy.BackendNative
	}
	image := req.Image
	if image == "" {
		image = f.InfoReply.DefaultImage
	}
	s.started = ctl.Started{
		Session: id, Backend: backend, ImageRequested: image, ImageDigest: "sha256:" + fmt.Sprintf("%064x", 1),
		Policy: json.RawMessage(`{"version":2}`), PolicySHA256: policy.HashBytes([]byte(`{"version":2}`)), CeilingSHA256: f.InfoReply.CeilingSHA256,
	}
	if req.Workspace != nil {
		b, err := io.ReadAll(req.Workspace)
		if err != nil {
			return nil, fmt.Errorf("read the project stream: %w", err)
		}
		s.Workspace = b
		s.started.Workspace = &ctl.WorkspaceInfo{ManifestSHA256: changeset.HashBytes(b), Bytes: int64(len(b))}
	}
	s.Manifest = changeset.Export{
		Format: changeset.ExportFormat, Session: id.String(), WorkspaceManifestSHA256: changeset.HashBytes(s.Workspace),
		Status: changeset.StatusComplete, Reasons: []string{}, Entries: []changeset.ExportEntry{},
	}
	s.Request.Workspace = nil
	if f.OnStart != nil {
		if err := f.OnStart(s); err != nil {
			return nil, err
		}
	}
	f.mu.Lock()
	f.sessions = append(f.sessions, s)
	f.mu.Unlock()
	return s, nil
}

// Close implements client.Client. Sessions are not affected.
func (f *Fake) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "Close")
	f.closed = true
	return nil
}

type stored struct {
	kind     string
	envelope []byte
}

// Session is one session of the fake. Its exported fields are for the test
// to read and to set, between calls.
type Session struct {
	// Request is the request the session was started with, without the
	// project stream, whose bytes are in Workspace.
	Request   client.StartRequest
	Workspace []byte
	// Manifest is what Changes answers and what Export announces; Stream is
	// what Export writes. A test fills them to play a session that changed
	// files. The manifest starts out complete and empty.
	Manifest changeset.Export
	Stream   []byte
	// Superseded is what the next Refresh answers, once.
	Superseded []receipt.SupersededV2

	fake    *Fake
	id      ids.ID
	created time.Time
	started ctl.Started

	mu        sync.Mutex
	seq       uint64
	records   map[uint64]stored
	runs      []client.RunRequest
	refreshes [][]byte
	snapshots []ids.ID
	// cancelRun and runDone belong to the command that runs, if any. They
	// are set in the critical section that checks stopped and closed, and
	// stay set until the record of the command is stored.
	cancelRun context.CancelFunc
	runDone   chan struct{}
	stopped   bool
	closed    bool
}

var _ client.Session = (*Session)(nil)

// ID implements client.Session.
func (s *Session) ID() ids.ID { return s.id }

// Started implements client.Session.
func (s *Session) Started() ctl.Started { return s.started }

// Runs returns the commands given to the session so far.
func (s *Session) Runs() []client.RunRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]client.RunRequest(nil), s.runs...)
}

// Refreshes returns the bytes of each refresh stream received so far.
func (s *Session) Refreshes() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.refreshes...)
}

// Stopped and Closed report whether Stop and Close were called.
func (s *Session) Stopped() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopped
}

// Closed reports whether Close was called.
func (s *Session) Closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// enter records a call on the session and says whether it may go on.
// afterStop is true for the calls that still work on a stopped session.
func (s *Session) enter(ctx context.Context, method string, afterStop bool) error {
	if err := s.fake.enterSession(ctx, method); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.open(afterStop)
}

// open says whether the session still takes a call. The caller holds s.mu.
func (s *Session) open(afterStop bool) error {
	switch {
	case s.closed:
		return client.ErrClosed
	case s.stopped && !afterStop:
		return Refusal(ctl.CodeProtocol, "the session is over")
	}
	return nil
}

// enterSession is enter without the check that the client itself is open: a
// session has a connection of its own.
func (f *Fake) enterSession(ctx context.Context, method string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, method)
	if q := f.failures[method]; len(q) > 0 {
		f.failures[method] = q[1:]
		return q[0]
	}
	return ctx.Err()
}

// append stores the record of an operation and returns its sequence number.
func (s *Session) append(kind string, detail any) uint64 {
	s.mu.Lock()
	s.seq++
	seq := s.seq
	s.mu.Unlock()
	var env []byte
	if s.fake.MakeRecord != nil {
		env = s.fake.MakeRecord(s.id, seq, kind, detail)
	} else {
		env, _ = json.Marshal(map[string]any{"clienttest": "not a signed record", "session": s.id.String(), "seq": seq, "kind": kind})
	}
	s.mu.Lock()
	s.records[seq] = stored{kind: kind, envelope: env}
	s.mu.Unlock()
	return seq
}

func (s *Session) list(from uint64) ctl.RecordsReply {
	s.mu.Lock()
	defer s.mu.Unlock()
	reply := ctl.RecordsReply{Session: s.id, Records: []ctl.RecordInfo{}, Pending: []uint64{}}
	for seq := max(from, 1); seq <= s.seq; seq++ {
		if r, ok := s.records[seq]; ok {
			reply.Records = append(reply.Records, ctl.RecordInfo{Seq: seq, Kind: r.kind, Bytes: int64(len(r.envelope))})
		}
	}
	return reply
}

func (s *Session) record(seq uint64) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[seq]
	if !ok {
		return nil, Refusal(ctl.CodeNotFound, "no such record")
	}
	return append([]byte(nil), r.envelope...), nil
}

// Refresh implements client.Session.
func (s *Session) Refresh(ctx context.Context, delta io.Reader) (ctl.Refreshed, error) {
	if err := s.enter(ctx, "Refresh", false); err != nil {
		return ctl.Refreshed{}, err
	}
	if s.started.Workspace == nil {
		return ctl.Refreshed{}, Refusal(ctl.CodeInvalid, "the session was started without a project")
	}
	b, err := io.ReadAll(delta)
	if err != nil {
		return ctl.Refreshed{}, fmt.Errorf("read the refresh stream: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshes = append(s.refreshes, b)
	reply := ctl.Refreshed{Workspace: *s.started.Workspace, Superseded: s.Superseded}
	if reply.Superseded == nil {
		reply.Superseded = []receipt.SupersededV2{}
	}
	s.Superseded = nil
	return reply, nil
}

// Run implements client.Session.
func (s *Session) Run(ctx context.Context, req client.RunRequest) (ctl.Result, error) {
	if err := s.fake.enterSession(ctx, "Run"); err != nil {
		return ctl.Result{}, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	// Invariant: checking that the session is neither stopped nor closed and
	// publishing how to cancel this command are one step under the lock, and
	// Stop and Close mark the session and read that handle in one step under
	// the same lock. Either they see the command and cancel it, or they come
	// first and the command never starts.
	s.mu.Lock()
	err := s.open(false)
	switch {
	case err != nil:
	case len(req.Argv) == 0:
		err = Refusal(ctl.CodeInvalid, "the command is empty")
	case s.cancelRun != nil:
		err = Refusal(ctl.CodeProtocol, "a command is running in this session")
	}
	if err != nil {
		s.mu.Unlock()
		return ctl.Result{}, err
	}
	s.cancelRun, s.runDone = cancel, done
	s.runs = append(s.runs, req)
	s.mu.Unlock()
	// The command stays the running one until its record is stored, and
	// whoever waits for it (Stop) is released only then: a stop record never
	// gets a sequence number before that of the command it ended.
	defer func() {
		s.mu.Lock()
		s.cancelRun, s.runDone = nil, nil
		s.mu.Unlock()
		close(done)
	}()

	stdout, stderr := iox.NewHashingTee(req.Stdout, 0), iox.NewHashingTee(req.Stderr, 0)
	call := RunCall{Request: req, Session: s}
	call.Request.Stdout, call.Request.Stderr = stdout, stderr
	step := s.fake.Step
	if step == nil {
		step = Exit(0)
	}
	began := time.Now()
	outcome := step(runCtx, call)

	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return ctl.Result{}, client.ErrClosed
	}
	if outcome.Status == "" {
		if runCtx.Err() != nil {
			sig := 9
			outcome = receipt.OutcomeV2{Status: receipt.StatusKilled, Signal: &sig, KillReason: receipt.KillCancelled}
		} else {
			zero := 0
			outcome = receipt.OutcomeV2{Status: receipt.StatusExited, ExitCode: &zero}
		}
	}
	res := ctl.Result{Outcome: outcome, DurationMS: time.Since(began).Milliseconds(), Stdout: stream(stdout), Stderr: stream(stderr)}
	res.Seq = s.append(receipt.KindCommand, res)
	return res, nil
}

func stream(t *iox.HashingTee) receipt.StreamV2 {
	sum := t.Sum()
	return receipt.StreamV2{SHA256: sum.SHA256, Bytes: sum.Bytes, Delivered: sum.Delivered}
}

// Snapshot implements client.Session.
func (s *Session) Snapshot(ctx context.Context) (ctl.Snapshotted, error) {
	if err := s.enter(ctx, "Snapshot", false); err != nil {
		return ctl.Snapshotted{}, err
	}
	id, err := ids.New()
	if err != nil {
		return ctl.Snapshotted{}, err
	}
	s.mu.Lock()
	s.snapshots = append(s.snapshots, id)
	s.mu.Unlock()
	reply := ctl.Snapshotted{Snapshot: id}
	reply.Seq = s.append(receipt.KindSnapshot, reply)
	return reply, nil
}

// Restore implements client.Session. Only the zero identifier and the
// snapshots of this session are accepted.
func (s *Session) Restore(ctx context.Context, snapshot ids.ID) (ctl.Restored, error) {
	if err := s.enter(ctx, "Restore", false); err != nil {
		return ctl.Restored{}, err
	}
	s.mu.Lock()
	known := snapshot.IsZero()
	for _, id := range s.snapshots {
		known = known || id == snapshot
	}
	s.mu.Unlock()
	if !known {
		return ctl.Restored{}, Refusal(ctl.CodeNotFound, "no such snapshot")
	}
	return ctl.Restored{Seq: s.append(receipt.KindRestore, snapshot)}, nil
}

// Changes implements client.Session.
func (s *Session) Changes(ctx context.Context) (changeset.Export, error) {
	if err := s.enter(ctx, "Changes", false); err != nil {
		return changeset.Export{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Manifest, nil
}

// Export implements client.Session: it writes Stream to w and records the
// export.
func (s *Session) Export(ctx context.Context, w io.Writer) (ctl.Exported, error) {
	if err := s.enter(ctx, "Export", false); err != nil {
		return ctl.Exported{}, err
	}
	s.mu.Lock()
	manifest, body := s.Manifest, append([]byte(nil), s.Stream...)
	s.mu.Unlock()
	hash, err := manifest.Hash()
	if err != nil {
		return ctl.Exported{}, fmt.Errorf("clienttest: the scripted manifest: %w", err)
	}
	if _, err := io.Copy(w, bytes.NewReader(body)); err != nil {
		return ctl.Exported{}, err
	}
	entries, skipped, size := manifest.Totals()
	reply := ctl.Exported{ManifestSHA256: hash, Entries: entries, Skipped: skipped, Bytes: size}
	reply.Seq = s.append(receipt.KindExport, reply)
	return reply, nil
}

// Records implements client.Session.
func (s *Session) Records(ctx context.Context, from uint64) (ctl.RecordsReply, error) {
	if err := s.enter(ctx, "Records", true); err != nil {
		return ctl.RecordsReply{}, err
	}
	return s.list(from), nil
}

// Record implements client.Session.
func (s *Session) Record(ctx context.Context, seq uint64) ([]byte, error) {
	if err := s.enter(ctx, "Record", true); err != nil {
		return nil, err
	}
	return s.record(seq)
}

// Stop implements client.Session. A running command is cancelled first.
func (s *Session) Stop(ctx context.Context) (ctl.Stopped, error) {
	if err := s.fake.enterSession(ctx, "Stop"); err != nil {
		return ctl.Stopped{}, err
	}
	// See Run: the check, the mark and the read of the handle are one step.
	s.mu.Lock()
	if err := s.open(false); err != nil {
		s.mu.Unlock()
		return ctl.Stopped{}, err
	}
	cancel, done := s.cancelRun, s.runDone
	s.stopped = true
	s.mu.Unlock()
	if cancel != nil {
		cancel()
		select {
		case <-done:
		case <-ctx.Done():
			return ctl.Stopped{}, ctx.Err()
		}
	}
	return ctl.Stopped{Seq: s.append(receipt.KindStop, nil)}, nil
}

// Close implements client.Session.
func (s *Session) Close() error {
	s.fake.mu.Lock()
	s.fake.calls = append(s.fake.calls, "Close")
	s.fake.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.cancelRun != nil {
		s.cancelRun()
	}
	return nil
}
