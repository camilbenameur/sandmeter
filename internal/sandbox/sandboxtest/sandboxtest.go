// Package sandboxtest is a backend for tests: it runs no process, needs no
// privilege and does what a script says.
//
// It is meant for the tests of everything above a backend (the engine, the
// service, the client) and it keeps the promises of the sandbox contract
// that those layers rely on, so that a test which passes against it is a
// test of the caller and not of a lenient double:
//
//   - one thing at a time: a second Exec, a Snapshot or a Restore during a
//     command answers sandbox.ErrBusy;
//   - Stop kills a running command, whose result says KillStopped, and waits
//     for it; a cancelled context gives KillCancelled, a command that
//     outlives its time limit KillWallTimeout;
//   - once the command is under way every outcome is a Result with a nil
//     error, and a stopped sandbox answers sandbox.ErrStopped;
//   - the layers are real directories inside Spec.Dir: a step can write
//     files where a command would, and a diff of the layers finds them.
//
// What a command "does" is a Step. The default step exits with status 0 at
// once.
package sandboxtest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/camilbenameur/sandmeter/internal/hostprobe"
	"github.com/camilbenameur/sandmeter/internal/ids"
	"github.com/camilbenameur/sandmeter/internal/sandbox"
	"github.com/camilbenameur/sandmeter/policy"
)

// Call is one command given to the fake.
type Call struct {
	Argv []string
	Opts sandbox.ExecOptions
	// Upper is the directory of the writable layer while the command "runs".
	// A step that wants the command to have written a file creates it here,
	// under the path the file would have in the sandbox.
	Upper string
	// Spec is the spec the sandbox was started with.
	Spec sandbox.Spec
}

// Step plays one command. It returns when the command ends by itself, or
// when ctx is done because the command was killed.
//
// A step that returns a Result with a Status says how the command ended, and
// that stands, even if a kill arrived at the same moment: a command that
// finished is never relabelled by a timer that fires late. A step that
// returns a Result without a Status leaves it to the fake: killed, with the
// reason, when a kill came, and exited otherwise. A step may fill any other
// part of the Result; the fake completes what it leaves zero: the scope of
// the counters, the storage mode, the profile and the times.
//
// An error from a step stands for a backend that breaks its contract; tests
// of a caller's defences use it.
type Step func(ctx context.Context, c Call) (sandbox.Result, error)

// Exit returns a step that ends at once with the given exit status.
func Exit(code int) Step {
	return func(context.Context, Call) (sandbox.Result, error) {
		return sandbox.Result{Status: sandbox.StatusExited, ExitCode: code}, nil
	}
}

// Output returns a step that writes to the command's streams, then exits
// with the given status.
func Output(stdout, stderr string, code int) Step {
	return func(_ context.Context, c Call) (sandbox.Result, error) {
		if c.Opts.Stdout != nil && stdout != "" {
			_, _ = c.Opts.Stdout.Write([]byte(stdout))
		}
		if c.Opts.Stderr != nil && stderr != "" {
			_, _ = c.Opts.Stderr.Write([]byte(stderr))
		}
		return sandbox.Result{Status: sandbox.StatusExited, ExitCode: code}, nil
	}
}

// Block is a step that runs until it is killed: by Stop, by the context of
// Exec or by the time limit.
func Block(ctx context.Context, _ Call) (sandbox.Result, error) {
	<-ctx.Done()
	return sandbox.Result{}, nil
}

// Write returns a step that creates a file in the writable layer, as a
// command writing to that path inside the sandbox would, then exits with
// status 0. The path is relative to the root of the sandbox.
func Write(path, content string) Step {
	return func(_ context.Context, c Call) (sandbox.Result, error) {
		full := filepath.Join(c.Upper, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return sandbox.Result{}, err
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			return sandbox.Result{}, err
		}
		return sandbox.Result{Status: sandbox.StatusExited}, nil
	}
}

// Sequence returns a step that plays the given steps in turn, one per
// command, and the last one for every command after that.
func Sequence(steps ...Step) Step {
	if len(steps) == 0 {
		return Exit(0)
	}
	var mu sync.Mutex
	next := 0
	return func(ctx context.Context, c Call) (sandbox.Result, error) {
		mu.Lock()
		s := steps[next]
		if next < len(steps)-1 {
			next++
		}
		mu.Unlock()
		return s(ctx, c)
	}
}

// PassingReport returns a host report in which every check said yes: the
// input that makes a Backend enforce every control.
func PassingReport() hostprobe.Report {
	r := hostprobe.Blank()
	r.Kernel = "0.0.0-sandboxtest"
	for _, s := range hostprobe.Checks {
		r.Set(hostprobe.Check{ID: s.ID, Outcome: hostprobe.Yes, Detail: "sandboxtest"})
	}
	return r
}

// Backend is the fake backend. The zero value is not usable: call New.
// Its exported fields are read at the calls they affect and may be changed
// between calls, not during one.
type Backend struct {
	// Name is the backend name; "native" unless set.
	Name string
	// Scope is the scope of the counters; sandbox.ScopeInitAndWorkload
	// unless set.
	Scope sandbox.Scope
	// Step plays every command; Exit(0) when nil.
	Step Step
	// Withdraw lists controls the backend does not offer, with the reason:
	// Capabilities reports them as not enforced whatever the host report
	// says.
	Withdraw map[policy.ControlID]string
	// StartErr, when not nil, is returned by Start.
	StartErr error
	// StopErrs is consumed one error per call to Stop of any sandbox of this
	// backend: a nil entry lets that Stop succeed, another makes it fail and
	// leave the sandbox to be stopped again. When the list is empty Stop
	// succeeds.
	StopErrs []error

	mu        sync.Mutex
	sandboxes []*Sandbox
}

// New returns a fake backend with the default behaviour.
func New() *Backend { return &Backend{} }

var _ sandbox.Backend = (*Backend)(nil)

func (b *Backend) name() string {
	if b.Name == "" {
		return policy.BackendNative
	}
	return b.Name
}

func (b *Backend) scope() sandbox.Scope {
	if b.Scope == "" {
		return sandbox.ScopeInitAndWorkload
	}
	return b.Scope
}

// Info implements sandbox.Backend.
func (b *Backend) Info() sandbox.Info {
	return sandbox.Info{Name: b.name(), Isolation: "none (test double)", Scope: b.scope()}
}

// Capabilities implements sandbox.Backend the way a real backend must: it
// starts from the host report and only ever withdraws.
func (b *Backend) Capabilities(report hostprobe.Report) sandbox.Capabilities {
	caps := report.Capabilities(b.name())
	for id, reason := range b.Withdraw {
		caps.Controls[id] = policy.Control{Reason: reason}
	}
	return caps
}

// Start implements sandbox.Backend. It creates the writable layer inside
// spec.Dir, which must exist.
func (b *Backend) Start(ctx context.Context, spec sandbox.Spec) (sandbox.Sandbox, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	startErr := b.StartErr
	b.mu.Unlock()
	if startErr != nil {
		return nil, startErr
	}
	if spec.ID.IsZero() {
		return nil, errors.New("sandboxtest: the spec has no session identifier")
	}
	if !filepath.IsAbs(spec.Dir) {
		return nil, fmt.Errorf("sandboxtest: the spec's directory %q is not an absolute path", spec.Dir)
	}
	if fi, err := os.Stat(spec.Dir); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("sandboxtest: the session directory must exist before Start: %v", err)
	}
	s := &Sandbox{backend: b, spec: spec, base: sandbox.ImageBase}
	if err := os.MkdirAll(s.upper(), 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(spec.Dir, "snap"), 0o755); err != nil {
		return nil, err
	}
	b.mu.Lock()
	b.sandboxes = append(b.sandboxes, s)
	b.mu.Unlock()
	return s, nil
}

// Sandboxes returns the sandboxes started so far, oldest first.
func (b *Backend) Sandboxes() []*Sandbox {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]*Sandbox(nil), b.sandboxes...)
}

func (b *Backend) nextStopErr() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.StopErrs) == 0 {
		return nil
	}
	err := b.StopErrs[0]
	b.StopErrs = b.StopErrs[1:]
	return err
}

// Sandbox is one session of the fake backend.
type Sandbox struct {
	backend *Backend
	spec    sandbox.Spec

	mu sync.Mutex
	// busy is true while Exec, Snapshot or Restore runs.
	busy bool
	// kill ends the running command with a reason; nil when none runs.
	kill func(sandbox.KillReason)
	// done is closed when the running command has returned.
	done    chan struct{}
	stopped bool
	stops   int
	calls   []Call
	// snaps lists the snapshots the writable layer sits on, oldest first;
	// all holds every snapshot ever taken and its parent chain.
	snaps []ids.ID
	all   map[ids.ID][]ids.ID
	base  sandbox.Base
}

var _ sandbox.Sandbox = (*Sandbox)(nil)

func (s *Sandbox) upper() string { return filepath.Join(s.spec.Dir, "upper") }

func (s *Sandbox) snapDir(id ids.ID) string { return filepath.Join(s.spec.Dir, "snap", id.String()) }

// ID implements sandbox.Sandbox.
func (s *Sandbox) ID() ids.ID { return s.spec.ID }

// Spec returns the spec the sandbox was started with.
func (s *Sandbox) Spec() sandbox.Spec { return s.spec }

// Calls returns the commands given to the sandbox so far, oldest first,
// whether or not they have ended.
func (s *Sandbox) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Call(nil), s.calls...)
}

// Stopped reports whether a Stop succeeded.
func (s *Sandbox) Stopped() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopped
}

// StopCalls returns how many times Stop was called, failures included.
func (s *Sandbox) StopCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stops
}

// begin takes the one slot of the sandbox.
func (s *Sandbox) begin() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return sandbox.ErrStopped
	}
	if s.busy {
		return sandbox.ErrBusy
	}
	s.busy = true
	return nil
}

func (s *Sandbox) end() {
	s.mu.Lock()
	s.busy = false
	s.mu.Unlock()
}

// Exec implements sandbox.Sandbox.
func (s *Sandbox) Exec(ctx context.Context, argv []string, opts sandbox.ExecOptions) (sandbox.Result, error) {
	if len(argv) == 0 {
		return sandbox.Result{}, errors.New("sandboxtest: empty command")
	}
	for i, a := range argv {
		if !utf8.ValidString(a) || strings.ContainsRune(a, 0) {
			return sandbox.Result{}, fmt.Errorf("sandboxtest: argument %d is not valid UTF-8 or holds a NUL byte", i)
		}
	}
	wall := s.spec.Limits.Wall
	if opts.Timeout < 0 || (wall > 0 && opts.Timeout > wall) {
		return sandbox.Result{}, fmt.Errorf("%w: a timeout of %v is not within the limit of %v", sandbox.ErrUnsupported, opts.Timeout, wall)
	}
	if opts.Timeout > 0 {
		wall = opts.Timeout
	}
	if err := s.begin(); err != nil {
		return sandbox.Result{}, err
	}

	// From here on the command is under way: whatever happens is a Result.
	runCtx, cancel := context.WithCancel(context.Background())
	var (
		once   sync.Once
		reason sandbox.KillReason
	)
	kill := func(r sandbox.KillReason) {
		once.Do(func() {
			reason = r
			cancel()
		})
	}
	done := make(chan struct{})
	call := Call{Argv: append([]string(nil), argv...), Opts: opts, Upper: s.upper(), Spec: s.spec}
	s.mu.Lock()
	s.kill, s.done = kill, done
	s.calls = append(s.calls, call)
	s.mu.Unlock()

	stopWatch := context.AfterFunc(ctx, func() { kill(sandbox.KillCancelled) })
	var timer *time.Timer
	if wall > 0 {
		timer = time.AfterFunc(wall, func() { kill(sandbox.KillWallTimeout) })
	}

	step := s.backend.Step
	if step == nil {
		step = Exit(0)
	}
	started := time.Now()
	res, err := step(runCtx, call)
	stopWatch()
	if timer != nil {
		timer.Stop()
	}
	// Settle the reason: after this call no kill can still be writing it.
	kill("")

	if res.Status == "" && reason != "" {
		res.Status, res.KillReason, res.Signal, res.ExitCode, res.Error = sandbox.StatusKilled, reason, 9, 0, ""
	} else if res.Status == "" {
		res.Status = sandbox.StatusExited
	}
	if res.Started.IsZero() {
		res.Started = started
	}
	if res.Duration == 0 {
		res.Duration = time.Since(started)
	}
	if res.Counters.Scope == "" {
		res.Counters.Scope = s.backend.scope()
	}
	if res.Storage.Upper == "" {
		res.Storage.Upper = s.spec.Storage
	}
	if res.Enforcement.SyscallProfile == "" {
		res.Enforcement.SyscallProfile = s.spec.SyscallProfile
	}

	s.mu.Lock()
	s.kill, s.done = nil, nil
	s.busy = false
	s.mu.Unlock()
	close(done)
	cancel()
	if err != nil {
		return sandbox.Result{}, err
	}
	return res, nil
}

// Stop implements sandbox.Sandbox.
func (s *Sandbox) Stop(ctx context.Context) error {
	s.mu.Lock()
	s.stops++
	kill, done := s.kill, s.done
	s.mu.Unlock()
	if kill != nil {
		kill(sandbox.KillStopped)
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err := s.backend.nextStopErr(); err != nil {
		return err
	}
	s.mu.Lock()
	s.stopped = true
	s.mu.Unlock()
	return nil
}

// Snapshot implements sandbox.Sandbox: the writable layer becomes a
// snapshot directory and an empty one takes its place.
func (s *Sandbox) Snapshot(ctx context.Context) (ids.ID, error) {
	if err := ctx.Err(); err != nil {
		return ids.ID{}, err
	}
	if err := s.begin(); err != nil {
		return ids.ID{}, err
	}
	defer s.end()
	id, err := ids.New()
	if err != nil {
		return ids.ID{}, err
	}
	if err := os.Rename(s.upper(), s.snapDir(id)); err != nil {
		return ids.ID{}, err
	}
	if err := os.Mkdir(s.upper(), 0o755); err != nil {
		return ids.ID{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.all == nil {
		s.all = map[ids.ID][]ids.ID{}
	}
	s.all[id] = append([]ids.ID(nil), s.snaps...)
	s.snaps = append(s.snaps, id)
	s.base = sandbox.Base{Kind: sandbox.BaseSnapshot, Snapshot: id}
	return id, nil
}

// Restore implements sandbox.Sandbox.
func (s *Sandbox) Restore(ctx context.Context, to sandbox.Base) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.begin(); err != nil {
		return err
	}
	defer s.end()
	s.mu.Lock()
	var chain []ids.ID
	switch to.Kind {
	case sandbox.BaseImage:
		if !to.Snapshot.IsZero() {
			s.mu.Unlock()
			return fmt.Errorf("%w: the image base names no snapshot", sandbox.ErrUnknownSnapshot)
		}
	case sandbox.BaseSnapshot:
		parents, ok := s.all[to.Snapshot]
		if !ok {
			s.mu.Unlock()
			return sandbox.ErrUnknownSnapshot
		}
		chain = append(append([]ids.ID(nil), parents...), to.Snapshot)
	default:
		s.mu.Unlock()
		return fmt.Errorf("%w: base kind %q", sandbox.ErrUnknownSnapshot, to.Kind)
	}
	s.mu.Unlock()
	if err := os.RemoveAll(s.upper()); err != nil {
		return err
	}
	if err := os.Mkdir(s.upper(), 0o755); err != nil {
		return err
	}
	s.mu.Lock()
	s.snaps, s.base = chain, to
	s.mu.Unlock()
	return nil
}

// Layers implements sandbox.Sandbox.
func (s *Sandbox) Layers() (sandbox.LayerView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return sandbox.LayerView{}, sandbox.ErrStopped
	}
	if s.busy {
		return sandbox.LayerView{}, sandbox.ErrBusy
	}
	v := sandbox.LayerView{Upper: s.upper(), Base: s.base, XattrPrefix: "trusted.overlay."}
	for i := len(s.snaps) - 1; i >= 0; i-- {
		v.Lowers = append(v.Lowers, sandbox.Layer{Dir: s.snapDir(s.snaps[i]), Kind: sandbox.LayerSnapshot, Snapshot: s.snaps[i]})
	}
	if s.spec.Workspace != "" {
		v.Lowers = append(v.Lowers, sandbox.Layer{Dir: s.spec.Workspace, Kind: sandbox.LayerWorkspace})
	}
	for i := len(s.spec.Layers) - 1; i >= 0; i-- {
		v.Lowers = append(v.Lowers, sandbox.Layer{Dir: s.spec.Layers[i], Kind: sandbox.LayerImage})
	}
	return v, nil
}
