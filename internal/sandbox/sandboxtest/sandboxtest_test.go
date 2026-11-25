package sandboxtest

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/camilbenameur/sandmeter/internal/hostprobe"
	"github.com/camilbenameur/sandmeter/internal/ids"
	"github.com/camilbenameur/sandmeter/internal/sandbox"
	"github.com/camilbenameur/sandmeter/policy"
)

func start(t *testing.T, b *Backend, mutate func(*sandbox.Spec)) *Sandbox {
	t.Helper()
	spec := NewSpec(t)
	// Tests that are about the time limit set one; the others have none.
	spec.Limits.Wall = sandbox.NoLimit()
	if mutate != nil {
		mutate(&spec)
	}
	sb, err := b.Start(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	return sb.(*Sandbox)
}

func TestExecDefaultsAndOutput(t *testing.T) {
	b := New()
	s := start(t, b, nil)
	res, err := s.Exec(context.Background(), []string{"true"}, sandbox.ExecOptions{})
	if err != nil || res.Status != sandbox.StatusExited || res.ExitCode != 0 {
		t.Fatalf("default step: %+v, %v", res, err)
	}
	if res.Counters.Scope != sandbox.ScopeInitAndWorkload || res.Storage.Upper != sandbox.StorageDisk || res.Started.IsZero() {
		t.Errorf("the fake left blanks in the result: %+v", res)
	}
	// A counter nobody measured stays nil: the fake does not invent zeros.
	if res.Counters.MemoryPeakBytes != nil || res.Flows.Recorded {
		t.Errorf("unmeasured evidence was filled in: %+v", res)
	}

	b.Step = Output("out\n", "err\n", 3)
	var stdout, stderr bytes.Buffer
	res, err = s.Exec(context.Background(), []string{"sh", "-c", "x"}, sandbox.ExecOptions{Stdout: &stdout, Stderr: &stderr})
	if err != nil || res.ExitCode != 3 || stdout.String() != "out\n" || stderr.String() != "err\n" {
		t.Errorf("output step: %+v, %v, %q, %q", res, err, stdout.String(), stderr.String())
	}
	calls := s.Calls()
	if len(calls) != 2 || calls[1].Argv[0] != "sh" || calls[1].Spec.ID != s.ID() {
		t.Errorf("calls: %+v", calls)
	}
	if got := b.Sandboxes(); len(got) != 1 || got[0] != s {
		t.Errorf("Sandboxes() = %v", got)
	}
}

func TestExecRefusesWhatWasNeverAttempted(t *testing.T) {
	s := start(t, New(), func(spec *sandbox.Spec) { spec.Limits.Wall = sandbox.AtMost(int64(time.Second)) })
	for name, argv := range map[string][]string{"empty": nil, "nul": {"a\x00b"}, "not utf-8": {"ok", "\xff"}} {
		if _, err := s.Exec(context.Background(), argv, sandbox.ExecOptions{}); err == nil {
			t.Errorf("%s: Exec accepted it", name)
		}
	}
	if _, err := s.Exec(context.Background(), []string{"true"}, sandbox.ExecOptions{Timeout: time.Minute}); !errors.Is(err, sandbox.ErrUnsupported) {
		t.Errorf("a timeout above the limit: %v, want ErrUnsupported", err)
	}
	if len(s.Calls()) != 0 {
		t.Errorf("a refused Exec was recorded as a command: %+v", s.Calls())
	}
}

// running starts a blocking command and returns when it is under way.
func running(t *testing.T, s *Sandbox, ctx context.Context, opts sandbox.ExecOptions) <-chan sandbox.Result {
	t.Helper()
	out := make(chan sandbox.Result, 1)
	go func() {
		res, err := s.Exec(ctx, []string{"sleep", "1000"}, opts)
		if err != nil {
			t.Errorf("Exec of a blocking command: %v", err)
		}
		out <- res
	}()
	deadline := time.Now().Add(5 * time.Second)
	for len(s.Calls()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the command never started")
		}
		time.Sleep(time.Millisecond)
	}
	return out
}

func TestOneThingAtATime(t *testing.T) {
	b := New()
	b.Step = Block
	s := start(t, b, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := running(t, s, ctx, sandbox.ExecOptions{})

	if _, err := s.Exec(context.Background(), []string{"true"}, sandbox.ExecOptions{}); !errors.Is(err, sandbox.ErrBusy) {
		t.Errorf("a second Exec: %v, want ErrBusy", err)
	}
	if _, err := s.Snapshot(context.Background()); !errors.Is(err, sandbox.ErrBusy) {
		t.Errorf("Snapshot during a command: %v, want ErrBusy", err)
	}
	if err := s.Restore(context.Background(), sandbox.ImageBase); !errors.Is(err, sandbox.ErrBusy) {
		t.Errorf("Restore during a command: %v, want ErrBusy", err)
	}
	if _, err := s.Layers(); !errors.Is(err, sandbox.ErrBusy) {
		t.Errorf("Layers during a command: %v, want ErrBusy", err)
	}

	cancel()
	res := <-out
	if res.Status != sandbox.StatusKilled || res.KillReason != sandbox.KillCancelled || res.Signal != 9 {
		t.Errorf("a cancelled command: %+v", res)
	}
}

func TestStopKillsARunningCommandAndIsFinal(t *testing.T) {
	b := New()
	b.Step = Block
	s := start(t, b, nil)
	out := running(t, s, context.Background(), sandbox.ExecOptions{})
	if err := s.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Stop waits for the command to end, but the goroutine that called Exec
	// still has to hand its result over: give it time instead of looking
	// once. A command that Stop did not kill blocks for good and fails here.
	select {
	case res := <-out:
		if res.KillReason != sandbox.KillStopped {
			t.Errorf("the stopped command says %q", res.KillReason)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Stop returned and the command it should have killed is still running")
	}
	if _, err := s.Exec(context.Background(), []string{"true"}, sandbox.ExecOptions{}); !errors.Is(err, sandbox.ErrStopped) {
		t.Errorf("Exec after Stop: %v, want ErrStopped", err)
	}
	if _, err := s.Layers(); !errors.Is(err, sandbox.ErrStopped) {
		t.Errorf("Layers after Stop: %v, want ErrStopped", err)
	}
	if err := s.Stop(context.Background()); err != nil {
		t.Errorf("a second Stop: %v", err)
	}
}

func TestStopCanFailAndBeRepeated(t *testing.T) {
	b := New()
	boom := errors.New("the cgroup would not empty")
	b.StopErrs = []error{boom}
	s := start(t, b, nil)
	ctx := context.Background()
	if err := s.Stop(ctx); !errors.Is(err, boom) {
		t.Fatalf("first Stop: %v", err)
	}
	if s.Stopped() {
		t.Error("a failed Stop is reported as a Stop that succeeded")
	}

	// The contract: once Stop was called, every operation but Stop answers
	// ErrStopped. A Stop that failed is a Stop that was called. A caller
	// that goes on using the sandbox after it must not pass its tests here.
	if res, err := s.Exec(ctx, []string{"true"}, sandbox.ExecOptions{}); !errors.Is(err, sandbox.ErrStopped) {
		t.Errorf("Exec after a failed Stop: %+v, %v; want ErrStopped", res, err)
	}
	if _, err := s.Layers(); !errors.Is(err, sandbox.ErrStopped) {
		t.Errorf("Layers after a failed Stop: %v, want ErrStopped", err)
	}
	if _, err := s.Snapshot(ctx); !errors.Is(err, sandbox.ErrStopped) {
		t.Errorf("Snapshot after a failed Stop: %v, want ErrStopped", err)
	}
	if err := s.Restore(ctx, sandbox.ImageBase); !errors.Is(err, sandbox.ErrStopped) {
		t.Errorf("Restore after a failed Stop: %v, want ErrStopped", err)
	}
	if len(s.Calls()) != 0 {
		t.Errorf("a command ran after a failed Stop: %+v", s.Calls())
	}

	// Stop itself can be repeated, and then succeeds.
	if err := s.Stop(ctx); err != nil || !s.Stopped() || s.StopCalls() != 2 {
		t.Errorf("second Stop: %v, stopped %v, calls %d", err, s.Stopped(), s.StopCalls())
	}
}

// TestStopAgainstAStartingCommand races Stop with an Exec that is just
// starting, many times. Whichever comes first, the promise holds: when Stop
// has returned nothing runs any more. Either the command never started and
// Exec answers ErrStopped, or it started and Stop killed it and waited.
//
// The step blocks until it is killed, so a Stop that misses a command leaves
// it running for ever: the test then fails on its deadline instead of
// passing by luck.
func TestStopAgainstAStartingCommand(t *testing.T) {
	const rounds = 2000
	b := New()
	b.Step = Block
	dir := t.TempDir()
	base := NewSpec(t)
	base.Limits.Wall = sandbox.NoLimit()
	for round := 0; round < rounds; round++ {
		spec := base
		id, err := ids.New()
		if err != nil {
			t.Fatal(err)
		}
		spec.ID, spec.Dir = id, filepath.Join(dir, id.String())
		if err := os.Mkdir(spec.Dir, 0o700); err != nil {
			t.Fatal(err)
		}
		sb, err := b.Start(context.Background(), spec)
		if err != nil {
			t.Fatal(err)
		}
		s := sb.(*Sandbox)

		type outcome struct {
			res sandbox.Result
			err error
		}
		var (
			gate    = make(chan struct{})
			ready   sync.WaitGroup
			execOut = make(chan outcome, 1)
			stopOut = make(chan error, 1)
		)
		ready.Add(2)
		go func() {
			ready.Done()
			<-gate
			res, err := s.Exec(context.Background(), []string{"sleep", "1000"}, sandbox.ExecOptions{})
			execOut <- outcome{res, err}
		}()
		go func() {
			ready.Done()
			<-gate
			stopOut <- s.Stop(context.Background())
		}()
		ready.Wait()
		close(gate)

		deadline := time.After(10 * time.Second)
		select {
		case err := <-stopOut:
			if err != nil {
				t.Fatalf("round %d: Stop: %v", round, err)
			}
		case <-deadline:
			t.Fatalf("round %d: Stop did not return", round)
		}
		// Stop has returned: the command, if it ever started, is over.
		select {
		case out := <-execOut:
			switch {
			case errors.Is(out.err, sandbox.ErrStopped):
				if len(s.Calls()) != 0 {
					t.Fatalf("round %d: Exec answered ErrStopped and a command was recorded", round)
				}
			case out.err == nil && out.res.Status == sandbox.StatusKilled && out.res.KillReason == sandbox.KillStopped:
			default:
				t.Fatalf("round %d: the racing Exec gave %+v, %v", round, out.res, out.err)
			}
		case <-deadline:
			t.Fatalf("round %d: Stop returned nil and the command is still running: Stopped() = %v", round, s.Stopped())
		}
		if !s.Stopped() {
			t.Fatalf("round %d: Stop returned nil and the sandbox is not stopped", round)
		}
		if err := os.RemoveAll(spec.Dir); err != nil {
			t.Fatal(err)
		}
	}
}

// TestStopWaitsForASnapshot: an operation that is not a command cannot be
// killed, and Stop still does not return before it is over.
func TestStopWaitsForASnapshot(t *testing.T) {
	s := start(t, New(), nil)
	if err := s.begin(nil, nil); err != nil {
		t.Fatal(err)
	}
	stopped := make(chan error, 1)
	go func() { stopped <- s.Stop(context.Background()) }()
	select {
	case err := <-stopped:
		t.Fatalf("Stop returned (%v) while an operation held the sandbox", err)
	case <-time.After(50 * time.Millisecond):
	}
	s.end()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return after the operation ended")
	}

	// A Stop whose context ends first gives up, and can be repeated.
	s = start(t, New(), nil)
	if err := s.begin(nil, nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := s.Stop(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Stop under a short deadline: %v", err)
	}
	s.end()
	if err := s.Stop(context.Background()); err != nil || !s.Stopped() {
		t.Errorf("Stop after the operation ended: %v, stopped %v", err, s.Stopped())
	}
}

func TestWallTimeout(t *testing.T) {
	b := New()
	b.Step = Block
	s := start(t, b, func(spec *sandbox.Spec) { spec.Limits.Wall = sandbox.AtMost(int64(time.Minute)) })
	res, err := s.Exec(context.Background(), []string{"sleep", "1000"}, sandbox.ExecOptions{Timeout: 20 * time.Millisecond})
	if err != nil || res.KillReason != sandbox.KillWallTimeout {
		t.Errorf("a command past its limit: %+v, %v", res, err)
	}
}

// TestALateKillDoesNotRelabelAFinishedCommand cancels the context at the
// moment the command ends by itself: the result must say that it exited.
func TestALateKillDoesNotRelabelAFinishedCommand(t *testing.T) {
	b := New()
	ctx, cancel := context.WithCancel(context.Background())
	b.Step = func(context.Context, Call) (sandbox.Result, error) {
		// The cancellation lands while the result is being put together.
		defer cancel()
		return sandbox.Result{Status: sandbox.StatusExited, ExitCode: 4}, nil
	}
	s := start(t, b, nil)
	for i := 0; i < 200; i++ {
		res, err := s.Exec(ctx, []string{"true"}, sandbox.ExecOptions{})
		if err != nil || res.Status != sandbox.StatusExited || res.ExitCode != 4 {
			t.Fatalf("round %d: %+v, %v", i, res, err)
		}
		ctx, cancel = context.WithCancel(context.Background())
	}
	cancel()
}

func TestLayersSnapshotRestore(t *testing.T) {
	b := New()
	b.Step = Sequence(Write("workspace/a.txt", "one"), Write("workspace/b.txt", "two"), Exit(0))
	image := t.TempDir()
	workspace := t.TempDir()
	s := start(t, b, func(spec *sandbox.Spec) {
		spec.Layers = []string{image + "/bottom", image + "/top"}
		spec.Workspace = workspace
	})
	ctx := context.Background()
	if _, err := s.Exec(ctx, []string{"w"}, sandbox.ExecOptions{}); err != nil {
		t.Fatal(err)
	}
	v, err := s.Layers()
	if err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(v.Upper, "workspace", "a.txt")); err != nil || string(b) != "one" {
		t.Errorf("the written file is not in the writable layer: %q, %v", b, err)
	}
	if v.Base != sandbox.ImageBase || len(v.Lowers) != 3 || v.Lowers[0].Kind != sandbox.LayerWorkspace ||
		v.Lowers[1].Dir != image+"/top" || v.Lowers[2].Dir != image+"/bottom" || v.XattrPrefix == "" {
		t.Errorf("layers before a snapshot: %+v", v)
	}

	snap, err := s.Snapshot(ctx)
	if err != nil || snap.IsZero() {
		t.Fatalf("Snapshot: %v, %v", snap, err)
	}
	if _, err := s.Exec(ctx, []string{"w"}, sandbox.ExecOptions{}); err != nil {
		t.Fatal(err)
	}
	v, _ = s.Layers()
	if v.Base != (sandbox.Base{Kind: sandbox.BaseSnapshot, Snapshot: snap}) || len(v.Lowers) != 4 ||
		v.Lowers[0].Kind != sandbox.LayerSnapshot || v.Lowers[0].Snapshot != snap {
		t.Errorf("layers after a snapshot: %+v", v)
	}
	if _, err := os.Stat(filepath.Join(v.Lowers[0].Dir, "workspace", "a.txt")); err != nil {
		t.Errorf("the snapshot does not hold what was written before it: %v", err)
	}
	if _, err := os.Stat(filepath.Join(v.Upper, "workspace", "b.txt")); err != nil {
		t.Errorf("the new writable layer does not hold what was written after: %v", err)
	}

	other, _ := ids.New()
	if err := s.Restore(ctx, sandbox.Base{Kind: sandbox.BaseSnapshot, Snapshot: other}); !errors.Is(err, sandbox.ErrUnknownSnapshot) {
		t.Errorf("Restore to a snapshot of nobody: %v", err)
	}
	if err := s.Restore(ctx, sandbox.Base{}); !errors.Is(err, sandbox.ErrUnknownSnapshot) {
		t.Errorf("Restore to the zero base: %v", err)
	}
	if err := s.Restore(ctx, sandbox.Base{Kind: sandbox.BaseSnapshot, Snapshot: snap}); err != nil {
		t.Fatal(err)
	}
	v, _ = s.Layers()
	if entries, _ := os.ReadDir(v.Upper); len(entries) != 0 || v.Base.Snapshot != snap {
		t.Errorf("after a restore the writable layer holds %d entries on base %+v", len(entries), v.Base)
	}
	if err := s.Restore(ctx, sandbox.ImageBase); err != nil {
		t.Fatal(err)
	}
	v, _ = s.Layers()
	if v.Base != sandbox.ImageBase || len(v.Lowers) != 3 {
		t.Errorf("after a restore to the image: %+v", v)
	}
	// The snapshot is kept: the session can go back to it.
	if err := s.Restore(ctx, sandbox.Base{Kind: sandbox.BaseSnapshot, Snapshot: snap}); err != nil {
		t.Errorf("a snapshot was lost by restoring under it: %v", err)
	}
}

// TestStartRefusesWhatARealBackendRefuses: the double is no more lenient
// than the contract. A Spec with a field left out is the weakest sandbox
// there is, and an engine that builds one must not pass its tests here.
func TestStartRefusesWhatARealBackendRefuses(t *testing.T) {
	b := New()
	ctx := context.Background()
	if _, err := b.Start(ctx, NewSpec(t)); err != nil {
		t.Fatalf("the Spec of NewSpec: %v", err)
	}
	started := len(b.Sandboxes())

	if _, err := b.Start(ctx, sandbox.Spec{}); !errors.Is(err, sandbox.ErrInvalid) {
		t.Errorf("the zero Spec: %v, want ErrInvalid", err)
	}
	for name, mutate := range map[string]func(*sandbox.Spec){
		"no identifier":        func(s *sandbox.Spec) { s.ID = ids.ID{} },
		"relative dir":         func(s *sandbox.Spec) { s.Dir = "relative" },
		"a limit left out":     func(s *sandbox.Spec) { s.Limits.MemoryBytes = sandbox.Limit{} },
		"a limit of zero":      func(s *sandbox.Spec) { s.Limits.PIDs = sandbox.AtMost(0) },
		"no floor":             func(s *sandbox.Spec) { s.Floor = sandbox.Floor{} },
		"no network mode":      func(s *sandbox.Spec) { s.Network.Mode = "" },
		"unknown network mode": func(s *sandbox.Spec) { s.Network.Mode = "host" },
		"no storage mode":      func(s *sandbox.Spec) { s.Storage = "" },
		"no profile":           func(s *sandbox.Spec) { s.SyscallProfile = "" },
		"unknown profile":      func(s *sandbox.Spec) { s.SyscallProfile = "relaxed" },
		"the host's own ids":   func(s *sandbox.Spec) { s.IDBase = 0 },
	} {
		spec := NewSpec(t)
		mutate(&spec)
		if _, err := b.Start(ctx, spec); !errors.Is(err, sandbox.ErrInvalid) {
			t.Errorf("%s: Start = %v, want ErrInvalid", name, err)
		}
	}
	// The directory of a session is the engine's to create.
	missing := NewSpec(t)
	missing.Dir = filepath.Join(missing.Dir, "absent")
	if _, err := b.Start(ctx, missing); err == nil {
		t.Error("Start accepted a session directory that does not exist")
	}

	b.StartErr = sandbox.ErrUnsupported
	if _, err := b.Start(ctx, NewSpec(t)); !errors.Is(err, sandbox.ErrUnsupported) {
		t.Errorf("StartErr: %v", err)
	}
	if len(b.Sandboxes()) != started {
		t.Error("a refused Start left a sandbox")
	}
}

// TestCapabilitiesComeFromTheReport is the rule every backend follows, kept
// by the fake too: nothing is enforced that the host report does not grant,
// and a backend only withdraws.
func TestCapabilitiesComeFromTheReport(t *testing.T) {
	b := New()
	caps := b.Capabilities(PassingReport())
	if !caps.Usable() || caps.Backend != policy.BackendNative {
		t.Fatalf("with a passing report: %+v", caps)
	}
	for _, id := range policy.Controls {
		if !caps.Control(id).Enforced {
			t.Errorf("%s is not enforced with a passing report", id)
		}
	}
	none := b.Capabilities(hostprobe.Blank())
	for _, id := range policy.Controls {
		if none.Control(id).Enforced {
			t.Errorf("%s is enforced although no check ran", id)
		}
	}
	b.Withdraw = map[policy.ControlID]string{policy.ControlPIDs: "the runtime's threads are counted, not the sandbox's tasks"}
	caps = b.Capabilities(PassingReport())
	if c := caps.Control(policy.ControlPIDs); c.Enforced || c.Reason == "" {
		t.Errorf("a withdrawn control: %+v", c)
	}
	if err := PassingReport().Validate(); err != nil {
		t.Error(err)
	}
}
