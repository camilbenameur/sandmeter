package clienttest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/camilbenameur/sandmeter/internal/changeset"
	"github.com/camilbenameur/sandmeter/internal/client"
	"github.com/camilbenameur/sandmeter/internal/ctl"
	"github.com/camilbenameur/sandmeter/internal/exit"
	"github.com/camilbenameur/sandmeter/internal/ids"
	"github.com/camilbenameur/sandmeter/receipt"
)

func start(t *testing.T, f *Fake, req client.StartRequest) *Session {
	t.Helper()
	c, err := f.Connect()(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.Start(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return s.(*Session)
}

func TestQuestions(t *testing.T) {
	f := New()
	ctx := context.Background()
	info, err := f.Info(ctx)
	if err != nil || info.Mode != ctl.ModeService || len(info.Backends) != 1 || info.DefaultImage == "" {
		t.Errorf("Info = %+v, %v", info, err)
	}
	probe, err := f.Probe(ctx)
	if err != nil || probe.Report.Validate() != nil || len(probe.Capabilities) != 1 || !probe.Capabilities[0].Usable() {
		t.Errorf("Probe = %+v, %v", probe, err)
	}
	images, err := f.Images(ctx)
	if err != nil || images.Default != info.DefaultImage || !strings.HasPrefix(images.Images[0].Digest, "sha256:") || len(images.Images[0].Digest) != 71 {
		t.Errorf("Images = %+v, %v", images, err)
	}
	if reply, err := f.Check(ctx, ctl.Check{}); err != nil || len(reply.Reasons) != 0 {
		t.Errorf("Check = %+v, %v", reply, err)
	}
	f.CheckFunc = func(ctl.Check) (ctl.CheckReply, error) {
		return ctl.CheckReply{Reasons: []ctl.Reason{{Code: ctl.CodePolicyRefused, Key: "limits.memory", Text: "too much"}}}, nil
	}
	if reply, _ := f.Check(ctx, ctl.Check{Policy: "x"}); len(reply.Reasons) != 1 {
		t.Errorf("a scripted check: %+v", reply)
	}
	if got := strings.Join(f.Calls(), " "); got != "Info Probe Images Check Check" {
		t.Errorf("calls: %s", got)
	}
}

func TestStartKeepsWhatWasSent(t *testing.T) {
	f := New()
	s := start(t, f, client.StartRequest{
		Policy: "version = 2\n", Image: "registry.test/tools:1", Workspace: strings.NewReader("tar bytes"),
		Env: []ctl.EnvVar{{Name: "TOKEN", Value: "v"}},
	})
	if string(s.Workspace) != "tar bytes" || s.Request.Policy != "version = 2\n" || s.Request.Workspace != nil || s.Request.Env[0].Name != "TOKEN" {
		t.Errorf("the session kept %+v, workspace %q", s.Request, s.Workspace)
	}
	st := s.Started()
	if st.Session != s.ID() || st.ImageRequested != "registry.test/tools:1" || st.Workspace == nil || st.Workspace.Bytes != 9 {
		t.Errorf("Started = %+v", st)
	}
	bare := start(t, f, client.StartRequest{})
	if bare.Started().Workspace != nil || bare.Started().ImageRequested != f.InfoReply.DefaultImage || bare.ID() == s.ID() {
		t.Errorf("a session without a project: %+v", bare.Started())
	}
	if _, err := bare.Refresh(context.Background(), strings.NewReader("")); client.CodeOf(err) != ctl.CodeInvalid {
		t.Errorf("Refresh without a project: %v", err)
	}
	list, err := f.Sessions(context.Background())
	if err != nil || len(list) != 2 || !list[0].Live || list[0].ID != s.ID() {
		t.Errorf("Sessions = %+v, %v", list, err)
	}
	if len(f.Started()) != 2 {
		t.Errorf("Started() lists %d sessions", len(f.Started()))
	}
}

func TestRunStreamsThenAnswers(t *testing.T) {
	f := New()
	seen := make(chan string, 1)
	var stdout bytes.Buffer
	f.Step = func(ctx context.Context, c RunCall) receipt.OutcomeV2 {
		io.WriteString(c.Request.Stdout, "first line\n")
		// The caller's writer has the output while the command still runs.
		seen <- stdout.String()
		io.WriteString(c.Request.Stderr, "warning\n")
		code := 3
		return receipt.OutcomeV2{Status: receipt.StatusExited, ExitCode: &code}
	}
	s := start(t, f, client.StartRequest{})
	var stderr bytes.Buffer
	res, err := s.Run(context.Background(), client.RunRequest{Argv: []string{"make", "test"}, Stdout: &stdout, Stderr: &stderr})
	if err != nil {
		t.Fatal(err)
	}
	if got := <-seen; got != "first line\n" {
		t.Errorf("while the command ran the caller had %q", got)
	}
	if res.Seq != 1 || *res.Outcome.ExitCode != 3 || res.Stdout.Bytes != 11 || res.Stdout.Delivered != 11 || res.Stderr.Bytes != 8 || len(res.Stdout.SHA256) != 64 {
		t.Errorf("Result = %+v", res)
	}
	if exit.ForOutcome(res.Outcome, false, false) != 3 {
		t.Error("the outcome does not map to the command's status")
	}
	// A nil writer discards: the bytes are counted, none is delivered.
	f.Step = Output("abc", "", 0)
	res, _ = s.Run(context.Background(), client.RunRequest{Argv: []string{"true"}})
	if res.Seq != 2 || res.Stdout.Bytes != 3 || res.Stdout.Delivered != 0 {
		t.Errorf("a run without writers: %+v", res)
	}
	if runs := s.Runs(); len(runs) != 2 || runs[0].Argv[0] != "make" {
		t.Errorf("Runs = %+v", runs)
	}
	if _, err := s.Run(context.Background(), client.RunRequest{}); client.CodeOf(err) != ctl.CodeInvalid {
		t.Errorf("an empty command: %v", err)
	}
}

func TestCancelGivesAResultAndCloseGivesAnError(t *testing.T) {
	f := New()
	f.Step = Block
	s := start(t, f, client.StartRequest{})

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	res, err := s.Run(ctx, client.RunRequest{Argv: []string{"sleep", "1000"}})
	if err != nil || res.Outcome.Status != receipt.StatusKilled || res.Outcome.KillReason != receipt.KillCancelled || res.Seq != 1 {
		t.Errorf("a cancelled run: %+v, %v", res, err)
	}

	// A second command while one runs is refused, as the root side does.
	started := make(chan struct{})
	f.Step = func(ctx context.Context, c RunCall) receipt.OutcomeV2 {
		close(started)
		return Block(ctx, c)
	}
	done := make(chan error, 1)
	go func() {
		_, err := s.Run(context.Background(), client.RunRequest{Argv: []string{"sleep", "1000"}})
		done <- err
	}()
	<-started
	if _, err := s.Run(context.Background(), client.RunRequest{Argv: []string{"true"}}); client.CodeOf(err) != ctl.CodeProtocol {
		t.Errorf("a second run during a run: %v", err)
	}
	// Dropping the connection under a command: the call fails, no result.
	s.Close()
	if err := <-done; !errors.Is(err, client.ErrClosed) {
		t.Errorf("a run whose session was closed: %v", err)
	}
	if _, err := s.Records(context.Background(), 0); !errors.Is(err, client.ErrClosed) {
		t.Errorf("Records after Close: %v", err)
	}
	if !s.Closed() {
		t.Error("Closed() is false after Close")
	}
}

func TestRecordsFollowTheOperations(t *testing.T) {
	f := New()
	f.MakeRecord = func(session ids.ID, seq uint64, kind string, detail any) []byte {
		return []byte(kind + "@" + session.String())
	}
	s := start(t, f, client.StartRequest{Workspace: strings.NewReader("p")})
	ctx := context.Background()
	if _, err := s.Run(ctx, client.RunRequest{Argv: []string{"true"}}); err != nil {
		t.Fatal(err)
	}
	snap, err := s.Snapshot(ctx)
	if err != nil || snap.Seq != 2 || snap.Snapshot.IsZero() {
		t.Fatalf("Snapshot = %+v, %v", snap, err)
	}
	other, _ := ids.New()
	if _, err := s.Restore(ctx, other); client.CodeOf(err) != ctl.CodeNotFound {
		t.Errorf("Restore to a snapshot of nobody: %v", err)
	}
	if r, err := s.Restore(ctx, snap.Snapshot); err != nil || r.Seq != 3 {
		t.Errorf("Restore = %+v, %v", r, err)
	}
	if r, err := s.Restore(ctx, ids.ID{}); err != nil || r.Seq != 4 {
		t.Errorf("Restore to the image = %+v, %v", r, err)
	}

	s.Manifest.Entries = []changeset.ExportEntry{{Path: "out.txt", Op: changeset.OpAdd, Type: changeset.TypeFile, Mode: 0o644, Size: 2, SHA256: strings.Repeat("a", 64)}}
	s.Stream = []byte("stream bytes")
	manifest, err := s.Changes(ctx)
	if err != nil || len(manifest.Entries) != 1 {
		t.Errorf("Changes = %+v, %v", manifest, err)
	}
	var out bytes.Buffer
	exported, err := s.Export(ctx, &out)
	wantHash, _ := s.Manifest.Hash()
	if err != nil || out.String() != "stream bytes" || exported.Seq != 5 || exported.ManifestSHA256 != wantHash || exported.Entries != 1 || exported.Bytes != 2 {
		t.Errorf("Export = %+v, %v, wrote %q", exported, err, out.String())
	}

	s.Superseded = []receipt.SupersededV2{{Path: "src/x.go", Type: receipt.TypeFile, Layer: "upper"}}
	refreshed, err := s.Refresh(ctx, strings.NewReader("delta"))
	if err != nil || len(refreshed.Superseded) != 1 || string(s.Refreshes()[0]) != "delta" {
		t.Errorf("Refresh = %+v, %v", refreshed, err)
	}
	if again, _ := s.Refresh(ctx, strings.NewReader("")); len(again.Superseded) != 0 || again.Superseded == nil {
		t.Errorf("a second refresh repeats the superseded paths: %+v", again)
	}

	stopped, err := s.Stop(ctx)
	if err != nil || stopped.Seq != 6 || !s.Stopped() {
		t.Fatalf("Stop = %+v, %v", stopped, err)
	}
	// Over, and still answering for its records until it is closed.
	if _, err := s.Run(ctx, client.RunRequest{Argv: []string{"true"}}); client.CodeOf(err) != ctl.CodeProtocol {
		t.Errorf("Run after Stop: %v", err)
	}
	list, err := s.Records(ctx, 0)
	if err != nil || len(list.Records) != 6 {
		t.Fatalf("Records = %+v, %v", list, err)
	}
	var kinds []string
	for _, r := range list.Records {
		kinds = append(kinds, r.Kind)
	}
	if got := strings.Join(kinds, " "); got != "command snapshot restore restore export stop" {
		t.Errorf("record kinds: %s", got)
	}
	if tail, _ := s.Records(ctx, 5); len(tail.Records) != 2 || tail.Records[0].Seq != 5 {
		t.Errorf("Records from 5 = %+v", tail)
	}
	env, err := s.Record(ctx, 5)
	if err != nil || string(env) != "export@"+s.ID().String() {
		t.Errorf("Record(5) = %q, %v", env, err)
	}
	if _, err := s.Record(ctx, 99); client.CodeOf(err) != ctl.CodeNotFound {
		t.Errorf("Record(99): %v", err)
	}
	// The same records through the client, by session identifier.
	if env, err := f.Record(ctx, s.ID(), 1); err != nil || !strings.HasPrefix(string(env), "command@") {
		t.Errorf("client Record = %q, %v", env, err)
	}
	if _, err := f.Records(ctx, other, 0); client.CodeOf(err) != ctl.CodeNotFound {
		t.Errorf("Records of an unknown session: %v", err)
	}
	if list, _ := f.Sessions(ctx); list[0].Live || list[0].LastSeq != 6 {
		t.Errorf("a stopped session is listed as %+v", list[0])
	}
}

func TestStopCancelsARunningCommandAndRecordsItFirst(t *testing.T) {
	f := New()
	started := make(chan struct{})
	f.Step = func(ctx context.Context, c RunCall) receipt.OutcomeV2 {
		close(started)
		return Block(ctx, c)
	}
	s := start(t, f, client.StartRequest{})
	results := make(chan ctl.Result, 1)
	go func() {
		res, err := s.Run(context.Background(), client.RunRequest{Argv: []string{"sleep", "1000"}})
		if err != nil {
			t.Errorf("the run that Stop cancels: %v", err)
		}
		results <- res
	}()
	<-started
	stopped, err := s.Stop(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	res := <-results
	if res.Outcome.KillReason != receipt.KillCancelled || res.Seq != 1 || stopped.Seq != 2 {
		t.Errorf("the command was recorded as %d (%s) and the stop as %d", res.Seq, res.Outcome.KillReason, stopped.Seq)
	}
}

func TestScriptedFailures(t *testing.T) {
	f := New()
	unavailable := errors.New("no socket")
	f.Fail("Connect", errors.Join(client.ErrUnavailable, unavailable))
	if _, err := f.Connect()(context.Background()); !errors.Is(err, client.ErrUnavailable) || client.ExitStatus(err) != exit.HostCannotRun {
		t.Errorf("a failed connect: %v", err)
	}
	f.Fail("Start", Refusal(ctl.CodePolicyRefused, "the policy is refused", ctl.Reason{Code: ctl.CodePolicyRefused, Key: "limits.memory", Text: "above the ceiling"}))
	_, err := f.Start(context.Background(), client.StartRequest{})
	if client.CodeOf(err) != ctl.CodePolicyRefused || client.ExitStatus(err) != exit.PolicyRefused || !strings.Contains(err.Error(), "limits.memory") {
		t.Errorf("a refused start: %v", err)
	}
	// A failure is used once.
	s := start(t, f, client.StartRequest{})
	f.Fail("Run", client.ErrClosed)
	if _, err := s.Run(context.Background(), client.RunRequest{Argv: []string{"true"}}); !errors.Is(err, client.ErrClosed) {
		t.Errorf("a scripted run failure: %v", err)
	}
	if _, err := s.Run(context.Background(), client.RunRequest{Argv: []string{"true"}}); err != nil {
		t.Errorf("the run after it: %v", err)
	}
	f.OnStart = func(*Session) error { return Refusal(ctl.CodeBudget, "no session left") }
	if _, err := f.Start(context.Background(), client.StartRequest{}); client.CodeOf(err) != ctl.CodeBudget {
		t.Errorf("OnStart refusing: %v", err)
	}
	if len(f.Started()) != 1 {
		t.Errorf("a refused start left a session: %d", len(f.Started()))
	}

	// A closed client refuses its own calls and leaves its sessions alone.
	f.Close()
	if _, err := f.Info(context.Background()); !errors.Is(err, client.ErrClosed) {
		t.Errorf("Info on a closed client: %v", err)
	}
	if _, err := s.Run(context.Background(), client.RunRequest{Argv: []string{"true"}}); err != nil {
		t.Errorf("a session after its client was closed: %v", err)
	}
}

func TestSequence(t *testing.T) {
	f := New()
	f.Step = Sequence(Exit(1), Exit(2))
	s := start(t, f, client.StartRequest{})
	for i, want := range []int{1, 2, 2} {
		res, err := s.Run(context.Background(), client.RunRequest{Argv: []string{"x"}})
		if err != nil || *res.Outcome.ExitCode != want {
			t.Errorf("command %d: %+v, %v", i+1, res.Outcome, err)
		}
	}
}

// race runs two calls at the same moment and returns when both are done, or
// fails the test when one of them is still going after the deadline.
func race(t *testing.T, round int, first, second func()) {
	t.Helper()
	var ready, done sync.WaitGroup
	gate := make(chan struct{})
	for _, call := range []func(){first, second} {
		ready.Add(1)
		done.Add(1)
		go func() {
			defer done.Done()
			ready.Done()
			<-gate
			call()
		}()
	}
	ready.Wait()
	close(gate)
	finished := make(chan struct{})
	go func() { done.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatalf("round %d: a call is still going: a command was left running after Stop or Close returned", round)
	}
}

// TestStopAgainstAStartingRun races Stop with a Run that is just starting,
// many times. The step blocks until it is cancelled, so a Stop that misses
// the command leaves it running for ever and the round never ends.
func TestStopAgainstAStartingRun(t *testing.T) {
	const rounds = 3000
	f := New()
	f.Step = Block
	c, err := f.Connect()(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < rounds; round++ {
		sess, err := c.Start(context.Background(), client.StartRequest{})
		if err != nil {
			t.Fatal(err)
		}
		s := sess.(*Session)
		var (
			res     ctl.Result
			runErr  error
			stopped ctl.Stopped
			stopErr error
		)
		race(t, round,
			func() { res, runErr = s.Run(context.Background(), client.RunRequest{Argv: []string{"sleep", "1000"}}) },
			func() { stopped, stopErr = s.Stop(context.Background()) },
		)
		if stopErr != nil {
			t.Fatalf("round %d: Stop: %v", round, stopErr)
		}
		switch {
		case client.CodeOf(runErr) == ctl.CodeProtocol:
			// Stop came first: the command never started, and has no record.
			if stopped.Seq != 1 || len(s.Runs()) != 0 {
				t.Fatalf("round %d: the run was refused, the stop record is %d and %d commands were taken", round, stopped.Seq, len(s.Runs()))
			}
		case runErr == nil && res.Outcome.KillReason == receipt.KillCancelled:
			// The command started and Stop ended it: its record comes first.
			if res.Seq != 1 || stopped.Seq != 2 {
				t.Fatalf("round %d: the command is record %d and the stop record %d", round, res.Seq, stopped.Seq)
			}
		default:
			t.Fatalf("round %d: the racing Run gave %+v, %v", round, res, runErr)
		}
	}
}

// TestCloseAgainstAStartingRun is the same race with Close: once Close has
// returned, the run fails with ErrClosed and nothing is left running.
func TestCloseAgainstAStartingRun(t *testing.T) {
	const rounds = 3000
	f := New()
	f.Step = Block
	c, err := f.Connect()(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < rounds; round++ {
		sess, err := c.Start(context.Background(), client.StartRequest{})
		if err != nil {
			t.Fatal(err)
		}
		s := sess.(*Session)
		var runErr error
		race(t, round,
			func() { _, runErr = s.Run(context.Background(), client.RunRequest{Argv: []string{"sleep", "1000"}}) },
			func() { s.Close() },
		)
		if !errors.Is(runErr, client.ErrClosed) {
			t.Fatalf("round %d: the racing Run gave %v, want ErrClosed", round, runErr)
		}
	}
}

// TestStopAfterACommandThatJustEnded calls Stop at the moment a command ends
// by itself. The command happened first and is recorded first: its record
// never follows the stop record.
func TestStopAfterACommandThatJustEnded(t *testing.T) {
	const rounds = 3000
	f := New()
	c, err := f.Connect()(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < rounds; round++ {
		ended := make(chan struct{})
		f.Step = func(context.Context, RunCall) receipt.OutcomeV2 {
			defer close(ended)
			zero := 0
			return receipt.OutcomeV2{Status: receipt.StatusExited, ExitCode: &zero}
		}
		sess, err := c.Start(context.Background(), client.StartRequest{})
		if err != nil {
			t.Fatal(err)
		}
		s := sess.(*Session)
		results := make(chan ctl.Result, 1)
		go func() {
			res, err := s.Run(context.Background(), client.RunRequest{Argv: []string{"true"}})
			if err != nil {
				t.Errorf("round %d: Run: %v", round, err)
			}
			results <- res
		}()
		<-ended
		stopped, err := s.Stop(context.Background())
		if err != nil {
			t.Fatalf("round %d: Stop: %v", round, err)
		}
		res := <-results
		if res.Seq != 1 || stopped.Seq != 2 {
			t.Fatalf("round %d: the command that ended first is record %d and the stop record %d", round, res.Seq, stopped.Seq)
		}
		list, err := s.Records(context.Background(), 0)
		if err != nil || len(list.Records) != 2 || list.Records[0].Kind != receipt.KindCommand || list.Records[1].Kind != receipt.KindStop {
			t.Fatalf("round %d: records %+v, %v", round, list.Records, err)
		}
	}
}
