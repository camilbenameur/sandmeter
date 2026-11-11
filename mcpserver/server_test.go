package mcpserver

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/camilbenameur/sandmeter/sandbox"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type fakeService struct {
	mu       sync.Mutex
	calls    []string
	starts   []StartRequest
	runErr   error
	runRes   RunResult
	stopped  []string
	startErr error
	stopErr  error
}

func (f *fakeService) rec(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, s)
}

func (f *fakeService) Start(_ context.Context, req StartRequest) (Session, error) {
	f.rec("start")
	f.mu.Lock()
	f.starts = append(f.starts, req)
	f.mu.Unlock()
	if f.startErr != nil {
		return Session{}, f.startErr
	}
	return Session{ID: "s1", Backend: req.Backend, ImageDigest: "sha256:abc", Capabilities: sandbox.Capabilities{Backend: req.Backend}}, nil
}

func (f *fakeService) Run(_ context.Context, id string, argv []string) (RunResult, error) {
	f.rec("run:" + id + ":" + strings.Join(argv, " "))
	if f.runErr != nil {
		return RunResult{}, f.runErr
	}
	return f.runRes, nil
}

func (f *fakeService) Snapshot(_ context.Context, id string) (string, error) {
	f.rec("snapshot:" + id)
	return "snap1", nil
}

func (f *fakeService) Restore(_ context.Context, id, snap string) error {
	f.rec("restore:" + id + ":" + snap)
	return nil
}

func (f *fakeService) Stop(_ context.Context, id string) error {
	f.rec("stop:" + id)
	f.mu.Lock()
	f.stopped = append(f.stopped, id)
	f.mu.Unlock()
	return f.stopErr
}

func (f *fakeService) Report(_ context.Context, path string) (string, error) {
	f.rec("report:" + path)
	return "receipt ok: 1 file changed", nil
}

func connect(t *testing.T, svc Service) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	ct, st := mcp.NewInMemoryTransports()
	ss, err := New(svc, "test").Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error: %v", name, err)
	}
	return res
}

func text(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatal("no content")
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content is %T", res.Content[0])
	}
	return tc.Text
}

func TestListTools(t *testing.T) {
	cs := connect(t, &fakeService{})
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, tool := range res.Tools {
		got[tool.Name] = tool.Description
	}
	for _, name := range []string{"start", "run", "snapshot", "restore", "stop", "report"} {
		if got[name] == "" {
			t.Errorf("tool %q missing or without description", name)
		}
	}
	if len(got) != 6 {
		t.Errorf("got %d tools, want 6", len(got))
	}
	if !strings.Contains(got["run"], "educational prototype") {
		t.Errorf("run description lacks the prototype warning: %q", got["run"])
	}
}

func TestStartAndRunInSession(t *testing.T) {
	svc := &fakeService{runRes: RunResult{ExitCode: 0, Stdout: "hi\n", ReceiptPath: "/r/1.json", DurationMS: 12}}
	cs := connect(t, svc)

	res := call(t, cs, "start", map[string]any{"backend": "native", "image": "alpine"})
	if res.IsError {
		t.Fatalf("start failed: %s", text(t, res))
	}
	if svc.starts[0].Image != "alpine" {
		t.Errorf("image not forwarded: %+v", svc.starts[0])
	}

	res = call(t, cs, "run", map[string]any{"session_id": "s1", "argv": []string{"echo", "hi"}})
	if res.IsError {
		t.Fatalf("run failed: %s", text(t, res))
	}
	if !strings.Contains(text(t, res), "hi") || !strings.Contains(text(t, res), "/r/1.json") {
		t.Errorf("unexpected text: %q", text(t, res))
	}
	if res.StructuredContent == nil {
		t.Error("no structured content")
	}
	for _, c := range svc.calls {
		if strings.HasPrefix(c, "stop:") {
			t.Errorf("a session run must not stop the session: %v", svc.calls)
		}
	}
}

func TestEphemeralRun(t *testing.T) {
	svc := &fakeService{runRes: RunResult{Stdout: "x"}}
	cs := connect(t, svc)
	res := call(t, cs, "run", map[string]any{"argv": []string{"true"}})
	if res.IsError {
		t.Fatalf("run failed: %s", text(t, res))
	}
	want := []string{"start", "run:s1:true", "stop:s1"}
	if strings.Join(svc.calls, ",") != strings.Join(want, ",") {
		t.Errorf("calls = %v, want %v", svc.calls, want)
	}
	if svc.starts[0].Backend != "native" || svc.starts[0].Image != "docker.io/library/alpine:3.20" || svc.starts[0].PolicyTOML != "" {
		t.Errorf("defaults not applied: %+v", svc.starts[0])
	}
	if !strings.Contains(text(t, res), "throwaway") {
		t.Errorf("output does not say the session was ephemeral: %q", text(t, res))
	}
}

func TestEphemeralRunStopsAfterRunError(t *testing.T) {
	svc := &fakeService{runErr: errors.New("boom")}
	cs := connect(t, svc)
	res := call(t, cs, "run", map[string]any{"argv": []string{"true"}})
	if !res.IsError {
		t.Fatal("want IsError")
	}
	if len(svc.stopped) != 1 {
		t.Errorf("session not stopped after error: %v", svc.calls)
	}
	if !strings.Contains(text(t, res), "boom") {
		t.Errorf("error text lost: %q", text(t, res))
	}
}

func TestSnapshotRestoreStopReport(t *testing.T) {
	svc := &fakeService{runRes: RunResult{ReceiptPath: "/r/1.json"}}
	cs := connect(t, svc)
	call(t, cs, "run", map[string]any{"session_id": "s1", "argv": []string{"true"}})
	svc.calls = nil
	if res := call(t, cs, "snapshot", map[string]any{"session_id": "s1"}); res.IsError || !strings.Contains(text(t, res), "snap1") {
		t.Errorf("snapshot: %v %q", res.IsError, text(t, res))
	}
	if res := call(t, cs, "restore", map[string]any{"session_id": "s1", "snapshot_id": "snap1"}); res.IsError {
		t.Errorf("restore: %s", text(t, res))
	}
	if res := call(t, cs, "stop", map[string]any{"session_id": "s1"}); res.IsError {
		t.Errorf("stop: %s", text(t, res))
	}
	res := call(t, cs, "report", map[string]any{"receipt_path": "/r/1.json"})
	if res.IsError || text(t, res) != "receipt ok: 1 file changed" {
		t.Errorf("report: %v %q", res.IsError, text(t, res))
	}
	want := "snapshot:s1,restore:s1:snap1,stop:s1,report:/r/1.json"
	if strings.Join(svc.calls, ",") != want {
		t.Errorf("calls = %v", svc.calls)
	}
}

func TestInputValidation(t *testing.T) {
	long := make([]string, maxArgv+1)
	for i := range long {
		long[i] = "a"
	}
	cases := []struct {
		name, tool, want string
		args             map[string]any
	}{
		{"empty argv", "run", "argv must not be empty", map[string]any{"argv": []string{}}},
		{"empty argv[0]", "run", "argv[0] must not be empty", map[string]any{"argv": []string{""}}},
		{"too many argv", "run", "limit is 256", map[string]any{"argv": long}},
		{"empty session", "snapshot", "session_id must not be empty", map[string]any{"session_id": ""}},
		{"blank stop id", "stop", "session_id must not be empty", map[string]any{"session_id": " "}},
		{"empty snapshot id", "restore", "snapshot_id must not be empty", map[string]any{"session_id": "s1", "snapshot_id": ""}},
		{"empty receipt", "report", "receipt_path must not be empty", map[string]any{"receipt_path": ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &fakeService{}
			cs := connect(t, svc)
			res := call(t, cs, tc.tool, tc.args)
			if !res.IsError {
				t.Fatalf("accepted invalid input")
			}
			if !strings.Contains(text(t, res), tc.want) {
				t.Errorf("message %q lacks %q", text(t, res), tc.want)
			}
			if len(svc.calls) != 0 {
				t.Errorf("service reached: %v", svc.calls)
			}
		})
	}
}

func TestReportRefusesUnknownPath(t *testing.T) {
	svc := &fakeService{}
	cs := connect(t, svc)
	res := call(t, cs, "report", map[string]any{"receipt_path": "/etc/shadow"})
	if !res.IsError || !strings.Contains(text(t, res), "not returned by run") {
		t.Errorf("want refusal, got %v %q", res.IsError, text(t, res))
	}
	if len(svc.calls) != 0 {
		t.Errorf("service reached: %v", svc.calls)
	}
}

func TestStartForwardsPolicy(t *testing.T) {
	svc := &fakeService{}
	cs := connect(t, svc)
	const pol = "[network]\nmode = \"none\"\n"
	if res := call(t, cs, "start", map[string]any{"policy_toml": pol}); res.IsError {
		t.Fatal(text(t, res))
	}
	if svc.starts[0].PolicyTOML != pol {
		t.Errorf("policy not forwarded: %+v", svc.starts[0])
	}
}

func structured(t *testing.T, res *mcp.CallToolResult) map[string]any {
	t.Helper()
	m, ok := res.StructuredContent.(map[string]any)
	if !ok {
		t.Fatalf("structured content is %T", res.StructuredContent)
	}
	return m
}

func TestRunStructuredSessionFields(t *testing.T) {
	cs := connect(t, &fakeService{})
	m := structured(t, call(t, cs, "run", map[string]any{"session_id": "s7", "argv": []string{"true"}}))
	if m["session_id"] != "s7" || m["ephemeral"] != false {
		t.Errorf("session run: %v", m)
	}
	m = structured(t, call(t, cs, "run", map[string]any{"argv": []string{"true"}}))
	if m["ephemeral"] != true || m["session_id"] != nil {
		t.Errorf("ephemeral run: %v", m)
	}
}

func TestEphemeralStartFailureDoesNotStop(t *testing.T) {
	svc := &fakeService{startErr: errors.New("needs root")}
	cs := connect(t, svc)
	res := call(t, cs, "run", map[string]any{"argv": []string{"true"}})
	if !res.IsError || !strings.Contains(text(t, res), "needs root") {
		t.Errorf("got %v %q", res.IsError, text(t, res))
	}
	if len(svc.stopped) != 0 {
		t.Errorf("stop called without a session: %v", svc.calls)
	}
}

func TestEphemeralStopFailureIsReported(t *testing.T) {
	svc := &fakeService{stopErr: errors.New("cgroup busy"), runRes: RunResult{Stdout: "ok"}}
	cs := connect(t, svc)
	res := call(t, cs, "run", map[string]any{"argv": []string{"true"}})
	if res.IsError {
		t.Fatalf("run output should still be returned: %s", text(t, res))
	}
	got := text(t, res)
	if !strings.Contains(got, "WARNING") || !strings.Contains(got, "cgroup busy") || strings.Contains(got, "started and stopped") {
		t.Errorf("stop failure not reported: %q", got)
	}
	if structured(t, res)["stop_error"] == nil {
		t.Error("stop_error missing from structured content")
	}

	svc.runErr = errors.New("boom")
	res = call(t, cs, "run", map[string]any{"argv": []string{"true"}})
	if !res.IsError || !strings.Contains(text(t, res), "boom") || !strings.Contains(text(t, res), "cgroup busy") {
		t.Errorf("both errors expected: %q", text(t, res))
	}
}

func TestEphemeralStopSurvivesCancelledContext(t *testing.T) {
	svc := &ctxService{}
	h := &handlers{svc: svc, receipts: map[string]struct{}{}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.runEphemeral(ctx, RunInput{Argv: []string{"true"}}) //nolint:errcheck
	if !svc.stopCtxLive {
		t.Error("Stop received a cancelled context")
	}
	if !svc.stopHasDeadline {
		t.Error("Stop context has no deadline")
	}
}

// ctxService records the state of the context handed to Stop.
type ctxService struct {
	fakeService
	stopCtxLive, stopHasDeadline bool
}

func (c *ctxService) Run(ctx context.Context, _ string, _ []string) (RunResult, error) {
	return RunResult{}, ctx.Err()
}

func (c *ctxService) Stop(ctx context.Context, _ string) error {
	c.stopCtxLive = ctx.Err() == nil
	_, c.stopHasDeadline = ctx.Deadline()
	return nil
}

func TestServiceErrorBecomesToolError(t *testing.T) {
	svc := &fakeService{runErr: errors.New("session s9 not found")}
	cs := connect(t, svc)
	res := call(t, cs, "run", map[string]any{"session_id": "s9", "argv": []string{"ls"}})
	if !res.IsError {
		t.Fatal("want IsError")
	}
	if !strings.Contains(text(t, res), "session s9 not found") {
		t.Errorf("message lost: %q", text(t, res))
	}

	svc.startErr = errors.New("needs root")
	res = call(t, cs, "start", map[string]any{})
	if !res.IsError || !strings.Contains(text(t, res), "needs root") {
		t.Errorf("start error: %v %q", res.IsError, text(t, res))
	}
}

func TestTextIsCapped(t *testing.T) {
	big := strings.Repeat("é", 40<<10)
	text40 := strings.Repeat("é", 20<<10) // 40 KiB of header-free body via summary
	svc := &fakeService{runRes: RunResult{Summary: big + text40}}
	cs := connect(t, svc)
	res := call(t, cs, "run", map[string]any{"session_id": "s1", "argv": []string{"cat"}})
	got := text(t, res)
	if len(got) > maxTextBytes {
		t.Errorf("text is %d bytes, cap is %d", len(got), maxTextBytes)
	}
	if !strings.Contains(got, "text truncated at 32 KiB") {
		t.Error("no truncation note")
	}
	if !utf8.ValidString(got) {
		t.Error("text is not valid UTF-8")
	}
}

func TestCapTextKeepsRuneBoundary(t *testing.T) {
	const note = "\n[text truncated at 32 KiB; the full value is in the structured content]"
	// Place a 3-byte rune so that it straddles the cut point.
	prefix := strings.Repeat("a", maxTextBytes-len(note)-1)
	got := capText(prefix + "€" + strings.Repeat("b", 100))
	if !utf8.ValidString(got) || !strings.HasSuffix(got, note) || len(got) > maxTextBytes {
		t.Errorf("bad cap: valid=%v len=%d", utf8.ValidString(got), len(got))
	}
	if strings.Contains(got, "€") {
		t.Error("straddling rune should have been dropped whole")
	}
}

func TestStderrSurvivesLargeStdout(t *testing.T) {
	svc := &fakeService{runRes: RunResult{
		Stdout: strings.Repeat("o", 64<<10),
		Stderr: "FATAL-MARKER: it broke\n",
	}}
	cs := connect(t, svc)
	got := text(t, call(t, cs, "run", map[string]any{"session_id": "s1", "argv": []string{"x"}}))
	if !strings.Contains(got, "FATAL-MARKER") {
		t.Errorf("stderr pushed out of the text (%d bytes)", len(got))
	}
}
