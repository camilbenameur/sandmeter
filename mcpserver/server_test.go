package mcpserver

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/camilbenameur/ringfence/sandbox"
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
	return nil
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
}

func TestSnapshotRestoreStopReport(t *testing.T) {
	svc := &fakeService{}
	cs := connect(t, svc)
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
		name string
		tool string
		args map[string]any
	}{
		{"empty argv", "run", map[string]any{"argv": []string{}}},
		{"empty argv[0]", "run", map[string]any{"argv": []string{""}}},
		{"too many argv", "run", map[string]any{"argv": long}},
		{"empty session", "snapshot", map[string]any{"session_id": ""}},
		{"empty stop id", "stop", map[string]any{"session_id": " "}},
		{"empty snapshot id", "restore", map[string]any{"session_id": "s1", "snapshot_id": ""}},
		{"empty receipt", "report", map[string]any{"receipt_path": ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := &fakeService{}
			cs := connect(t, svc)
			res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tc.tool, Arguments: tc.args})
			// Either the schema layer or our checks may reject it; the service
			// must not be reached in both cases.
			if err == nil && !res.IsError {
				t.Errorf("accepted invalid input")
			}
			if len(svc.calls) != 0 {
				t.Errorf("service reached: %v", svc.calls)
			}
		})
	}
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
	svc := &fakeService{runRes: RunResult{Stdout: big, StdoutTruncated: true}}
	cs := connect(t, svc)
	res := call(t, cs, "run", map[string]any{"session_id": "s1", "argv": []string{"cat"}})
	got := text(t, res)
	if len(got) > maxTextBytes {
		t.Errorf("text is %d bytes, cap is %d", len(got), maxTextBytes)
	}
	if !strings.Contains(got, "truncated") {
		t.Error("no truncation note")
	}
}
