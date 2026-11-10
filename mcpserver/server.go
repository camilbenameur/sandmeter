// Package mcpserver exposes the sandbox to coding agents as an MCP server
// over stdio.
package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// maxArgv bounds the command line an agent can send in one call.
	maxArgv = 256
	// maxTextBytes caps the text part of a result so one noisy command cannot
	// flood the agent's context window.
	maxTextBytes = 32 << 10

	defaultBackend = "native"
	defaultImage   = "docker.io/library/alpine:3.20"

	prototypeNote = "The sandbox is an educational prototype: do not rely on it to contain hostile code."
)

// New builds the MCP server. version is reported to clients.
func New(svc Service, version string) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "ringfence", Version: version}, nil)
	h := &handlers{svc: svc}

	mcp.AddTool(s, &mcp.Tool{
		Name: "start",
		Description: "Starts a sandbox session and returns its id and what the backend enforces on this host " +
			"(network modes, limits, seccomp, snapshots). Optionally takes a container image and a policy in TOML. " +
			"Network is off unless the policy allows hosts. " + prototypeNote,
	}, h.start)
	mcp.AddTool(s, &mcp.Tool{
		Name: "run",
		Description: "Runs a command inside an isolated sandbox and returns exit code, stdout, stderr and a signed receipt path. " +
			"With session_id it runs in that session; without it, it starts a throwaway session with the default " +
			"policy (no network), runs the command and stops the session. " + prototypeNote,
	}, h.run)
	mcp.AddTool(s, &mcp.Tool{
		Name: "snapshot",
		Description: "Saves the current filesystem state of a session and returns a snapshot id. " +
			"Not every backend supports it; the error says so when it does not.",
	}, h.snapshot)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "restore",
		Description: "Rolls the filesystem of a session back to a snapshot taken earlier with the snapshot tool.",
	}, h.restore)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "stop",
		Description: "Stops a session and releases its resources. Receipts already written stay on disk.",
	}, h.stop)
	mcp.AddTool(s, &mcp.Tool{
		Name: "report",
		Description: "Verifies the signature of a run receipt and summarizes it: files changed, connections attempted, " +
			"cgroup statistics. Takes the receipt_path returned by run.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, h.report)
	return s
}

// Serve runs the server on stdin/stdout until the client disconnects or ctx ends.
func Serve(ctx context.Context, svc Service, version string) error {
	if err := New(svc, version).Run(ctx, &mcp.StdioTransport{}); err != nil {
		return fmt.Errorf("mcp server: %w", err)
	}
	return nil
}

type handlers struct{ svc Service }

// StartInput is the argument of the start tool.
type StartInput struct {
	Backend    string `json:"backend,omitempty" jsonschema:"backend name, for example native or gvisor; defaults to native"`
	Image      string `json:"image,omitempty" jsonschema:"OCI image reference for the root filesystem; defaults to docker.io/library/alpine:3.20"`
	PolicyTOML string `json:"policy_toml,omitempty" jsonschema:"policy as TOML text; empty means the default policy (no network)"`
}

// RunInput is the argument of the run tool.
type RunInput struct {
	SessionID string   `json:"session_id,omitempty" jsonschema:"session from the start tool; omit to run in a throwaway session"`
	Argv      []string `json:"argv" jsonschema:"command and arguments, one entry per element, not a shell string; use sh -c for a shell"`
	Image     string   `json:"image,omitempty" jsonschema:"image for the throwaway session; ignored when session_id is set"`
	Backend   string   `json:"backend,omitempty" jsonschema:"backend for the throwaway session; ignored when session_id is set"`
}

// SessionInput is the argument of the snapshot and stop tools.
type SessionInput struct {
	SessionID string `json:"session_id" jsonschema:"session id returned by start"`
}

// RestoreInput is the argument of the restore tool.
type RestoreInput struct {
	SessionID  string `json:"session_id" jsonschema:"session id returned by start"`
	SnapshotID string `json:"snapshot_id" jsonschema:"snapshot id returned by snapshot"`
}

// ReportInput is the argument of the report tool.
type ReportInput struct {
	ReceiptPath string `json:"receipt_path" jsonschema:"path of a receipt file returned by run"`
}

// RunOutput is the structured result of the run tool.
type RunOutput struct {
	RunResult
	SessionID string `json:"session_id,omitempty"`
	Ephemeral bool   `json:"ephemeral"`
}

// SnapshotOutput is the structured result of the snapshot tool.
type SnapshotOutput struct {
	SnapshotID string `json:"snapshot_id"`
}

// ReportOutput is the structured result of the report tool.
type ReportOutput struct {
	Summary string `json:"summary"`
}

// OKOutput is the structured result of tools that only confirm an action.
type OKOutput struct {
	OK bool `json:"ok"`
}

func (h *handlers) start(ctx context.Context, _ *mcp.CallToolRequest, in StartInput) (*mcp.CallToolResult, Session, error) {
	sess, err := h.svc.Start(ctx, StartRequest(in))
	if err != nil {
		return toolError[Session](err)
	}
	text := fmt.Sprintf("Started session %s (backend %s, image %s).", sess.ID, sess.Backend, sess.ImageDigest)
	return textResult(text), sess, nil
}

func (h *handlers) run(ctx context.Context, _ *mcp.CallToolRequest, in RunInput) (*mcp.CallToolResult, RunOutput, error) {
	if err := validateArgv(in.Argv); err != nil {
		return toolError[RunOutput](err)
	}
	sessionID := in.SessionID
	ephemeral := sessionID == ""
	if ephemeral {
		id, err := h.startEphemeral(ctx, in)
		if err != nil {
			return toolError[RunOutput](err)
		}
		sessionID = id
		// Stop with a fresh context: if the caller cancelled the run, the
		// session still has to be torn down.
		defer func() { _ = h.svc.Stop(context.WithoutCancel(ctx), sessionID) }()
	}
	res, err := h.svc.Run(ctx, sessionID, in.Argv)
	if err != nil {
		return toolError[RunOutput](err)
	}
	out := RunOutput{RunResult: res, Ephemeral: ephemeral}
	if !ephemeral {
		out.SessionID = sessionID
	}
	return textResult(runText(out)), out, nil
}

func (h *handlers) startEphemeral(ctx context.Context, in RunInput) (string, error) {
	req := StartRequest{Backend: in.Backend, Image: in.Image}
	if req.Backend == "" {
		req.Backend = defaultBackend
	}
	if req.Image == "" {
		req.Image = defaultImage
	}
	sess, err := h.svc.Start(ctx, req)
	if err != nil {
		return "", fmt.Errorf("start ephemeral session: %w", err)
	}
	return sess.ID, nil
}

func (h *handlers) snapshot(ctx context.Context, _ *mcp.CallToolRequest, in SessionInput) (*mcp.CallToolResult, SnapshotOutput, error) {
	if err := requireID("session_id", in.SessionID); err != nil {
		return toolError[SnapshotOutput](err)
	}
	id, err := h.svc.Snapshot(ctx, in.SessionID)
	if err != nil {
		return toolError[SnapshotOutput](err)
	}
	return textResult("Snapshot " + id + " saved."), SnapshotOutput{SnapshotID: id}, nil
}

func (h *handlers) restore(ctx context.Context, _ *mcp.CallToolRequest, in RestoreInput) (*mcp.CallToolResult, OKOutput, error) {
	if err := errors.Join(requireID("session_id", in.SessionID), requireID("snapshot_id", in.SnapshotID)); err != nil {
		return toolError[OKOutput](err)
	}
	if err := h.svc.Restore(ctx, in.SessionID, in.SnapshotID); err != nil {
		return toolError[OKOutput](err)
	}
	return textResult("Restored snapshot " + in.SnapshotID + "."), OKOutput{OK: true}, nil
}

func (h *handlers) stop(ctx context.Context, _ *mcp.CallToolRequest, in SessionInput) (*mcp.CallToolResult, OKOutput, error) {
	if err := requireID("session_id", in.SessionID); err != nil {
		return toolError[OKOutput](err)
	}
	if err := h.svc.Stop(ctx, in.SessionID); err != nil {
		return toolError[OKOutput](err)
	}
	return textResult("Stopped session " + in.SessionID + "."), OKOutput{OK: true}, nil
}

func (h *handlers) report(ctx context.Context, _ *mcp.CallToolRequest, in ReportInput) (*mcp.CallToolResult, ReportOutput, error) {
	if err := requireID("receipt_path", in.ReceiptPath); err != nil {
		return toolError[ReportOutput](err)
	}
	summary, err := h.svc.Report(ctx, in.ReceiptPath)
	if err != nil {
		return toolError[ReportOutput](err)
	}
	return textResult(summary), ReportOutput{Summary: summary}, nil
}

func validateArgv(argv []string) error {
	switch {
	case len(argv) == 0:
		return errors.New("argv must not be empty")
	case len(argv) > maxArgv:
		return fmt.Errorf("argv has %d entries, the limit is %d", len(argv), maxArgv)
	case argv[0] == "":
		return errors.New("argv[0] must not be empty")
	}
	return nil
}

func requireID(field, v string) error {
	if strings.TrimSpace(v) == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	return nil
}

func runText(out RunOutput) string {
	var b strings.Builder
	if out.Ephemeral {
		b.WriteString("Ran in a throwaway session (started and stopped for this call).\n")
	}
	fmt.Fprintf(&b, "exit code %d in %d ms", out.ExitCode, out.DurationMS)
	if out.Killed != "" {
		fmt.Fprintf(&b, ", killed: %s", out.Killed)
	}
	b.WriteString("\n")
	if out.Summary != "" {
		b.WriteString(out.Summary + "\n")
	}
	if out.ReceiptPath != "" {
		b.WriteString("receipt: " + out.ReceiptPath + "\n")
	}
	appendStream(&b, "stdout", out.Stdout, out.StdoutTruncated)
	appendStream(&b, "stderr", out.Stderr, out.StderrTruncated)
	return b.String()
}

func appendStream(b *strings.Builder, name, s string, truncated bool) {
	if s == "" {
		return
	}
	fmt.Fprintf(b, "--- %s", name)
	if truncated {
		b.WriteString(" (truncated)")
	}
	b.WriteString(" ---\n" + s)
	if !strings.HasSuffix(s, "\n") {
		b.WriteString("\n")
	}
}

// textResult builds a result holding only text, capped at maxTextBytes. The
// structured content is filled in by the SDK from the typed output.
func textResult(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: capText(s)}}}
}

// capText cuts s to maxTextBytes without splitting a UTF-8 sequence.
func capText(s string) string {
	if len(s) <= maxTextBytes {
		return s
	}
	const note = "\n[text truncated at 32 KiB; the full value is in the structured content]"
	cut := maxTextBytes - len(note)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + note
}

// toolError turns err into a tool error result, so the agent sees the message
// instead of a protocol failure.
func toolError[Out any](err error) (*mcp.CallToolResult, Out, error) {
	var zero Out
	res := &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: capText(err.Error())}},
	}
	return res, zero, nil
}
