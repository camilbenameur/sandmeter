package mcpserver

import (
	"context"

	"github.com/camilbenameur/sandmeter/sandbox"
)

// Service is everything the MCP server needs from the rest of sandmeter.
// Keeping it this small lets the server be tested with a fake and keeps the
// protocol layer free of sandbox details.
type Service interface {
	// Start creates a session and returns what the chosen backend enforces.
	Start(ctx context.Context, req StartRequest) (Session, error)
	// Run executes argv in an existing session.
	Run(ctx context.Context, sessionID string, argv []string) (RunResult, error)
	// Snapshot freezes the session filesystem and returns a snapshot id.
	Snapshot(ctx context.Context, sessionID string) (string, error)
	// Restore rolls the session filesystem back to a snapshot.
	Restore(ctx context.Context, sessionID, snapshotID string) error
	// Stop ends the session and releases its resources.
	Stop(ctx context.Context, sessionID string) error
	// Report verifies a signed receipt and returns a human-readable summary.
	Report(ctx context.Context, receiptPath string) (string, error)
}

// StartRequest asks for a new session. Empty fields mean "use the default".
type StartRequest struct {
	Backend    string
	Image      string
	PolicyTOML string
}

// Session describes a started session.
type Session struct {
	ID           string               `json:"id"`
	Backend      string               `json:"backend"`
	ImageDigest  string               `json:"image_digest"`
	Capabilities sandbox.Capabilities `json:"capabilities"`
}

// RunResult is the outcome of one command, with output already truncated by
// the service.
type RunResult struct {
	ExitCode        int    `json:"exit_code"`
	Killed          string `json:"killed,omitempty"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	StdoutTruncated bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated bool   `json:"stderr_truncated,omitempty"`
	DurationMS      int64  `json:"duration_ms"`
	ReceiptPath     string `json:"receipt_path,omitempty"`
	Summary         string `json:"summary,omitempty"`
}
