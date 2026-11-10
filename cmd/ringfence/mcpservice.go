package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/camilbenameur/ringfence/engine"
	"github.com/camilbenameur/ringfence/mcpserver"
	"github.com/camilbenameur/ringfence/policy"
	"github.com/camilbenameur/ringfence/receipt"
)

// mcpService adapts the engine to the MCP server.
type mcpService struct{ e *engine.Engine }

const (
	defaultBackend = "native"
	defaultImage   = "docker.io/library/alpine:3.20"
	// mcpOutputLimit caps what is returned to the agent per stream.
	mcpOutputLimit = 64 << 10
)

func (m *mcpService) Start(ctx context.Context, req mcpserver.StartRequest) (mcpserver.Session, error) {
	backend, img := req.Backend, req.Image
	if backend == "" {
		backend = defaultBackend
	}
	if img == "" {
		img = defaultImage
	}
	p := policy.Default()
	if strings.TrimSpace(req.PolicyTOML) != "" {
		var err error
		if p, err = policy.Parse([]byte(req.PolicyTOML)); err != nil {
			return mcpserver.Session{}, err
		}
	}
	s, err := m.e.Start(ctx, backend, img, p)
	if err != nil {
		return mcpserver.Session{}, err
	}
	return mcpserver.Session{ID: s.ID, Backend: s.Backend, ImageDigest: s.Image.Digest, Capabilities: s.Caps}, nil
}

func (m *mcpService) Run(ctx context.Context, id string, argv []string) (mcpserver.RunResult, error) {
	s, err := m.e.Session(id)
	if err != nil {
		return mcpserver.RunResult{}, err
	}
	o, err := s.Run(ctx, argv)
	if err != nil {
		return mcpserver.RunResult{}, err
	}
	stdout, outCut := cut(o.Result.Stdout)
	stderr, errCut := cut(o.Result.Stderr)
	return mcpserver.RunResult{
		ExitCode:        o.Result.ExitCode,
		Killed:          o.Result.Killed,
		Stdout:          stdout,
		Stderr:          stderr,
		StdoutTruncated: o.Result.StdoutTruncated || outCut,
		StderrTruncated: o.Result.StderrTruncated || errCut,
		DurationMS:      o.Result.Duration.Milliseconds(),
		ReceiptPath:     o.ReceiptPath,
		Summary:         receipt.Summary(o.Receipt),
	}, nil
}

func cut(b []byte) (string, bool) {
	if len(b) > mcpOutputLimit {
		return string(b[:mcpOutputLimit]), true
	}
	return string(b), false
}

func (m *mcpService) Snapshot(ctx context.Context, id string) (string, error) {
	s, err := m.e.Session(id)
	if err != nil {
		return "", err
	}
	return s.Snapshot(ctx)
}

func (m *mcpService) Restore(ctx context.Context, id, snap string) error {
	s, err := m.e.Session(id)
	if err != nil {
		return err
	}
	return s.Restore(ctx, snap)
}

func (m *mcpService) Stop(ctx context.Context, id string) error {
	s, err := m.e.Session(id)
	if err != nil {
		return err
	}
	return s.Stop(ctx)
}

// Report verifies a receipt. Only files inside the receipt directory are
// read, so an agent cannot use the tool to read arbitrary host files.
func (m *mcpService) Report(ctx context.Context, path string) (string, error) {
	dir, err := filepath.Abs(m.e.ReceiptDir)
	if err != nil {
		return "", err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", err
	}
	defer root.Close()
	rel := path
	if filepath.IsAbs(path) {
		if rel, err = filepath.Rel(dir, path); err != nil || strings.HasPrefix(rel, "..") {
			return "", errors.New("report: receipt must be inside the receipt directory")
		}
	}
	f, err := root.Open(rel)
	if err != nil {
		return "", fmt.Errorf("report: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 16<<20 {
		return "", errors.New("report: not a receipt file")
	}
	data := make([]byte, st.Size())
	if _, err := io.ReadFull(f, data); err != nil {
		return "", err
	}
	pub, err := receipt.LoadPublicKey(keyPath() + ".pub")
	if err != nil {
		return "", err
	}
	r, err := receipt.Verify(data, pub)
	if err != nil {
		return "", fmt.Errorf("report: verify failed: %w", err)
	}
	return fmt.Sprintf("signature ok (key %s)\n%s", receipt.KeyID(pub), receipt.Summary(r)), nil
}
