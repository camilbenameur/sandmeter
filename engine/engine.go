// Package engine ties the pieces together: it pulls the image, validates the
// policy against the backend, starts a sandbox, runs commands, computes the
// diff of the writable layer from the host side, and writes a signed receipt
// for every command.
package engine

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/camilbenameur/sandmeter/image"
	"github.com/camilbenameur/sandmeter/policy"
	"github.com/camilbenameur/sandmeter/receipt"
	"github.com/camilbenameur/sandmeter/sandbox"
)

// DiffLimit caps the number of entries in a receipt diff.
const DiffLimit = 100000

// Engine runs sandboxes and signs receipts. Fields must be set before use.
type Engine struct {
	Store      *image.Store
	Backends   map[string]sandbox.Backend
	Key        ed25519.PrivateKey
	ReceiptDir string
	Version    string

	mu       sync.Mutex
	sessions map[string]*Session
}

// Versioner is implemented by backends that wrap an external runtime.
type Versioner interface{ Version() string }

// BackendNames returns the configured backends, sorted.
func (e *Engine) BackendNames() []string {
	names := make([]string, 0, len(e.Backends))
	for n := range e.Backends {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Backend returns a configured backend by name.
func (e *Engine) Backend(name string) (sandbox.Backend, error) {
	b, ok := e.Backends[name]
	if !ok {
		return nil, fmt.Errorf("unknown backend %q (have %s)", name, strings.Join(e.BackendNames(), ", "))
	}
	return b, nil
}

// Session is one started sandbox.
type Session struct {
	ID      string
	Backend string
	Image   image.Image
	Policy  policy.Policy
	Caps    sandbox.Capabilities

	e     *Engine
	sb    sandbox.Sandbox
	mu    sync.Mutex
	count int
}

// StartOption adjusts a session before it starts.
type StartOption func(*sandbox.Spec)

// WithExtraLayer stacks a read-only directory on top of the image layers.
// The escape suite uses it to add its probe binary and scripts without
// touching the image or the writable layer.
func WithExtraLayer(dir string) StartOption {
	return func(s *sandbox.Spec) { s.Layers = append(s.Layers, dir) }
}

// WithEnv appends environment variables for every command of the session.
func WithEnv(env ...string) StartOption {
	return func(s *sandbox.Spec) { s.Env = append(s.Env, env...) }
}

// Start validates the policy against the backend, pulls the image if needed,
// and starts a sandbox.
func (e *Engine) Start(ctx context.Context, backend, imageRef string, p policy.Policy, opts ...StartOption) (*Session, error) {
	b, err := e.Backend(backend)
	if err != nil {
		return nil, err
	}
	caps := b.Capabilities()
	spec, err := p.Validate(caps)
	if err != nil {
		return nil, fmt.Errorf("policy refused by backend %q:\n%w", backend, err)
	}
	img, err := e.Store.Load(imageRef)
	if err != nil {
		img, err = e.Store.Pull(ctx, imageRef)
		if err != nil {
			return nil, err
		}
	}
	spec.Layers = img.Layers
	spec.Env = imageEnv(img.Config.Env)
	spec.Workdir = img.Config.WorkingDir
	for _, o := range opts {
		o(&spec)
	}
	sb, err := b.Start(ctx, spec)
	if err != nil {
		return nil, err
	}
	s := &Session{ID: sb.ID(), Backend: backend, Image: img, Policy: p, Caps: caps, e: e, sb: sb}
	e.mu.Lock()
	if e.sessions == nil {
		e.sessions = map[string]*Session{}
	}
	e.sessions[s.ID] = s
	e.mu.Unlock()
	return s, nil
}

// Session returns a started session by ID.
func (e *Engine) Session(id string) (*Session, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	s, ok := e.sessions[id]
	if !ok {
		return nil, fmt.Errorf("unknown session %q", id)
	}
	return s, nil
}

// StopAll stops every session; used on shutdown.
func (e *Engine) StopAll(ctx context.Context) error {
	e.mu.Lock()
	ss := make([]*Session, 0, len(e.sessions))
	for _, s := range e.sessions {
		ss = append(ss, s)
	}
	e.mu.Unlock()
	var errs []error
	for _, s := range ss {
		errs = append(errs, s.Stop(ctx))
	}
	return errors.Join(errs...)
}

func imageEnv(env []string) []string {
	for _, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			return env
		}
	}
	return append([]string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}, env...)
}

// Output is the outcome of one Run.
type Output struct {
	Result      sandbox.Result
	Receipt     receipt.Receipt
	Envelope    []byte
	ReceiptPath string
}

// Run executes argv and writes a signed receipt.
func (s *Session) Run(ctx context.Context, argv []string) (Output, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count++
	started := time.Now().UTC()
	res, err := s.sb.Exec(ctx, argv)
	finished := time.Now().UTC()
	if err != nil {
		return Output{Result: res}, err
	}
	rec, err := s.receipt(argv, res, started, finished)
	if err != nil {
		return Output{Result: res}, err
	}
	env, err := receipt.Sign(rec, s.e.Key)
	if err != nil {
		return Output{Result: res}, err
	}
	out := Output{Result: res, Receipt: rec, Envelope: env}
	if s.e.ReceiptDir != "" {
		if err := os.MkdirAll(s.e.ReceiptDir, 0o755); err != nil {
			return out, err
		}
		out.ReceiptPath = filepath.Join(s.e.ReceiptDir, fmt.Sprintf("%s-%d.json", s.ID, s.count))
		if err := os.WriteFile(out.ReceiptPath, env, 0o644); err != nil {
			return out, err
		}
	}
	return out, nil
}

func (s *Session) receipt(argv []string, res sandbox.Result, started, finished time.Time) (receipt.Receipt, error) {
	pol, err := json.Marshal(s.Policy)
	if err != nil {
		return receipt.Receipt{}, err
	}
	var diff receipt.Diff
	if l, ok := s.sb.(sandbox.Layered); ok {
		upper, lowers := l.Layers()
		diff, err = receipt.DiffUpper(upper, lowers, DiffLimit)
		if err != nil {
			return receipt.Receipt{}, fmt.Errorf("diff: %w", err)
		}
	}
	id, err := randomID()
	if err != nil {
		return receipt.Receipt{}, err
	}
	backendVersion := ""
	if v, ok := s.e.Backends[s.Backend].(Versioner); ok {
		backendVersion = v.Version()
	}
	conns := res.Connections
	if conns == nil {
		conns = []sandbox.Connection{}
	}
	return receipt.Receipt{
		Schema:          receipt.SchemaV1,
		ID:              id,
		Backend:         s.Backend,
		Capabilities:    s.Caps,
		PolicySHA256:    s.Policy.Hash(),
		Policy:          pol,
		Image:           receipt.ImageRef{Ref: s.Image.Ref, Digest: s.Image.Digest},
		Argv:            argv,
		ExitCode:        res.ExitCode,
		Killed:          res.Killed,
		StartedAt:       started,
		FinishedAt:      finished,
		DurationMS:      res.Duration.Milliseconds(),
		StdoutSHA256:    sha(res.Stdout),
		StderrSHA256:    sha(res.Stderr),
		StdoutTruncated: res.StdoutTruncated,
		StderrTruncated: res.StderrTruncated,
		Diff:            diff,
		Connections:     conns,
		Cgroup:          res.Stats,
		Host: receipt.Host{
			Kernel:           kernel(),
			Arch:             runtime.GOARCH,
			SandmeterVersion: s.e.Version,
			BackendVersion:   backendVersion,
		},
	}, nil
}

// Sandbox returns the backend sandbox, for backend-specific measurements.
func (s *Session) Sandbox() sandbox.Sandbox { return s.sb }

// Snapshot freezes the writable layer.
func (s *Session) Snapshot(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, err := s.sb.Snapshot(ctx)
	return string(id), err
}

// Restore resets the writable layer.
func (s *Session) Restore(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sb.Restore(ctx, sandbox.SnapshotID(id))
}

// Stop releases the sandbox.
func (s *Session) Stop(ctx context.Context) error {
	s.e.mu.Lock()
	delete(s.e.sessions, s.ID)
	s.e.mu.Unlock()
	return s.sb.Stop(ctx)
}

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func kernel() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "unknown"
	}
	return unix.ByteSliceToString(u.Sysname[:]) + " " + unix.ByteSliceToString(u.Release[:])
}
