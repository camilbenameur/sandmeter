//go:build integration && linux

package engine

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/camilbenameur/ringfence/backend/gvisor"
	"github.com/camilbenameur/ringfence/backend/native"
	"github.com/camilbenameur/ringfence/image"
	"github.com/camilbenameur/ringfence/policy"
	"github.com/camilbenameur/ringfence/receipt"
	"github.com/camilbenameur/ringfence/sandbox"
)

// testImage is pinned by digest so runs are comparable.
var testImage = envOr("RINGFENCE_TEST_IMAGE", "docker.io/library/alpine:3.20")

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func TestMain(m *testing.M) {
	// The native backend re-executes this test binary as the sandbox init.
	if len(os.Args) > 1 && os.Args[1] == native.InitArg {
		native.Init()
	}
	os.Exit(m.Run())
}

func newTestEngine(t *testing.T) (*Engine, ed25519.PublicKey) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	home := envOr("RINGFENCE_TEST_HOME", "/var/lib/ringfence-test")
	state := t.TempDir()
	// The native init runs as the sandbox uid and must traverse the state
	// directory and its parents; t.TempDir makes them 0700.
	for d := state; d != os.TempDir() && d != "/"; d = filepath.Dir(d) {
		if err := os.Chmod(d, 0o711); err != nil {
			t.Fatal(err)
		}
	}
	bs := map[string]sandbox.Backend{
		"native": native.New(native.Options{StateDir: filepath.Join(state, "native")}),
	}
	if _, err := exec.LookPath("runsc"); err == nil {
		bs["gvisor"] = gvisor.New(gvisor.Options{StateDir: filepath.Join(state, "gvisor")})
	}
	return &Engine{
		Store:      &image.Store{Root: filepath.Join(home, "images"), IDShift: 100000},
		Backends:   bs,
		Key:        priv,
		ReceiptDir: t.TempDir(),
		Version:    "test",
	}, pub
}

func forEachBackend(t *testing.T, e *Engine, f func(t *testing.T, backend string)) {
	for _, name := range e.BackendNames() {
		t.Run(name, func(t *testing.T) { f(t, name) })
	}
}

func start(t *testing.T, e *Engine, backend string, p policy.Policy) *Session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	s, err := e.Start(ctx, backend, testImage, p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Stop(context.Background()) })
	return s
}

func runOK(t *testing.T, s *Session, argv ...string) Output {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	o, err := s.Run(ctx, argv)
	if err != nil {
		t.Fatalf("%v: %v", argv, err)
	}
	return o
}

func TestEchoAndReceipt(t *testing.T) {
	e, pub := newTestEngine(t)
	forEachBackend(t, e, func(t *testing.T, backend string) {
		s := start(t, e, backend, policy.Default())
		o := runOK(t, s, "sh", "-c", "echo hello; id -u; hostname; echo data > /workspace/out.txt")
		if o.Result.ExitCode != 0 {
			t.Fatalf("exit %d, stderr %s", o.Result.ExitCode, o.Result.Stderr)
		}
		lines := strings.Split(strings.TrimSpace(string(o.Result.Stdout)), "\n")
		if len(lines) != 3 || lines[0] != "hello" || lines[1] != "0" || lines[2] != "sandbox" {
			t.Fatalf("stdout %q", o.Result.Stdout)
		}
		data, err := os.ReadFile(o.ReceiptPath)
		if err != nil {
			t.Fatal(err)
		}
		rec, err := receipt.Verify(data, pub)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, en := range rec.Diff.Entries {
			if en.Path == "workspace/out.txt" || en.Path == "/workspace/out.txt" {
				found = en.Op == "add"
			}
		}
		if !found {
			t.Fatalf("diff does not show workspace/out.txt as added: %+v", rec.Diff.Entries)
		}
		if rec.Image.Digest == "" || rec.Backend != backend {
			t.Fatalf("receipt %+v", rec)
		}
	})
}

func TestReadOnlyRoot(t *testing.T) {
	e, _ := newTestEngine(t)
	forEachBackend(t, e, func(t *testing.T, backend string) {
		s := start(t, e, backend, policy.Default())
		o := runOK(t, s, "sh", "-c", "touch /etc/x 2>/dev/null && echo writable || echo readonly; touch /tmp/ok && echo tmp-ok")
		if got := strings.TrimSpace(string(o.Result.Stdout)); got != "readonly\ntmp-ok" {
			t.Fatalf("stdout %q stderr %q", got, o.Result.Stderr)
		}
	})
}

func TestSnapshotRestore(t *testing.T) {
	e, _ := newTestEngine(t)
	forEachBackend(t, e, func(t *testing.T, backend string) {
		s := start(t, e, backend, policy.Default())
		runOK(t, s, "sh", "-c", "echo one > /workspace/f")
		snap, err := s.Snapshot(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		runOK(t, s, "sh", "-c", "echo two > /workspace/f; rm -f /workspace/g")
		if err := s.Restore(context.Background(), snap); err != nil {
			t.Fatal(err)
		}
		o := runOK(t, s, "cat", "/workspace/f")
		if strings.TrimSpace(string(o.Result.Stdout)) != "one" {
			t.Fatalf("after restore: %q", o.Result.Stdout)
		}
		if err := s.Restore(context.Background(), "image"); err != nil {
			t.Fatal(err)
		}
		o = runOK(t, s, "sh", "-c", "test -e /workspace/f && echo present || echo absent")
		if strings.TrimSpace(string(o.Result.Stdout)) != "absent" {
			t.Fatalf("after restore to image: %q", o.Result.Stdout)
		}
	})
}

func TestLimits(t *testing.T) {
	e, _ := newTestEngine(t)
	forEachBackend(t, e, func(t *testing.T, backend string) {
		p := policy.Default()
		p.Limits.Wall = "2s"
		s := start(t, e, backend, p)
		o := runOK(t, s, "sleep", "30")
		if o.Result.Killed != "wall-timeout" {
			t.Fatalf("killed %q exit %d", o.Result.Killed, o.Result.ExitCode)
		}

		p = policy.Default()
		p.Limits.Memory = "64MiB"
		s = start(t, e, backend, p)
		// Grow a shell string until the cgroup OOM-kills the sandbox.
		o = runOK(t, s, "sh", "-c", `x=aaaaaaaaaaaaaaaa; while :; do x="$x$x"; done`)
		if o.Result.Killed != "oom" {
			t.Fatalf("memory hog: killed %q exit %d stats %+v", o.Result.Killed, o.Result.ExitCode, o.Result.Stats)
		}
		if o.Result.Stats.MemoryPeakBytes > 64<<20*105/100 {
			t.Fatalf("memory peak %d over the limit", o.Result.Stats.MemoryPeakBytes)
		}
	})
}

func TestNetworkNone(t *testing.T) {
	e, _ := newTestEngine(t)
	forEachBackend(t, e, func(t *testing.T, backend string) {
		s := start(t, e, backend, policy.Default())
		o := runOK(t, s, "sh", "-c", "ip -o link 2>/dev/null | wc -l; nc -w 2 1.1.1.1 80 </dev/null && echo connected || echo refused")
		if !strings.Contains(string(o.Result.Stdout), "refused") {
			t.Fatalf("stdout %q", o.Result.Stdout)
		}
	})
}

func TestNetworkAllowlist(t *testing.T) {
	if os.Getenv("RINGFENCE_NET_TESTS") == "" {
		t.Skip("set RINGFENCE_NET_TESTS=1 to test egress (needs internet and IP forwarding)")
	}
	e, _ := newTestEngine(t)
	forEachBackend(t, e, func(t *testing.T, backend string) {
		p := policy.Default()
		p.Network = policy.Network{Mode: "allowlist", Allow: []string{"1.1.1.1:80"}}
		s := start(t, e, backend, p)
		o := runOK(t, s, "sh", "-c",
			"nc -w 3 1.1.1.1 80 </dev/null && echo allowed-ok || echo allowed-fail; "+
				"nc -w 3 1.0.0.1 80 </dev/null && echo denied-open || echo denied-ok")
		out := string(o.Result.Stdout)
		if !strings.Contains(out, "allowed-ok") || !strings.Contains(out, "denied-ok") {
			t.Fatalf("stdout %q stderr %q", out, o.Result.Stderr)
		}
		var sawAllowed, sawDenied bool
		for _, c := range o.Result.Connections {
			if c.DstIP == "1.1.1.1" && c.Allowed {
				sawAllowed = true
			}
			if c.DstIP == "1.0.0.1" && !c.Allowed {
				sawDenied = true
			}
		}
		if !sawAllowed || !sawDenied {
			t.Fatalf("connection log %+v", o.Result.Connections)
		}
	})
}
