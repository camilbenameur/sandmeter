package engine

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/camilbenameur/sandmeter/internal/image"
	"github.com/camilbenameur/sandmeter/internal/prototype/policy"
	"github.com/camilbenameur/sandmeter/internal/prototype/sandbox"
	"github.com/camilbenameur/sandmeter/receipt"
)

// The files under receipt/testdata/v1 are recordings of what this engine
// emits for schema v1: Engine.Start and Session.Run produced them, with the
// policy validation, the diff walker, the hashing and the signing of the
// tree they were recorded from. The backend and the image are stand-ins,
// because real ones need root and a registry: the backend starts nothing,
// writes into the upper directory what the recorded command wrote, and
// returns the recorded result.
//
// Without the flag below, the test runs the same commands again and compares
// the signed bytes with the recordings, so the engine cannot drift away from
// v1 unnoticed while it still claims to emit it. With the flag it rewrites
// the recordings. That is never the way to make a test pass: a difference
// means the engine changed what it emits.
//
// The day the engine emits another schema, delete this file. The recordings
// stay: from then on no code in the tree can write a v1 receipt, and they
// are what the v1 decoder is held to.
var updateV1Fixtures = flag.Bool("update-v1-fixtures", false,
	"rewrite receipt/testdata/v1 from what the engine emits now")

// v1FixtureKey is the signing key of the recordings. Its seed is derived
// from a public label, so the key protects nothing: it only makes the
// signatures the same from one recording session to the next.
func v1FixtureKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("sandmeter receipt v1 fixture key"))
	return ed25519.NewKeyFromSeed(seed[:])
}

// v1Scenario is one recorded command.
type v1Scenario struct {
	name    string
	backend string
	// version is what the backend reports through Versioner; the native
	// backend reports nothing.
	version string
	caps    sandbox.Capabilities
	policy  policy.Policy
	argv    []string
	// writes puts into the upper directory what the command wrote through
	// the overlay.
	writes func(t *testing.T, upper string)
	result sandbox.Result
}

// The capabilities are the ones the two backends report as root on a cgroup
// v2 host.
func nativeCaps(notes ...string) sandbox.Capabilities {
	return sandbox.Capabilities{
		Backend: "native", Isolation: "linux-namespaces",
		CPULimit: true, MemoryLimit: true, PIDsLimit: true, WallTimeout: true,
		Networks:     []sandbox.NetworkMode{sandbox.NetworkNone, sandbox.NetworkAllowlist},
		ReadOnlyRoot: true, Seccomp: true, DropCaps: true, Snapshot: true,
		NeedsRoot: true,
		Notes:     notes,
	}
}

func gvisorCaps() sandbox.Capabilities {
	c := nativeCaps()
	c.Backend, c.Isolation = "gvisor", "user-space-kernel (gVisor systrap)"
	return c
}

func v1Scenarios() []v1Scenario {
	const userns = "kernel.apparmor_restrict_unprivileged_userns=1: rootless mode is unavailable on this host"
	return []v1Scenario{
		{
			// A command that succeeds, writes files of every kind the diff
			// knows and reaches the network under an allowlist.
			name:    "success",
			backend: "native",
			caps:    nativeCaps(),
			policy: policy.Policy{
				Limits:     policy.Limits{CPU: 2, PIDs: 512},
				Network:    policy.Network{Mode: "allowlist", Allow: []string{"192.0.2.10:443", "example.com:443"}},
				Filesystem: policy.Filesystem{ReadOnlyRoot: false},
				Syscalls:   policy.Syscalls{Filter: "default"},
			},
			argv: []string{"sh", "-c", "wget -q -O /workspace/page.html https://192.0.2.10/ && sh /workspace/install.sh"},
			writes: func(t *testing.T, upper string) {
				w := tree{t, upper}
				w.file("workspace/page.html", "<!doctype html>\n<title>Example Domain</title>\n", 0o644)
				w.file("etc/motd", "Welcome!\ninstalled by install.sh\n", 0o644)
				w.dir("opt", 0o755)
				w.dir("opt/tool", 0o755)
				w.file("opt/tool/run.sh", "#!/bin/sh\nexec /usr/local/bin/helper \"$@\"\n", 0o755)
				w.symlink("opt/tool/current", "run.sh")
				w.file("usr/local/bin/helper", "\x7fELF stand-in\n", 0o755|os.ModeSetuid)
				// rm -rf then mkdir: overlayfs marks the new directory opaque.
				w.dir("var/cache/apk", 0o755)
				w.opaque("var/cache/apk")
				w.file("var/cache/apk/index.new", "index\n", 0o644)
				// A name and a link target that are not valid UTF-8.
				w.file("tmp/caf\xe9.txt", "latin-1 name\n", 0o600)
				w.symlink("tmp/latin1", "caf\xe9.txt")
				w.fifo("tmp/pipe", 0o644)
			},
			result: sandbox.Result{
				ExitCode: 0,
				Stdout:   []byte("installed helper\n"),
				Duration: 412 * time.Millisecond,
				Stats:    sandbox.CgroupStats{MemoryPeakBytes: 9764864, CPUUsageUsec: 183402, PIDsPeak: 4},
				// Sorted the way the firewall log is: by address, then protocol.
				Connections: []sandbox.Connection{
					{Proto: "tcp", DstIP: "192.0.2.10", DstPort: 443, Allowed: true},
					{Proto: "udp", DstIP: "198.51.100.53", DstPort: 53},
					{Proto: "tcp", DstIP: "198.51.100.7", DstPort: 80},
					{Proto: "icmp", DstIP: "203.0.113.1"},
				},
			},
		},
		{
			// A command that fails against the process limit of the default
			// policy and changes nothing.
			name:    "failed",
			backend: "native",
			caps:    nativeCaps(userns),
			policy:  policy.Default(),
			argv:    []string{"sh", "-c", "for i in $(seq 1 400); do sleep 2 & done; wait"},
			writes:  func(*testing.T, string) {},
			result: sandbox.Result{
				ExitCode: 2,
				Stderr:   []byte("sh: can't fork: Resource temporarily unavailable\n"),
				Duration: 187 * time.Millisecond,
				Stats:    sandbox.CgroupStats{MemoryPeakBytes: 6037504, CPUUsageUsec: 152811, PIDsPeak: 256, PIDsMaxHits: 3},
			},
		},
		{
			// A command killed by the wall-time limit on the other backend,
			// with more output than is kept and a file over the hashing
			// budget.
			name:    "killed",
			backend: "gvisor",
			version: "runsc version release-20261019.0",
			caps:    gvisorCaps(),
			policy: policy.Policy{
				Limits:     policy.Limits{Memory: "64MiB", Wall: "2s"},
				Network:    policy.Network{Mode: "none"},
				Filesystem: policy.Filesystem{ReadOnlyRoot: true},
				Syscalls:   policy.Syscalls{Filter: "off"},
			},
			argv: []string{"sh", "-c", "echo started > /tmp/state; truncate -s 2G /tmp/big.img; while :; do echo spinning; done"},
			writes: func(t *testing.T, upper string) {
				w := tree{t, upper}
				w.file("tmp/state", "started\n", 0o644)
				w.sparse("tmp/big.img", 2<<30, 0o644)
			},
			result: sandbox.Result{
				ExitCode:        128 + int(syscall.SIGKILL),
				Killed:          "wall-timeout",
				Stdout:          bytes.Repeat([]byte("spinning\n"), 1<<20/9+1)[:1<<20],
				StdoutTruncated: true,
				Duration:        2004 * time.Millisecond,
				Stats:           sandbox.CgroupStats{MemoryPeakBytes: 46837760, CPUUsageUsec: 1974212, PIDsPeak: 41},
			},
		},
		{
			// A command killed by the memory limit.
			name:    "oom",
			backend: "native",
			caps:    nativeCaps(),
			policy: policy.Policy{
				Limits:     policy.Limits{Memory: "64MiB"},
				Network:    policy.Network{Mode: "none"},
				Filesystem: policy.Filesystem{ReadOnlyRoot: true},
				Syscalls:   policy.Syscalls{Filter: "default"},
			},
			argv:   []string{"sh", "-c", `x=aaaaaaaaaaaaaaaa; while :; do x="$x$x"; done`},
			writes: func(*testing.T, string) {},
			result: sandbox.Result{
				ExitCode: 128 + int(syscall.SIGKILL),
				Killed:   "oom",
				Duration: 311 * time.Millisecond,
				Stats:    sandbox.CgroupStats{MemoryPeakBytes: 67108864, OOMKills: 1, CPUUsageUsec: 286402, PIDsPeak: 2},
			},
		},
	}
}

// tree writes files with exact modes, whatever the umask is: the modes are
// part of the signed diff.
type tree struct {
	t    *testing.T
	root string
}

func (w tree) path(rel string) string {
	w.t.Helper()
	p := filepath.Join(w.root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		w.t.Fatal(err)
	}
	return p
}

func (w tree) check(err error) {
	w.t.Helper()
	if err != nil {
		w.t.Fatal(err)
	}
}

func (w tree) dir(rel string, mode os.FileMode) {
	w.t.Helper()
	p := w.path(rel)
	if err := os.Mkdir(p, 0o755); err != nil && !os.IsExist(err) {
		w.t.Fatal(err)
	}
	w.check(os.Chmod(p, mode))
}

func (w tree) file(rel, content string, mode os.FileMode) {
	w.t.Helper()
	p := w.path(rel)
	w.check(os.WriteFile(p, []byte(content), 0o600))
	w.check(os.Chmod(p, mode))
}

func (w tree) symlink(rel, target string) {
	w.t.Helper()
	w.check(os.Symlink(target, w.path(rel)))
}

func (w tree) fifo(rel string, mode os.FileMode) {
	w.t.Helper()
	p := w.path(rel)
	w.check(syscall.Mkfifo(p, 0o600))
	w.check(os.Chmod(p, mode))
}

// sparse makes a file of the given length that takes no room on disk.
func (w tree) sparse(rel string, size int64, mode os.FileMode) {
	w.t.Helper()
	p := w.path(rel)
	w.check(os.WriteFile(p, nil, 0o600))
	w.check(os.Truncate(p, size))
	w.check(os.Chmod(p, mode))
}

// opaque marks a directory the way overlayfs does for a mount made from a
// user namespace. The trusted.* form needs root; the diff reads both.
func (w tree) opaque(rel string) {
	w.t.Helper()
	if err := unix.Setxattr(filepath.Join(w.root, rel), "user.overlay.opaque", []byte("y"), 0); err != nil {
		if *updateV1Fixtures {
			w.t.Fatalf("user xattrs are needed to record the fixtures: %v", err)
		}
		w.t.Skipf("user xattrs unsupported in %s: %v", w.root, err)
	}
}

// standIn takes the place of a backend. It starts nothing.
type standIn struct {
	t    *testing.T
	sc   v1Scenario
	root string
	// lowers are the image layers the engine passed in the spec, kept to
	// check that the stand-in diffed against what the engine loaded.
	lowers []string
}

func (b *standIn) Capabilities() sandbox.Capabilities { return b.sc.caps }

// Version makes the stand-in a Versioner. An empty answer is recorded like
// a backend that is not one.
func (b *standIn) Version() string { return b.sc.version }

func (b *standIn) Start(_ context.Context, spec sandbox.Spec) (sandbox.Sandbox, error) {
	// The same stack as internal/layers builds: an upper directory over a
	// base layer of mount points over the image layers, top layer first.
	base := filepath.Join(b.root, "base")
	w := tree{b.t, base}
	for _, d := range []string{"dev", "proc", "sys", "workspace", "etc"} {
		w.dir(d, 0o755)
	}
	w.dir("tmp", 0o777|os.ModeSticky)
	w.file("etc/hosts", "127.0.0.1 localhost\n::1 localhost\n", 0o644)
	w.file("etc/hostname", "sandbox\n", 0o644)
	w.file("etc/resolv.conf", "", 0o644)

	lowers := []string{base}
	for i := len(spec.Layers) - 1; i >= 0; i-- {
		lowers = append(lowers, spec.Layers[i])
	}
	b.lowers = spec.Layers
	upper := filepath.Join(b.root, "upper")
	if err := os.Mkdir(upper, 0o755); err != nil {
		return nil, err
	}
	return &standInSandbox{b: b, upper: upper, lowers: lowers}, nil
}

type standInSandbox struct {
	b      *standIn
	upper  string
	lowers []string
}

func (s *standInSandbox) ID() string { return "000000000001" }

func (s *standInSandbox) Exec(_ context.Context, argv []string) (sandbox.Result, error) {
	sc := s.b.sc
	if !slices.Equal(argv, sc.argv) {
		return sandbox.Result{}, fmt.Errorf("stand-in got argv %q, recorded %q", argv, sc.argv)
	}
	sc.writes(s.b.t, s.upper)
	if *updateV1Fixtures {
		// A recording keeps the wall-clock times the engine took around
		// Exec: make them agree with the recorded duration.
		time.Sleep(sc.result.Duration)
	}
	return sc.result, nil
}

func (s *standInSandbox) Snapshot(context.Context) (sandbox.SnapshotID, error) {
	return "", sandbox.ErrNotImplemented
}

func (s *standInSandbox) Restore(context.Context, sandbox.SnapshotID) error {
	return sandbox.ErrNotImplemented
}

func (s *standInSandbox) Stop(context.Context) error { return nil }

func (s *standInSandbox) Layers() (string, []string) { return s.upper, s.lowers }

func (s *standInSandbox) DiffBase() string { return "image" }

// v1FixtureImage is the image of the recordings: a directory tree, not a
// registry pull, under a name that cannot resolve.
const v1FixtureImage = "registry.example/sandmeter/v1-fixture:1"

// newFixtureStore lays out an image store that already holds
// v1FixtureImage, the way image.Store.Pull leaves it.
func newFixtureStore(t *testing.T, root string) *image.Store {
	t.Helper()
	sum := sha256.Sum256([]byte("sandmeter v1 fixture image layer"))
	layer := filepath.Join(root, "layers", "sha256", hex.EncodeToString(sum[:]))
	w := tree{t, layer}
	w.file("bin/sh", "#!stand-in\n", 0o755)
	w.file("etc/motd", "Welcome!\n", 0o644)
	w.file("etc/os-release", "ID=fixture\nVERSION_ID=1\n", 0o644)
	w.file("etc/passwd", "root:x:0:0:root:/root:/bin/sh\n", 0o644)
	w.dir("root", 0o700)
	w.dir("usr/local/bin", 0o755)
	w.file("var/cache/apk/APKINDEX.00000000.tar.gz", "stale index\n", 0o644)
	w.symlink("var/run", "/run")
	w.check(os.WriteFile(layer+".complete", []byte(`{"id_shift":0,"overlay_whiteouts":false}`), 0o644))

	sum = sha256.Sum256([]byte("sandmeter v1 fixture image"))
	digest := hex.EncodeToString(sum[:])
	meta, err := json.Marshal(image.Image{
		Ref:      v1FixtureImage,
		Digest:   "sha256:" + digest,
		Platform: "linux/" + runtime.GOARCH,
		Layers:   []string{layer},
		Config:   image.Config{Env: []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}},
	})
	w.check(err)
	w.check(os.MkdirAll(filepath.Join(root, "images"), 0o755))
	w.check(os.WriteFile(filepath.Join(root, "images", digest+".json"), meta, 0o644))
	refs, err := json.Marshal(map[string]string{v1FixtureImage: "sha256:" + digest})
	w.check(err)
	w.check(os.WriteFile(filepath.Join(root, "refs.json"), refs, 0o644))
	return &image.Store{Root: root}
}

// volatile blanks the receipt fields that differ from one run or one host
// to the next, in the signed bytes themselves, so that everything else is
// still compared byte for byte, order included.
func volatile(t *testing.T, payload []byte) []byte {
	t.Helper()
	var v struct {
		ID         string `json:"id"`
		StartedAt  string `json:"started_at"`
		FinishedAt string `json:"finished_at"`
		Host       struct {
			Kernel string `json:"kernel"`
			Arch   string `json:"arch"`
		} `json:"host"`
	}
	if err := json.Unmarshal(payload, &v); err != nil {
		t.Fatalf("payload is not JSON: %v\n%s", err, payload)
	}
	for _, f := range []struct{ key, val string }{
		{"id", v.ID}, {"started_at", v.StartedAt}, {"finished_at", v.FinishedAt},
		{"kernel", v.Host.Kernel}, {"arch", v.Host.Arch},
	} {
		quoted, err := json.Marshal(f.val)
		if err != nil {
			t.Fatal(err)
		}
		old := []byte(`"` + f.key + `":` + string(quoted))
		if n := bytes.Count(payload, old); n != 1 {
			t.Fatalf("%s appears %d times in the payload, want once:\n%s", old, n, payload)
		}
		payload = bytes.Replace(payload, old, []byte(`"`+f.key+`":"*"`), 1)
	}
	return payload
}

func envelopePayload(t *testing.T, envelope []byte) []byte {
	t.Helper()
	var env receipt.Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return payload
}

func TestEngineEmitsTheRecordedV1Receipts(t *testing.T) {
	key := v1FixtureKey()
	pub := key.Public().(ed25519.PublicKey)

	if *updateV1Fixtures {
		if err := os.MkdirAll(v1FixtureDir, 0o755); err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatal(err)
		}
		writeFixture(t, "key.pub.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
		// The same key the way the builds that emit v1 store it next to the
		// private key (receipt.LoadPublicKey reads this form).
		writeFixture(t, "key.pub", []byte(base64.StdEncoding.EncodeToString(pub)+"\n"))
	}

	for _, sc := range v1Scenarios() {
		t.Run(sc.name, func(t *testing.T) {
			dir := t.TempDir()
			b := &standIn{t: t, sc: sc, root: filepath.Join(dir, "sandbox")}
			e := &Engine{
				Store:      newFixtureStore(t, filepath.Join(dir, "store")),
				Backends:   map[string]sandbox.Backend{sc.backend: b},
				Key:        key,
				ReceiptDir: filepath.Join(dir, "receipts"),
				// What a binary built without a version stamp reports, as
				// every build before the first release does.
				Version: "dev",
			}
			ctx := context.Background()
			s, err := e.Start(ctx, sc.backend, v1FixtureImage, sc.policy)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Stop(ctx)
			if len(b.lowers) != 1 {
				t.Fatalf("the engine passed layers %v, want the one layer of the fixture image", b.lowers)
			}
			out, err := s.Run(ctx, sc.argv)
			if err != nil {
				t.Fatal(err)
			}
			onDisk, err := os.ReadFile(out.ReceiptPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(onDisk, out.Envelope) {
				t.Fatal("the receipt file differs from the envelope Run returned")
			}
			if _, err := receipt.Verify(out.Envelope, pub); err != nil {
				t.Fatalf("the engine emitted a receipt that does not verify: %v", err)
			}
			payload := envelopePayload(t, out.Envelope)
			checkSignedV1(t, payload, sc.policy)

			if *updateV1Fixtures {
				writeFixture(t, sc.name+".json", out.Envelope)
				writeFixture(t, sc.name+".payload.json", payload)
				return
			}
			recorded, err := os.ReadFile(filepath.Join(v1FixtureDir, sc.name+".payload.json"))
			if err != nil {
				t.Fatal(err)
			}
			if got, want := volatile(t, payload), volatile(t, recorded); !bytes.Equal(got, want) {
				t.Errorf("the engine no longer emits the recorded v1 bytes (id, times, kernel and arch blanked).\n"+
					" now:      %s\n recorded: %s\n"+
					"If the engine is meant to emit another schema, delete this test; do not rewrite the recordings.", got, want)
			}
		})
	}
}

// checkSignedV1 holds what the engine signs to the frozen v1 form, read back
// with the frozen decoders only, in the places the recordings pin for four
// commands and nothing pins in general: the policy and the two hashes that
// are taken over other signed bytes.
func checkSignedV1(t *testing.T, payload []byte, ran policy.Policy) {
	t.Helper()
	signed, err := receipt.DecodeV1(payload)
	if err != nil {
		t.Fatalf("the engine signed something the v1 decoder refuses: %v", err)
	}

	// The policy is the one the command ran under, and its hash is the hash
	// of the policy bytes as signed.
	if got := receipt.PolicyHashV1(signed.Policy); got != signed.PolicySHA256 {
		t.Errorf("policy_sha256 is %s, the signed policy bytes hash to %s", signed.PolicySHA256, got)
	}
	p, err := receipt.DecodePolicyV1(signed.Policy)
	if err != nil {
		t.Fatalf("the engine signed a policy the v1 decoder refuses: %v\n%s", err, signed.Policy)
	}
	if got := policyFromV1(p); !reflect.DeepEqual(got, ran) {
		t.Errorf("the signed policy reads back as %+v, the command ran under %+v", got, ran)
	}
	// That hash is also the one "sandmeter check" prints for the policy
	// file. This holds for as long as policy.Policy encodes the way the v1
	// policy does; what the two commands tell the user has to be decided
	// again the day it does not.
	if signed.PolicySHA256 != ran.Hash() {
		t.Errorf("policy_sha256 is %s, the policy the command ran under hashes to %s", signed.PolicySHA256, ran.Hash())
	}

	// The diff hash is the hash of the entries as signed.
	entries, err := json.Marshal(signed.Diff.Entries)
	if err != nil {
		t.Fatal(err)
	}
	if got := sha(entries); got != signed.Diff.SHA256 {
		t.Errorf("diff.sha256 is %s, the signed entries hash to %s", signed.Diff.SHA256, got)
	}
}

func writeFixture(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(v1FixtureDir, name), data, 0o644); err != nil {
		t.Fatal(err)
	}
}
