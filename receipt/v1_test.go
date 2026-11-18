package receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/camilbenameur/sandmeter/internal/prototype/sandbox"
)

// The tests in this file hold schema v1 in place. They read the recordings
// in testdata/v1 (see the README there) and compare them with values written
// out below by hand. When one of them fails, the change under test altered a
// published format: fix the change, not the recording and not the value.

func readV1(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "v1", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// v1Key reads the public key of the recordings from its PKIX PEM file.
func v1Key(t *testing.T) ed25519.PublicKey {
	t.Helper()
	block, rest := pem.Decode(readV1(t, "key.pub.pem"))
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("key.pub.pem is not one PUBLIC KEY block")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("key.pub.pem holds a %T, want an Ed25519 key", k)
	}
	return pub
}

// v1Payload returns the signed bytes inside a recorded envelope.
func v1Payload(t *testing.T, envelope []byte) []byte {
	t.Helper()
	var env Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		t.Fatal(err)
	}
	body, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// v1Recording is one receipt under testdata/v1 and what it has to decode to.
type v1Recording struct {
	name string
	// payloadSHA256 pins the signed bytes from this side too: the files
	// under testdata cannot change without this file changing with them.
	payloadSHA256 string
	want          ReceiptV1
	policy        PolicyV1
}

const (
	// v1EmptySHA256 is the SHA-256 of no bytes: the sum of an empty stream.
	v1EmptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	// v1NoEntriesSHA256 is the SHA-256 of "[]": the sum of an empty diff.
	v1NoEntriesSHA256 = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
)

func v1Caps(backend, isolation string, notes ...string) CapabilitiesV1 {
	return CapabilitiesV1{
		Backend: backend, Isolation: isolation,
		CPULimit: true, MemoryLimit: true, PIDsLimit: true, WallTimeout: true,
		Networks:     []string{"none", "allowlist"},
		ReadOnlyRoot: true, Seccomp: true, DropCaps: true, Snapshot: true,
		NeedsRoot: true,
		Notes:     notes,
	}
}

func v1Recordings() []v1Recording {
	image := ImageRefV1{
		Ref:    "registry.example/sandmeter/v1-fixture:1",
		Digest: "sha256:ae7f611098db5308f0800ced11291df967370bfc718451e823fcb201555d5620",
	}
	at := func(hour, min, sec, nsec int) time.Time {
		return time.Date(2026, time.November, 18, hour, min, sec, nsec, time.UTC)
	}
	host := func(backendVersion string) HostV1 {
		return HostV1{Kernel: "Linux 6.8.0-149-generic", Arch: "amd64", SandmeterVersion: "dev", BackendVersion: backendVersion}
	}
	return []v1Recording{
		{
			name:          "success",
			payloadSHA256: "359f1ca5ca711427bbf937c9e01901b9d03fb64c4672689f60d9e12a1cc24d24",
			want: ReceiptV1{
				Schema:       "sandmeter.receipt/v1",
				ID:           "e4cd000c7318602d9f667052035d356d",
				Backend:      "native",
				Capabilities: v1Caps("native", "linux-namespaces"),
				PolicySHA256: "cbf3e070ac2facdaad6864ae59bb7494e904ff6af6ee5d36ca1898723d3a660d",
				Policy:       json.RawMessage(`{"limits":{"cpu":2,"pids":512},"network":{"mode":"allowlist","allow":["192.0.2.10:443","example.com:443"]},"filesystem":{"read_only_root":false},"syscalls":{"filter":"default"}}`),
				Image:        image,
				Argv:         []string{"sh", "-c", "wget -q -O /workspace/page.html https://192.0.2.10/ && sh /workspace/install.sh"},
				ExitCode:     0,
				StartedAt:    at(13, 50, 41, 497105907),
				FinishedAt:   at(13, 50, 41, 911731105),
				DurationMS:   412,
				StdoutSHA256: "d441c8ade7b6ed6e896de7a732080a23bb546f34efe4391226921a102777790f",
				StderrSHA256: v1EmptySHA256,
				Diff: DiffV1{
					SHA256: "37ba51efa82b894e20bc1e262f789ac9fa4c02ab8c247e850bd6f4e986f44a65",
					Entries: []EntryV1{
						{Path: `"tmp/caf\xe9.txt"`, Op: "add", Type: "file", Mode: 0o600, Size: 13, SHA256: "53f0d43c2e4fbc7ac8fa0f77bfc56eddd4554ce1d7fbc2cab0bf429c727c5971", PathEscaped: true},
						{Path: "etc/motd", Op: "modify", Type: "file", Mode: 0o644, Size: 33, SHA256: "471a804cfbc51448683f1def50a9bd9b6314d30e5205fc10ca1792b323b9eb17"},
						{Path: "opt", Op: "add", Type: "dir", Mode: 0o755},
						{Path: "opt/tool", Op: "add", Type: "dir", Mode: 0o755},
						{Path: "opt/tool/current", Op: "add", Type: "symlink", Mode: 0o777, Target: "run.sh"},
						{Path: "opt/tool/run.sh", Op: "add", Type: "file", Mode: 0o755, Size: 42, SHA256: "6b7f8807c790a9bf8c8309c5e65ae8a0b766df7a6deeab49d80b8e41bdd061d8"},
						{Path: "tmp/latin1", Op: "add", Type: "symlink", Mode: 0o777, Target: `"caf\xe9.txt"`, TargetEscaped: true},
						{Path: "tmp/pipe", Op: "add", Type: "other", Mode: 0o644},
						{Path: "usr/local/bin/helper", Op: "add", Type: "file", Mode: 0o4755, Size: 14, SHA256: "cb49ce442cc2436ff6be06e1debbd240652b1ea36bfa184972b9e8316fcda4ab"},
						{Path: "var/cache/apk", Op: "opaque", Type: "dir", Mode: 0o755},
						{Path: "var/cache/apk/index.new", Op: "add", Type: "file", Mode: 0o644, Size: 6, SHA256: "f816b480f87144ec4de5862adf028ff66cc6964250325d53fd22bf8922824b6f"},
						{Path: "workspace/page.html", Op: "add", Type: "file", Mode: 0o644, Size: 46, SHA256: "87023b612b5df5c3f1093904a21156fa19fd13ee9c64b6f6f25308707996d75b"},
					},
				},
				Connections: []ConnectionV1{
					{Proto: "tcp", DstIP: "192.0.2.10", DstPort: 443, Allowed: true},
					{Proto: "udp", DstIP: "198.51.100.53", DstPort: 53},
					{Proto: "tcp", DstIP: "198.51.100.7", DstPort: 80},
					{Proto: "icmp", DstIP: "203.0.113.1"},
				},
				Cgroup: CgroupStatsV1{MemoryPeakBytes: 9764864, CPUUsageUsec: 183402, PIDsPeak: 4},
				Host:   host(""),
			},
			policy: PolicyV1{
				Limits:   PolicyLimitsV1{CPU: 2, PIDs: 512},
				Network:  PolicyNetworkV1{Mode: "allowlist", Allow: []string{"192.0.2.10:443", "example.com:443"}},
				Syscalls: PolicySyscallsV1{Filter: "default"},
			},
		},
		{
			name:          "failed",
			payloadSHA256: "81f4c1716f0dd7def3c572872568c30c6c4d4b56626207a9e8134b57fdc365fb",
			want: ReceiptV1{
				Schema:       "sandmeter.receipt/v1",
				ID:           "f00b5fa0d8e79b857d10ad8652ca94fb",
				Backend:      "native",
				Capabilities: v1Caps("native", "linux-namespaces", "kernel.apparmor_restrict_unprivileged_userns=1: rootless mode is unavailable on this host"),
				PolicySHA256: "fe3d28bbc3927503709a88ad9177b45e3deefe003d00578062a383ae40320e7c",
				Policy:       json.RawMessage(`{"limits":{"cpu":1,"memory":"512MiB","pids":256,"wall":"60s"},"network":{"mode":"none"},"filesystem":{"read_only_root":true},"syscalls":{"filter":"default"}}`),
				Image:        image,
				Argv:         []string{"sh", "-c", "for i in $(seq 1 400); do sleep 2 & done; wait"},
				ExitCode:     2,
				StartedAt:    at(13, 50, 41, 932018665),
				FinishedAt:   at(13, 50, 42, 119384571),
				DurationMS:   187,
				StdoutSHA256: v1EmptySHA256,
				StderrSHA256: "dad66d6d507d75121ede00c812b9735cab87b3ba399850ae447ecaa1cbcb243b",
				Diff:         DiffV1{SHA256: v1NoEntriesSHA256, Entries: []EntryV1{}},
				Connections:  []ConnectionV1{},
				Cgroup:       CgroupStatsV1{MemoryPeakBytes: 6037504, CPUUsageUsec: 152811, PIDsPeak: 256, PIDsMaxHits: 3},
				Host:         host(""),
			},
			policy: PolicyV1{
				Limits:     PolicyLimitsV1{CPU: 1, Memory: "512MiB", PIDs: 256, Wall: "60s"},
				Network:    PolicyNetworkV1{Mode: "none"},
				Filesystem: PolicyFilesystemV1{ReadOnlyRoot: true},
				Syscalls:   PolicySyscallsV1{Filter: "default"},
			},
		},
		{
			name:          "killed",
			payloadSHA256: "ddcbb4e3d82f2774f02723559b6b95496b8700c7eae305ddde3ca3bba0c0209c",
			want: ReceiptV1{
				Schema:          "sandmeter.receipt/v1",
				ID:              "2b9cc7a5765896f8844c2e35e964e1a6",
				Backend:         "gvisor",
				Capabilities:    v1Caps("gvisor", "user-space-kernel (gVisor systrap)"),
				PolicySHA256:    "6b987cfd4affd6ba3592baea042d34535766625ac3a05333b8e25f4ef38ee729",
				Policy:          json.RawMessage(`{"limits":{"memory":"64MiB","wall":"2s"},"network":{"mode":"none"},"filesystem":{"read_only_root":true},"syscalls":{"filter":"off"}}`),
				Image:           image,
				Argv:            []string{"sh", "-c", "echo started > /tmp/state; truncate -s 2G /tmp/big.img; while :; do echo spinning; done"},
				ExitCode:        137,
				Killed:          "wall-timeout",
				StartedAt:       at(13, 50, 42, 128671583),
				FinishedAt:      at(13, 50, 44, 142532537),
				DurationMS:      2004,
				StdoutSHA256:    "3b2bf56ea94c7e0df7e80940d9df00138ceb08fa0c27547a4542f93d66874a80",
				StderrSHA256:    v1EmptySHA256,
				StdoutTruncated: true,
				Diff: DiffV1{
					SHA256:    "76370e7f9afe7413db2af63482ef78f83abca577ffb8fbed141f9f1cf4724871",
					Truncated: true,
					Entries: []EntryV1{
						{Path: "tmp/big.img", Op: "add", Type: "file", Mode: 0o644, Size: 2 << 30, Skipped: "too_large"},
						{Path: "tmp/state", Op: "add", Type: "file", Mode: 0o644, Size: 8, SHA256: "eff64b343dcb2b1dc113648e7089b9ce9f8a7f6c7808a03a2cffb4ad7302f606"},
					},
				},
				Connections: []ConnectionV1{},
				Cgroup:      CgroupStatsV1{MemoryPeakBytes: 46837760, CPUUsageUsec: 1974212, PIDsPeak: 41},
				Host:        host("runsc version release-20261019.0"),
			},
			policy: PolicyV1{
				Limits:     PolicyLimitsV1{Memory: "64MiB", Wall: "2s"},
				Network:    PolicyNetworkV1{Mode: "none"},
				Filesystem: PolicyFilesystemV1{ReadOnlyRoot: true},
				Syscalls:   PolicySyscallsV1{Filter: "off"},
			},
		},
		{
			name:          "oom",
			payloadSHA256: "fa8801cc789e9fa1083048d1ecedf2e3cc035f467e85dc673169171d62257968",
			want: ReceiptV1{
				Schema:       "sandmeter.receipt/v1",
				ID:           "4f6b8edb3a797a32c6b2371ae59e9f7a",
				Backend:      "native",
				Capabilities: v1Caps("native", "linux-namespaces"),
				PolicySHA256: "30365d6b50fbb9fcb622d431aaa45496d9d46ad445a32c6068598b0e491d4759",
				Policy:       json.RawMessage(`{"limits":{"memory":"64MiB"},"network":{"mode":"none"},"filesystem":{"read_only_root":true},"syscalls":{"filter":"default"}}`),
				Image:        image,
				Argv:         []string{"sh", "-c", `x=aaaaaaaaaaaaaaaa; while :; do x="$x$x"; done`},
				ExitCode:     137,
				Killed:       "oom",
				StartedAt:    at(13, 50, 44, 166679699),
				FinishedAt:   at(13, 50, 44, 478635143),
				DurationMS:   311,
				StdoutSHA256: v1EmptySHA256,
				StderrSHA256: v1EmptySHA256,
				Diff:         DiffV1{SHA256: v1NoEntriesSHA256, Entries: []EntryV1{}},
				Connections:  []ConnectionV1{},
				Cgroup:       CgroupStatsV1{MemoryPeakBytes: 67108864, OOMKills: 1, CPUUsageUsec: 286402, PIDsPeak: 2},
				Host:         host(""),
			},
			policy: PolicyV1{
				Limits:     PolicyLimitsV1{Memory: "64MiB"},
				Network:    PolicyNetworkV1{Mode: "none"},
				Filesystem: PolicyFilesystemV1{ReadOnlyRoot: true},
				Syscalls:   PolicySyscallsV1{Filter: "default"},
			},
		},
	}
}

// eachV1 runs f on every recording, with its envelope and its signed bytes.
func eachV1(t *testing.T, f func(t *testing.T, rec v1Recording, envelope, payload []byte)) {
	for _, rec := range v1Recordings() {
		t.Run(rec.name, func(t *testing.T) {
			envelope := readV1(t, rec.name+".json")
			f(t, rec, envelope, v1Payload(t, envelope))
		})
	}
}

func TestV1RecordingsVerify(t *testing.T) {
	pub := v1Key(t)
	eachV1(t, func(t *testing.T, rec v1Recording, envelope, _ []byte) {
		got, err := Verify(envelope, pub)
		if err != nil {
			t.Fatalf("a recorded v1 receipt no longer verifies: %v", err)
		}
		if got.Schema != SchemaV1 || got.ID != rec.want.ID {
			t.Errorf("Verify returned schema %q id %q, want %q and %q", got.Schema, got.ID, SchemaV1, rec.want.ID)
		}
	})
}

func TestV1SignedBytesArePinned(t *testing.T) {
	eachV1(t, func(t *testing.T, rec v1Recording, _, payload []byte) {
		if file := readV1(t, rec.name+".payload.json"); !bytes.Equal(payload, file) {
			t.Errorf("the payload of %s.json is not the content of %s.payload.json", rec.name, rec.name)
		}
		if got := hexSHA256(payload); got != rec.payloadSHA256 {
			t.Errorf("signed bytes changed: sha256 %s, pinned %s", got, rec.payloadSHA256)
		}
	})
}

func TestV1DecodesToTheRecordedValues(t *testing.T) {
	eachV1(t, func(t *testing.T, rec v1Recording, _, payload []byte) {
		got, err := DecodeV1(payload)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, rec.want) {
			t.Errorf("DecodeV1 changed what a recorded receipt holds:\n got  %+v\n want %+v", got, rec.want)
		}
	})
}

// TestV1EncodingIsFrozen is the other half of the decode test: the values
// written in this file encode to the signed bytes, so every field name, tag,
// omitempty and position of the v1 structs is pinned.
func TestV1EncodingIsFrozen(t *testing.T) {
	eachV1(t, func(t *testing.T, rec v1Recording, _, payload []byte) {
		got, err := json.Marshal(rec.want)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("the v1 structs no longer encode to the signed bytes:\n got  %s\n want %s", got, payload)
		}
	})
}

// v1Field is one field of a frozen struct: its Go name, its type the way
// v1.go writes it, and its whole struct tag.
type v1Field struct{ name, typ, tag string }

// v1Frozen is the declaration of every struct of schema v1, written out a
// second time. It is compared with what the compiler sees, and is not derived
// from any other type: neither from the structs in v1.go nor from the types
// the rest of the code works with.
var v1Frozen = []struct {
	typ    reflect.Type
	fields []v1Field
}{
	{reflect.TypeFor[ReceiptV1](), []v1Field{
		{"Schema", "string", `json:"schema"`},
		{"ID", "string", `json:"id"`},
		{"Backend", "string", `json:"backend"`},
		{"Capabilities", "CapabilitiesV1", `json:"capabilities"`},
		{"PolicySHA256", "string", `json:"policy_sha256"`},
		{"Policy", "json.RawMessage", `json:"policy"`},
		{"Image", "ImageRefV1", `json:"image"`},
		{"Argv", "[]string", `json:"argv"`},
		{"ExitCode", "int", `json:"exit_code"`},
		{"Killed", "string", `json:"killed"`},
		{"StartedAt", "time.Time", `json:"started_at"`},
		{"FinishedAt", "time.Time", `json:"finished_at"`},
		{"DurationMS", "int64", `json:"duration_ms"`},
		{"StdoutSHA256", "string", `json:"stdout_sha256"`},
		{"StderrSHA256", "string", `json:"stderr_sha256"`},
		{"StdoutTruncated", "bool", `json:"stdout_truncated"`},
		{"StderrTruncated", "bool", `json:"stderr_truncated"`},
		{"Diff", "DiffV1", `json:"diff"`},
		{"Connections", "[]ConnectionV1", `json:"connections"`},
		{"Cgroup", "CgroupStatsV1", `json:"cgroup"`},
		{"Host", "HostV1", `json:"host"`},
	}},
	{reflect.TypeFor[CapabilitiesV1](), []v1Field{
		{"Backend", "string", `json:"backend"`},
		{"Isolation", "string", `json:"isolation"`},
		{"CPULimit", "bool", `json:"cpu_limit"`},
		{"MemoryLimit", "bool", `json:"memory_limit"`},
		{"PIDsLimit", "bool", `json:"pids_limit"`},
		{"WallTimeout", "bool", `json:"wall_timeout"`},
		{"Networks", "[]string", `json:"networks"`},
		{"ReadOnlyRoot", "bool", `json:"read_only_root"`},
		{"Seccomp", "bool", `json:"seccomp"`},
		{"DropCaps", "bool", `json:"drop_capabilities"`},
		{"Snapshot", "bool", `json:"snapshot"`},
		{"NeedsRoot", "bool", `json:"needs_root"`},
		{"Notes", "[]string", `json:"notes,omitempty"`},
	}},
	{reflect.TypeFor[ImageRefV1](), []v1Field{
		{"Ref", "string", `json:"ref"`},
		{"Digest", "string", `json:"digest"`},
	}},
	{reflect.TypeFor[HostV1](), []v1Field{
		{"Kernel", "string", `json:"kernel"`},
		{"Arch", "string", `json:"arch"`},
		{"SandmeterVersion", "string", `json:"sandmeter_version"`},
		{"BackendVersion", "string", `json:"backend_version"`},
	}},
	{reflect.TypeFor[DiffV1](), []v1Field{
		{"SHA256", "string", `json:"sha256"`},
		{"Truncated", "bool", `json:"truncated"`},
		{"Entries", "[]EntryV1", `json:"entries"`},
	}},
	{reflect.TypeFor[EntryV1](), []v1Field{
		{"Path", "string", `json:"path"`},
		{"Op", "string", `json:"op"`},
		{"Type", "string", `json:"type"`},
		{"Mode", "uint32", `json:"mode"`},
		{"Size", "int64", `json:"size"`},
		{"SHA256", "string", `json:"sha256"`},
		{"Target", "string", `json:"target"`},
		{"PathEscaped", "bool", `json:"path_escaped,omitempty"`},
		{"TargetEscaped", "bool", `json:"target_escaped,omitempty"`},
		{"Skipped", "string", `json:"skipped,omitempty"`},
	}},
	{reflect.TypeFor[ConnectionV1](), []v1Field{
		{"Proto", "string", `json:"proto"`},
		{"DstIP", "string", `json:"dst_ip"`},
		{"DstPort", "uint16", `json:"dst_port,omitempty"`},
		{"Allowed", "bool", `json:"allowed"`},
	}},
	{reflect.TypeFor[CgroupStatsV1](), []v1Field{
		{"MemoryPeakBytes", "int64", `json:"memory_peak_bytes"`},
		{"OOMKills", "int64", `json:"oom_kills"`},
		{"CPUUsageUsec", "int64", `json:"cpu_usage_usec"`},
		{"PIDsPeak", "int64", `json:"pids_peak"`},
		{"PIDsMaxHits", "int64", `json:"pids_max_hits"`},
	}},
	{reflect.TypeFor[PolicyV1](), []v1Field{
		{"Limits", "PolicyLimitsV1", `json:"limits"`},
		{"Network", "PolicyNetworkV1", `json:"network"`},
		{"Filesystem", "PolicyFilesystemV1", `json:"filesystem"`},
		{"Syscalls", "PolicySyscallsV1", `json:"syscalls"`},
	}},
	{reflect.TypeFor[PolicyLimitsV1](), []v1Field{
		{"CPU", "float64", `json:"cpu,omitempty"`},
		{"Memory", "string", `json:"memory,omitempty"`},
		{"PIDs", "int64", `json:"pids,omitempty"`},
		{"Wall", "string", `json:"wall,omitempty"`},
	}},
	{reflect.TypeFor[PolicyNetworkV1](), []v1Field{
		{"Mode", "string", `json:"mode"`},
		{"Allow", "[]string", `json:"allow,omitempty"`},
	}},
	{reflect.TypeFor[PolicyFilesystemV1](), []v1Field{
		{"ReadOnlyRoot", "bool", `json:"read_only_root"`},
	}},
	{reflect.TypeFor[PolicySyscallsV1](), []v1Field{
		{"Filter", "string", `json:"filter"`},
	}},
}

// v1TypeName writes a field type the way v1.go declares it.
func v1TypeName(t reflect.Type) string {
	switch {
	case t == reflect.TypeFor[json.RawMessage]():
		// Told apart by identity: what reflection calls this type depends on
		// the toolchain.
		return "json.RawMessage"
	case t == reflect.TypeFor[time.Time]():
		return "time.Time"
	case t.Kind() == reflect.Slice && t.Name() == "":
		return "[]" + v1TypeName(t.Elem())
	case t.Name() != "" && t.PkgPath() == reflect.TypeFor[ReceiptV1]().PkgPath():
		return t.Name()
	default:
		// A predeclared type prints as its name. Anything else, such as a
		// type of another package, prints in full and matches nothing above.
		return t.String()
	}
}

// v1StructsIn adds to seen every struct of this package that a value of type
// t holds, t included.
func v1StructsIn(t reflect.Type, seen map[reflect.Type]bool) {
	switch t.Kind() {
	case reflect.Pointer, reflect.Slice, reflect.Array:
		v1StructsIn(t.Elem(), seen)
	case reflect.Map:
		v1StructsIn(t.Key(), seen)
		v1StructsIn(t.Elem(), seen)
	case reflect.Struct:
		if t.PkgPath() != reflect.TypeFor[ReceiptV1]().PkgPath() || seen[t] {
			return
		}
		seen[t] = true
		for i := range t.NumField() {
			v1StructsIn(t.Field(i).Type, seen)
		}
	}
}

// TestV1StructsAreFrozen holds every v1 struct to its declaration: the
// fields, their order, their types and their tags, and no method.
//
// The other tests cannot. A field added with omitempty encodes the recorded
// values to the same bytes and decodes the recorded payloads to the same
// values, so every one of them still passes, while DecodeV1 has started to
// accept a key that every reader of v1 released before refuses.
func TestV1StructsAreFrozen(t *testing.T) {
	pinned := map[reflect.Type]bool{}
	for _, frozen := range v1Frozen {
		name := frozen.typ.Name()
		if pinned[frozen.typ] {
			t.Errorf("%s is listed twice", name)
		}
		pinned[frozen.typ] = true
		if frozen.typ.Kind() != reflect.Struct {
			t.Errorf("%s is no longer a struct", name)
			continue
		}

		var now []v1Field
		for i := range frozen.typ.NumField() {
			f := frozen.typ.Field(i)
			field := v1Field{f.Name, v1TypeName(f.Type), string(f.Tag)}
			if f.Anonymous {
				field.name = "(embedded) " + f.Name
			}
			now = append(now, field)
		}
		if !slices.Equal(now, frozen.fields) {
			t.Errorf("%s is no longer the struct schema v1 was published with:\n%s"+
				"Put the struct back. A field that is new, gone, moved, renamed, retyped or re-tagged belongs to another schema.",
				name, v1Changes(now, frozen.fields))
		}

		// A method such as UnmarshalJSON takes the decoding of its struct
		// over, whatever the fields say, and no other test would notice one
		// that still reads the recordings. The frozen structs are plain data.
		ptr := reflect.PointerTo(frozen.typ)
		for i := range ptr.NumMethod() {
			t.Errorf("%s has a method, %s: a frozen struct is plain data, write a function instead", name, ptr.Method(i).Name)
		}
	}

	// As a check on the list itself: it names every struct a v1 receipt or
	// its policy is made of, and nothing else.
	reachable := map[reflect.Type]bool{}
	v1StructsIn(reflect.TypeFor[ReceiptV1](), reachable)
	v1StructsIn(reflect.TypeFor[PolicyV1](), reachable)
	for typ := range reachable {
		if !pinned[typ] {
			t.Errorf("%s is part of a v1 receipt and v1Frozen does not list it", typ.Name())
		}
	}
	for typ := range pinned {
		if !reachable[typ] {
			t.Errorf("v1Frozen lists %s, which is no part of a v1 receipt or of its policy", typ.Name())
		}
	}
}

func (f v1Field) String() string { return f.name + " " + f.typ + " `" + f.tag + "`" }

// v1Changes says in what a field list differs from the frozen one.
func v1Changes(now, frozen []v1Field) string {
	var b strings.Builder
	for _, f := range now {
		if !slices.Contains(frozen, f) {
			fmt.Fprintf(&b, "  not a field of v1:  %s\n", f)
		}
	}
	for _, f := range frozen {
		if !slices.Contains(now, f) {
			fmt.Fprintf(&b, "  gone or changed:    %s\n", f)
		}
	}
	if b.Len() == 0 {
		b.WriteString("  the same fields in another order:")
		for _, f := range now {
			b.WriteString(" " + f.name)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// TestV1ZeroValuesEncode pins which keys a v1 receipt always carries and
// which ones it leaves out when empty. The recordings cannot show it for a
// field that is never empty in them, such as the network modes.
func TestV1ZeroValuesEncode(t *testing.T) {
	for _, tc := range []struct {
		v    any
		want string
	}{
		{ReceiptV1{}, `{"schema":"","id":"","backend":"",` +
			`"capabilities":{"backend":"","isolation":"","cpu_limit":false,"memory_limit":false,"pids_limit":false,` +
			`"wall_timeout":false,"networks":null,"read_only_root":false,"seccomp":false,"drop_capabilities":false,` +
			`"snapshot":false,"needs_root":false},` +
			`"policy_sha256":"","policy":null,"image":{"ref":"","digest":""},"argv":null,"exit_code":0,"killed":"",` +
			`"started_at":"0001-01-01T00:00:00Z","finished_at":"0001-01-01T00:00:00Z","duration_ms":0,` +
			`"stdout_sha256":"","stderr_sha256":"","stdout_truncated":false,"stderr_truncated":false,` +
			`"diff":{"sha256":"","truncated":false,"entries":null},"connections":null,` +
			`"cgroup":{"memory_peak_bytes":0,"oom_kills":0,"cpu_usage_usec":0,"pids_peak":0,"pids_max_hits":0},` +
			`"host":{"kernel":"","arch":"","sandmeter_version":"","backend_version":""}}`},
		{EntryV1{}, `{"path":"","op":"","type":"","mode":0,"size":0,"sha256":"","target":""}`},
		{ConnectionV1{}, `{"proto":"","dst_ip":"","allowed":false}`},
		{PolicyV1{}, `{"limits":{},"network":{"mode":""},"filesystem":{"read_only_root":false},"syscalls":{"filter":""}}`},
	} {
		got, err := json.Marshal(tc.v)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != tc.want {
			t.Errorf("zero %T encodes as\n %s\nwant\n %s", tc.v, got, tc.want)
		}
	}
}

func TestV1PolicyHashIsOverTheSignedBytes(t *testing.T) {
	eachV1(t, func(t *testing.T, rec v1Recording, _, payload []byte) {
		r, err := DecodeV1(payload)
		if err != nil {
			t.Fatal(err)
		}
		// The policy field is the bytes that were signed, not a re-encoding.
		if !bytes.Contains(payload, append([]byte(`"policy":`), r.Policy...)) {
			t.Fatalf("Policy %s does not appear as is in the signed bytes", r.Policy)
		}
		if got := PolicyHashV1(r.Policy); got != r.PolicySHA256 {
			t.Errorf("PolicyHashV1 = %s, the receipt says %s", got, r.PolicySHA256)
		}

		// The same policy written with other bytes has another hash: nothing
		// is normalised on the way, not even white space around the value.
		for _, other := range [][]byte{
			bytes.Replace(r.Policy, []byte(`{"limits":`), []byte(`{ "limits":`), 1),
			append([]byte(" "), r.Policy...),
			append(bytes.Clone(r.Policy), '\n'),
		} {
			if bytes.Equal(other, r.Policy) || PolicyHashV1(other) == r.PolicySHA256 {
				t.Errorf("a policy with other bytes passed for the signed one: %q", other)
			}
		}

		// Why bytes: a policy struct that gained one field since the receipt
		// was signed decodes the policy without complaint and encodes it to
		// other bytes. A check on the re-encoded struct would refuse every
		// receipt written before the field existed.
		var grown struct {
			PolicyV1
			Mounts []string `json:"mounts"`
		}
		if err := json.Unmarshal(r.Policy, &grown); err != nil {
			t.Fatal(err)
		}
		again, err := json.Marshal(grown)
		if err != nil {
			t.Fatal(err)
		}
		if PolicyHashV1(again) == r.PolicySHA256 {
			t.Fatal("the grown struct encodes to the signed bytes: this test no longer shows the trap")
		}
	})
}

func TestV1PolicyDecodes(t *testing.T) {
	eachV1(t, func(t *testing.T, rec v1Recording, _, _ []byte) {
		got, err := DecodePolicyV1(rec.want.Policy)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, rec.policy) {
			t.Errorf("DecodePolicyV1 = %+v, want %+v", got, rec.policy)
		}
		// And back: the frozen policy structs encode to the signed bytes.
		again, err := json.Marshal(rec.policy)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again, rec.want.Policy) {
			t.Errorf("PolicyV1 encodes to %s, signed %s", again, rec.want.Policy)
		}
	})
}

func TestDecodePolicyV1IsStrict(t *testing.T) {
	const ok = `{"limits":{},"network":{"mode":"none"},"filesystem":{"read_only_root":true},"syscalls":{"filter":"default"}}`
	if _, err := DecodePolicyV1([]byte(ok)); err != nil {
		t.Fatalf("a plain v1 policy is refused: %v", err)
	}
	for name, in := range map[string]string{
		"unknown key":        strings.Replace(ok, `"limits":{}`, `"limits":{},"mounts":[]`, 1),
		"unknown nested key": strings.Replace(ok, `"limits":{}`, `"limits":{"disk":"1GiB"}`, 1),
		"trailing data":      ok + ` {}`,
		"not json":           `nope`,
	} {
		if _, err := DecodePolicyV1([]byte(in)); err == nil {
			t.Errorf("%s: accepted %s", name, in)
		}
	}
}

// TestV1DiffHashRecomputes checks the entry structs against a value the
// recording carries itself: the diff hash is the SHA-256 of the entries as
// encoding/json writes them.
func TestV1DiffHashRecomputes(t *testing.T) {
	eachV1(t, func(t *testing.T, rec v1Recording, _, payload []byte) {
		r, err := DecodeV1(payload)
		if err != nil {
			t.Fatal(err)
		}
		entries, err := json.Marshal(r.Diff.Entries)
		if err != nil {
			t.Fatal(err)
		}
		if got := hexSHA256(entries); got != r.Diff.SHA256 {
			t.Errorf("entries hash to %s, the receipt says %s", got, r.Diff.SHA256)
		}
	})
}

func TestDecodeV1IsStrict(t *testing.T) {
	payload := readV1(t, "failed.payload.json")
	if _, err := DecodeV1(payload); err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string][]byte{
		"unknown field":        bytes.Replace(payload, []byte(`{"schema"`), []byte(`{"extra":1,"schema"`), 1),
		"unknown nested field": bytes.Replace(payload, []byte(`"host":{`), []byte(`"host":{"extra":1,`), 1),
		"trailing data":        append(bytes.Clone(payload), ` {}`...),
		"another schema":       bytes.Replace(payload, []byte(`sandmeter.receipt/v1`), []byte(`sandmeter.receipt/v2`), 1),
		"no schema":            bytes.Replace(payload, []byte(`"schema":"sandmeter.receipt/v1",`), nil, 1),
		"not json":             []byte(`nope`),
		"empty":                nil,
	} {
		if bytes.Equal(in, payload) {
			t.Fatalf("%s: the case does not change the payload", name)
		}
		if _, err := DecodeV1(in); err == nil {
			t.Errorf("%s: DecodeV1 accepted it", name)
		}
	}
}

// v1CapabilitySetters sets each capability flag by its Go field, under the
// key it has to have in a v1 receipt.
var v1CapabilitySetters = map[string]func(*CapabilitiesV1){
	"cpu_limit":         func(c *CapabilitiesV1) { c.CPULimit = true },
	"memory_limit":      func(c *CapabilitiesV1) { c.MemoryLimit = true },
	"pids_limit":        func(c *CapabilitiesV1) { c.PIDsLimit = true },
	"wall_timeout":      func(c *CapabilitiesV1) { c.WallTimeout = true },
	"read_only_root":    func(c *CapabilitiesV1) { c.ReadOnlyRoot = true },
	"seccomp":           func(c *CapabilitiesV1) { c.Seccomp = true },
	"drop_capabilities": func(c *CapabilitiesV1) { c.DropCaps = true },
	"snapshot":          func(c *CapabilitiesV1) { c.Snapshot = true },
	"needs_root":        func(c *CapabilitiesV1) { c.NeedsRoot = true },
}

// TestV1CapabilityKeys pins which Go field each capability key belongs to.
// The recordings cannot: every backend that wrote a v1 receipt declared all
// of these true, so two swapped fields would decode to the same value.
func TestV1CapabilityKeys(t *testing.T) {
	for key, set := range v1CapabilitySetters {
		var c CapabilitiesV1
		set(&c)
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(b), "true") != 1 || !strings.Contains(string(b), `"`+key+`":true`) {
			t.Errorf("the field for %q encodes as %s", key, b)
		}
	}
}

// TestVerifyKeepsEachV1Capability does for the conversion in fromV1 what
// TestV1CapabilityKeys does for the frozen struct, and goes away with it.
func TestVerifyKeepsEachV1Capability(t *testing.T) {
	for key, set := range v1CapabilitySetters {
		var r ReceiptV1
		set(&r.Capabilities)
		b, err := json.Marshal(fromV1(r).Capabilities)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(b), "true") != 1 || !strings.Contains(string(b), `"`+key+`":true`) {
			t.Errorf("after fromV1 the capability %q encodes as %s", key, b)
		}
	}
}

// backendCapabilitySetters sets each capability flag by its Go field on the
// type the backends declare them with, under the key a v1 receipt records it
// under.
var backendCapabilitySetters = map[string]func(*sandbox.Capabilities){
	"cpu_limit":         func(c *sandbox.Capabilities) { c.CPULimit = true },
	"memory_limit":      func(c *sandbox.Capabilities) { c.MemoryLimit = true },
	"pids_limit":        func(c *sandbox.Capabilities) { c.PIDsLimit = true },
	"wall_timeout":      func(c *sandbox.Capabilities) { c.WallTimeout = true },
	"read_only_root":    func(c *sandbox.Capabilities) { c.ReadOnlyRoot = true },
	"seccomp":           func(c *sandbox.Capabilities) { c.Seccomp = true },
	"drop_capabilities": func(c *sandbox.Capabilities) { c.DropCaps = true },
	"snapshot":          func(c *sandbox.Capabilities) { c.Snapshot = true },
	"needs_root":        func(c *sandbox.Capabilities) { c.NeedsRoot = true },
}

// TestSigningKeepsEachCapability is the same check on the way out, through
// toV1: a control the backend declared is signed under its own key and under
// no other. Here too the recordings would not notice two flags swapped.
func TestSigningKeepsEachCapability(t *testing.T) {
	for key := range v1CapabilitySetters {
		if backendCapabilitySetters[key] == nil {
			t.Errorf("no backend capability is checked against the v1 key %q", key)
		}
	}
	for key, set := range backendCapabilitySetters {
		r := Receipt{Schema: SchemaV1}
		set(&r.Capabilities)
		body, err := Canonical(r)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := DecodeV1(body)
		if err != nil {
			t.Fatalf("%s: what Canonical returns is not a v1 payload: %v", key, err)
		}
		b, err := json.Marshal(signed.Capabilities)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(b), "true") != 1 || !strings.Contains(string(b), `"`+key+`":true`) {
			t.Errorf("the capability %q is signed as %s", key, b)
		}
	}
}

// TestV1KeyFiles checks the two forms of the public key against each other
// and against the key id the recordings were signed under.
func TestV1KeyFiles(t *testing.T) {
	pub := v1Key(t)
	legacy, err := LoadPublicKey(filepath.Join("testdata", "v1", "key.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(legacy) {
		t.Fatal("key.pub and key.pub.pem hold different keys")
	}
	eachV1(t, func(t *testing.T, _ v1Recording, envelope, _ []byte) {
		var env Envelope
		if err := json.Unmarshal(envelope, &env); err != nil {
			t.Fatal(err)
		}
		if env.PayloadType != PayloadType || len(env.Signatures) != 1 || env.Signatures[0].KeyID != KeyID(pub) {
			t.Errorf("envelope has type %q and signatures %+v, want one signature by key %s", env.PayloadType, env.Signatures, KeyID(pub))
		}
	})
}

// TestVerifyLosesNothingFromV1 checks fromV1 and toV1 against each other on
// real receipts: what Verify hands back encodes to the signed bytes again.
// It holds for as long as Receipt, the type Verify returns, can hold
// everything a v1 receipt does. When Receipt takes another shape this test
// goes away with the two conversions; the tests of the frozen structs stay.
func TestVerifyLosesNothingFromV1(t *testing.T) {
	pub := v1Key(t)
	eachV1(t, func(t *testing.T, _ v1Recording, envelope, payload []byte) {
		got, err := Verify(envelope, pub)
		if err != nil {
			t.Fatal(err)
		}
		again, err := Canonical(got)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again, payload) {
			t.Errorf("Verify lost or changed something:\n got  %s\n want %s", again, payload)
		}
	})
}

// TestVerifyDecodesBySchema signs payloads this build has no decoder for and
// checks that Verify says so, whatever else they hold.
func TestVerifyDecodesBySchema(t *testing.T) {
	pub, priv := newKey(t)
	for name, body := range map[string]string{
		"a later schema":     `{"schema":"sandmeter.receipt/v2","kind":"command","seq":1}`,
		"v1 fields, renamed": strings.Replace(string(readV1(t, "oom.payload.json")), "sandmeter.receipt/v1", "other.receipt/v1", 1),
		"no schema":          `{"id":"r1"}`,
	} {
		_, err := Verify(envelopeJSON(t, signRaw(priv, PayloadType, []byte(body))), pub)
		if err == nil || !strings.Contains(err.Error(), "unsupported schema") {
			t.Errorf("%s: err = %v, want an unsupported schema error", name, err)
		}
	}
}
