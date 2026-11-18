package engine

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/camilbenameur/sandmeter/policy"
	"github.com/camilbenameur/sandmeter/receipt"
)

// v1FixtureDir holds the v1 receipts recorded from this engine; see the
// README there.
const v1FixtureDir = "../../receipt/testdata/v1"

// recordedReceipt loads a recorded v1 receipt the way the replay command
// does: through receipt.Verify, with the public key of the recordings.
func recordedReceipt(t *testing.T, name string) receipt.Receipt {
	t.Helper()
	keyPEM, err := os.ReadFile(filepath.Join(v1FixtureDir, "key.pub.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("key.pub.pem holds no PEM block")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := os.ReadFile(filepath.Join(v1FixtureDir, name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := receipt.Verify(envelope, key.(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("recorded receipt %s: %v", name, err)
	}
	return rec
}

func TestPinnedRef(t *testing.T) {
	d := "sha256:abc"
	for in, want := range map[string]string{
		"docker.io/library/alpine:3.20": "docker.io/library/alpine@sha256:abc",
		"alpine":                        "alpine@sha256:abc",
		"localhost:5000/x/y:tag":        "localhost:5000/x/y@sha256:abc",
		"localhost:5000/x/y":            "localhost:5000/x/y@sha256:abc",
		"alpine@sha256:old":             "alpine@sha256:abc",
		"ghcr.io/o/r:v1@sha256:0123":    "ghcr.io/o/r@sha256:abc",
	} {
		if got := pinnedRef(in, d); got != want {
			t.Errorf("pinnedRef(%q) = %q, want %q", in, got, want)
		}
	}
	if got := pinnedRef("alpine:3", ""); got != "alpine:3" {
		t.Errorf("no digest: got %q", got)
	}
}

// TestReplayPolicyOfRecordedReceipts checks that a replay of a v1 receipt
// starts from the policy its command ran under. The policies are written
// out here, not taken from policy.Default or from the recorder: a v1
// receipt keeps meaning what it meant when it was signed.
func TestReplayPolicyOfRecordedReceipts(t *testing.T) {
	for name, want := range map[string]policy.Policy{
		"success": {
			Limits:   policy.Limits{CPU: 2, PIDs: 512},
			Network:  policy.Network{Mode: "allowlist", Allow: []string{"192.0.2.10:443", "example.com:443"}},
			Syscalls: policy.Syscalls{Filter: "default"},
		},
		"failed": {
			Limits:     policy.Limits{CPU: 1, Memory: "512MiB", PIDs: 256, Wall: "60s"},
			Network:    policy.Network{Mode: "none"},
			Filesystem: policy.Filesystem{ReadOnlyRoot: true},
			Syscalls:   policy.Syscalls{Filter: "default"},
		},
		"killed": {
			Limits:     policy.Limits{Memory: "64MiB", Wall: "2s"},
			Network:    policy.Network{Mode: "none"},
			Filesystem: policy.Filesystem{ReadOnlyRoot: true},
			Syscalls:   policy.Syscalls{Filter: "off"},
		},
		"oom": {
			Limits:     policy.Limits{Memory: "64MiB"},
			Network:    policy.Network{Mode: "none"},
			Filesystem: policy.Filesystem{ReadOnlyRoot: true},
			Syscalls:   policy.Syscalls{Filter: "default"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := replayPolicy(recordedReceipt(t, name))
			if err != nil {
				t.Fatalf("a recorded v1 receipt can no longer be replayed: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("replay policy = %+v, want %+v", got, want)
			}
		})
	}
}

// TestReplayPolicyChecksTheSignedBytes pins what the hash in a v1 receipt
// covers: the policy bytes as signed. A receipt whose policy says the same
// thing with other bytes does not match its hash, and one whose bytes match
// is accepted whatever the policy type of this build encodes to.
func TestReplayPolicyChecksTheSignedBytes(t *testing.T) {
	if _, err := replayPolicy(recordedReceipt(t, "failed")); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*receipt.Receipt){
		"same policy, other bytes": func(r *receipt.Receipt) {
			r.Policy = bytes.Replace(r.Policy, []byte(`{"limits":`), []byte(`{ "limits":`), 1)
		},
		"another policy": func(r *receipt.Receipt) {
			r.Policy = bytes.Replace(r.Policy, []byte(`"pids":256`), []byte(`"pids":4096`), 1)
		},
		"another hash": func(r *receipt.Receipt) {
			r.PolicySHA256 = strings.Repeat("0", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			rec := recordedReceipt(t, "failed")
			before := string(rec.Policy) + rec.PolicySHA256
			change(&rec)
			if string(rec.Policy)+rec.PolicySHA256 == before {
				t.Fatal("the case does not change the receipt")
			}
			_, err := replayPolicy(rec)
			if err == nil || !strings.Contains(err.Error(), "policy hash mismatch") {
				t.Fatalf("err = %v, want a policy hash mismatch", err)
			}
		})
	}

	rec := recordedReceipt(t, "failed")
	rec.Policy = bytes.Replace(rec.Policy, []byte(`{"limits":`), []byte(`{"mounts":[],"limits":`), 1)
	rec.PolicySHA256 = receipt.PolicyHashV1(rec.Policy)
	if _, err := replayPolicy(rec); err == nil || !strings.Contains(err.Error(), "policy in receipt") {
		t.Fatalf("a v1 policy with an unknown key: err = %v, want it refused", err)
	}
}

func TestPolicyRoundTripKeepsZeroFields(t *testing.T) {
	p := policy.Default()
	p.Limits.CPU = 0
	p.Limits.Wall = ""
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	q, err := replayPolicy(receipt.Receipt{Policy: b, PolicySHA256: p.Hash()})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(q, p) {
		t.Fatalf("round trip changed the policy: %+v -> %+v", p, q)
	}
}
