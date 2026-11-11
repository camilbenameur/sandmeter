package receipt

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/camilbenameur/sandmeter/sandbox"
)

func sample() Receipt {
	t0 := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	return Receipt{
		Schema:       SchemaV1,
		ID:           "r1",
		Backend:      "native",
		Capabilities: sandbox.Capabilities{Backend: "native", Networks: []sandbox.NetworkMode{sandbox.NetworkNone}},
		PolicySHA256: "abc",
		Policy:       json.RawMessage(`{"a": 1}`),
		Image:        ImageRef{Ref: "alpine:3", Digest: "sha256:00"},
		Argv:         []string{"echo", "hi"},
		StartedAt:    t0,
		FinishedAt:   t0.Add(time.Second),
		DurationMS:   1000,
		Diff:         Diff{Entries: []Entry{{Path: "a", Op: "add", Type: "file"}}},
		Connections:  []sandbox.Connection{{Proto: "tcp", DstIP: "1.1.1.1", DstPort: 443}, {Proto: "tcp", DstIP: "2.2.2.2", Allowed: true}},
		Cgroup:       sandbox.CgroupStats{MemoryPeakBytes: 5 << 20, PIDsPeak: 3},
	}
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// resign builds an envelope from arbitrary parts, to test rejection paths.
func envelopeJSON(t *testing.T, env Envelope) []byte {
	t.Helper()
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func signRaw(priv ed25519.PrivateKey, ptype string, body []byte) Envelope {
	return Envelope{
		PayloadType: ptype,
		Payload:     base64.StdEncoding.EncodeToString(body),
		Signatures: []Signature{{
			KeyID: KeyID(priv.Public().(ed25519.PublicKey)),
			Sig:   base64.StdEncoding.EncodeToString(ed25519.Sign(priv, pae(ptype, body))),
		}},
	}
}

func TestRoundTrip(t *testing.T) {
	pub, priv := newKey(t)
	env, err := Sign(sample(), priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(env, pub)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := Canonical(sample())
	b, _ := Canonical(got)
	if string(a) != string(b) {
		t.Fatalf("round trip changed the receipt:\n%s\n%s", a, b)
	}
}

func TestPAE(t *testing.T) {
	got := string(pae("type", []byte("body!")))
	if got != "DSSEv1 4 type 5 body!" {
		t.Fatalf("pae = %q", got)
	}
}

func TestVerifyRejects(t *testing.T) {
	pub, priv := newKey(t)
	otherPub, _ := newKey(t)
	good, err := Sign(sample(), priv)
	if err != nil {
		t.Fatal(err)
	}
	var env Envelope
	if err := json.Unmarshal(good, &env); err != nil {
		t.Fatal(err)
	}
	body, _ := Canonical(sample())

	tamperedPayload := env
	tamperedPayload.Payload = base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(body), `"r1"`, `"r2"`, 1)))
	tamperedType := env
	tamperedType.PayloadType = "application/other"
	wrongKeyID := env
	wrongKeyID.Signatures = []Signature{{KeyID: "0000000000000000", Sig: env.Signatures[0].Sig}}

	unknown := strings.Replace(string(body), `{"schema"`, `{"extra":1,"schema"`, 1)
	badSchema := sample()
	badSchema.Schema = "other/v9"
	badSchemaBody, _ := Canonical(badSchema)

	cases := map[string]struct {
		env []byte
		pub ed25519.PublicKey
	}{
		"tampered payload":      {envelopeJSON(t, tamperedPayload), pub},
		"tampered payload type": {envelopeJSON(t, tamperedType), pub},
		"wrong key":             {good, otherPub},
		"wrong keyid":           {envelopeJSON(t, wrongKeyID), pub},
		"unknown field":         {envelopeJSON(t, signRaw(priv, PayloadType, []byte(unknown))), pub},
		"bad schema":            {envelopeJSON(t, signRaw(priv, PayloadType, badSchemaBody)), pub},
		"trailing data":         {envelopeJSON(t, signRaw(priv, PayloadType, append(append([]byte{}, body...), []byte(` {}`)...))), pub},
		"not json":              {[]byte("nope"), pub},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(c.env, c.pub); err == nil {
				t.Fatal("Verify accepted a bad envelope")
			}
		})
	}
}

func TestKeyFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "key")
	k1, err := LoadOrCreateKey(p)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode = %v, err %v", fi.Mode().Perm(), err)
	}
	pi, err := os.Stat(p + ".pub")
	if err != nil || pi.Mode().Perm() != 0o644 {
		t.Fatalf("pub mode = %v, err %v", pi.Mode().Perm(), err)
	}
	k2, err := LoadOrCreateKey(p)
	if err != nil || !k1.Equal(k2) {
		t.Fatalf("reload differs: %v", err)
	}
	pub, err := LoadPublicKey(p + ".pub")
	if err != nil || !pub.Equal(k1.Public()) {
		t.Fatalf("public key mismatch: %v", err)
	}

	if err := os.Chmod(p, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(p); err == nil {
		t.Fatal("loaded a group-readable key")
	}
}

func TestKeyFileGarbage(t *testing.T) {
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte("not base64 !!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(p); err == nil {
		t.Fatal("loaded garbage")
	}
}

func TestSummary(t *testing.T) {
	s := Summary(sample())
	for _, want := range []string{"native", "sha256:00", "echo hi", "exit 0", "1 add", "1 allowed, 1 denied", "5.0 MiB", "3 peak"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary lacks %q:\n%s", want, s)
		}
	}
}

func TestCanonicalNormalizesToUTC(t *testing.T) {
	a := sample()
	b := a
	b.StartedAt = a.StartedAt.In(time.FixedZone("x", 5*3600))
	b.FinishedAt = a.FinishedAt.In(time.FixedZone("x", 5*3600))
	ca, _ := Canonical(a)
	cb, _ := Canonical(b)
	if string(ca) != string(cb) {
		t.Errorf("zone changes signed bytes:\n%s\n%s", ca, cb)
	}
}
