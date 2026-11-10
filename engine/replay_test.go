package engine

import (
	"encoding/json"
	"testing"

	"github.com/camilbenameur/ringfence/policy"
)

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

func TestPolicyRoundTripKeepsZeroFields(t *testing.T) {
	p := policy.Default()
	p.Limits.CPU = 0
	p.Limits.Wall = ""
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var q policy.Policy
	if err := jsonUnmarshalStrict(b, &q); err != nil {
		t.Fatal(err)
	}
	if q.Hash() != p.Hash() {
		t.Fatalf("round trip changed the policy: %+v -> %+v", p, q)
	}
}
