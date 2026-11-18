package engine

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/camilbenameur/sandmeter/internal/prototype/sandbox"
	"github.com/camilbenameur/sandmeter/receipt"
)

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

// TestEachBackendCapabilityIsSignedUnderItsOwnKey checks the copy in
// capabilitiesV1 flag by flag: a control the backend declared reaches the
// signed bytes under its own key and under no other. The recorded receipts
// cannot notice two flags swapped, because every backend that wrote one
// declared all of them true.
func TestEachBackendCapabilityIsSignedUnderItsOwnKey(t *testing.T) {
	// Every boolean key of the frozen shape has a setter here.
	all, err := json.Marshal(receipt.CapabilitiesV1{})
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]any
	if err := json.Unmarshal(all, &keys); err != nil {
		t.Fatal(err)
	}
	for key, v := range keys {
		if _, isBool := v.(bool); isBool && backendCapabilitySetters[key] == nil {
			t.Errorf("no backend capability is checked against the v1 key %q", key)
		}
	}

	for key, set := range backendCapabilitySetters {
		var c sandbox.Capabilities
		set(&c)
		body, err := receipt.Canonical(receipt.Receipt{Schema: receipt.SchemaV1, Capabilities: capabilitiesV1(c)})
		if err != nil {
			t.Fatal(err)
		}
		signed, err := receipt.DecodeV1(body)
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

func TestCapabilitiesV1KeepsTheRest(t *testing.T) {
	got := capabilitiesV1(sandbox.Capabilities{
		Backend:   "native",
		Isolation: "linux-namespaces",
		Networks:  []sandbox.NetworkMode{sandbox.NetworkNone, sandbox.NetworkAllowlist},
		Notes:     []string{"a note"},
	})
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"backend":"native","isolation":"linux-namespaces","cpu_limit":false,"memory_limit":false,"pids_limit":false,"wall_timeout":false,"networks":["none","allowlist"],"read_only_root":false,"seccomp":false,"drop_capabilities":false,"snapshot":false,"needs_root":false,"notes":["a note"]}`
	if string(b) != want {
		t.Errorf("capabilities encode as\n %s\nwant\n %s", b, want)
	}

	// A backend that declared no network list signs null, one that declared
	// an empty list signs []: the two are different signed bytes.
	for _, tc := range []struct {
		in   []sandbox.NetworkMode
		want string
	}{{nil, `"networks":null`}, {[]sandbox.NetworkMode{}, `"networks":[]`}} {
		b, err := json.Marshal(capabilitiesV1(sandbox.Capabilities{Networks: tc.in}))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), tc.want) {
			t.Errorf("networks %#v encode as %s, want %s in it", tc.in, b, tc.want)
		}
	}
}

func TestConnectionsV1IsNeverNil(t *testing.T) {
	for _, in := range [][]sandbox.Connection{nil, {}} {
		b, err := json.Marshal(connectionsV1(in))
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != "[]" {
			t.Errorf("no connection encodes as %s, want []", b)
		}
	}
	got := connectionsV1([]sandbox.Connection{{Proto: "tcp", DstIP: "192.0.2.10", DstPort: 443, Allowed: true}})
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if want := `[{"proto":"tcp","dst_ip":"192.0.2.10","dst_port":443,"allowed":true}]`; string(b) != want {
		t.Errorf("connections encode as %s, want %s", b, want)
	}
}
