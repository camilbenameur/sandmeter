package policy

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

// fullV2 uses every key of schema v2.
const fullV2 = `
version = 2

[limits]
cpu = 0.5
memory = "1GiB"
pids = 512
wall = "10m"
disk = "256MiB"

[storage]
upper = "tmpfs"

[network]
mode = "proxy"
allow = ["pypi.org", "*.pythonhosted.org:443"]

[filesystem]
read_only_root = false

[syscalls]
profile = "compat"

[process]
env = { CI = "1", LANG = "C.UTF-8" }
env_pass = ["NPM_TOKEN"]
workdir = "/workspace"

[workspace]
exclude = [".env", "node_modules/"]
`

func decodeStrict(t *testing.T, doc string, into any) error {
	t.Helper()
	md, err := toml.Decode(doc, into)
	if err != nil {
		return err
	}
	if und := md.Undecoded(); len(und) > 0 {
		t.Fatalf("keys of the document have no field: %v", und)
	}
	return nil
}

func TestEveryV2KeyHasAField(t *testing.T) {
	var p Policy
	if err := decodeStrict(t, fullV2, &p); err != nil {
		t.Fatal(err)
	}
	writable := false
	want := Policy{
		Version:    2,
		Limits:     Limits{CPU: Num(0.5), Memory: "1GiB", PIDs: Num(512), Wall: "10m", Disk: "256MiB"},
		Storage:    Storage{Upper: UpperTmpfs},
		Network:    Network{Mode: NetworkProxy, Allow: []string{"pypi.org", "*.pythonhosted.org:443"}},
		Filesystem: Filesystem{ReadOnlyRoot: &writable},
		Syscalls:   Syscalls{Profile: ProfileCompat},
		Process:    Process{Env: map[string]string{"CI": "1", "LANG": "C.UTF-8"}, EnvPass: []string{"NPM_TOKEN"}, Workdir: "/workspace"},
		Workspace:  Workspace{Exclude: []string{".env", "node_modules/"}},
	}
	if !reflect.DeepEqual(p, want) {
		t.Errorf("decoded\n %+v\nwant\n %+v", p, want)
	}

	// The JSON form of the same document reads back to the same value.
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var back Policy
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&back); err != nil {
		t.Fatalf("%s: %v", b, err)
	}
	if !reflect.DeepEqual(back, want) {
		t.Errorf("after JSON\n %+v\nwant\n %+v", back, want)
	}
}

// TestAbsentKeysStayUnset is the property the ceiling rests on: a key the
// file leaves out is told apart from every value the file could give.
func TestAbsentKeysStayUnset(t *testing.T) {
	var p Policy
	if err := decodeStrict(t, "version = 2\n", &p); err != nil {
		t.Fatal(err)
	}
	if p.Limits.CPU.IsSet() || p.Limits.PIDs.IsSet() || p.Limits.Memory != "" || p.Limits.Wall != "" || p.Limits.Disk != "" {
		t.Errorf("limits of an empty file are set: %+v", p.Limits)
	}
	if p.Filesystem.ReadOnlyRoot != nil {
		t.Error("read_only_root of an empty file is not nil: unset could be read as false, a writable root")
	}
	if p.Network.Mode != "" || p.Syscalls.Profile != "" || p.Storage.Upper != "" {
		t.Errorf("modes of an empty file are set: %+v %+v %+v", p.Network, p.Syscalls, p.Storage)
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"version":2,"limits":{},"storage":{},"network":{},"filesystem":{},"syscalls":{},"process":{},"workspace":{}}`
	if string(b) != want {
		t.Errorf("an empty policy encodes as\n %s\nwant\n %s", b, want)
	}
}

func TestNumberFromTOML(t *testing.T) {
	type doc struct {
		Limits Limits `toml:"limits"`
	}
	for _, tc := range []struct {
		line      string
		value     float64
		unlimited bool
	}{
		{`cpu = 2`, 2, false},
		{`cpu = 0.25`, 0.25, false},
		{`cpu = 0`, 0, false},
		{`cpu = -1`, -1, false},
		{`cpu = "unlimited"`, 0, true},
	} {
		var d doc
		if err := decodeStrict(t, "[limits]\n"+tc.line+"\n", &d); err != nil {
			t.Errorf("%s: %v", tc.line, err)
			continue
		}
		n := d.Limits.CPU
		v, ok := n.Value()
		if !n.IsSet() || n.IsUnlimited() != tc.unlimited || ok == tc.unlimited || (ok && v != tc.value) {
			t.Errorf("%s decoded as %#v", tc.line, n)
		}
	}
	// A value that compares false with every bound must not get in.
	for _, line := range []string{`cpu = nan`, `cpu = inf`, `cpu = -inf`, `cpu = +inf`, `cpu = "many"`, `cpu = ""`, `cpu = true`, `cpu = [1]`, `pids = "UNLIMITED"`} {
		var d doc
		if err := decodeStrict(t, "[limits]\n"+line+"\n", &d); err == nil {
			t.Errorf("%s was accepted as cpu=%#v pids=%#v", line, d.Limits.CPU, d.Limits.PIDs)
		}
	}
}

func TestNumberJSON(t *testing.T) {
	for in, want := range map[string]Number{
		`null`:        {},
		`2`:           Num(2),
		`0.5`:         Num(0.5),
		`256`:         Num(256),
		`"unlimited"`: NoLimit(),
	} {
		var n Number
		if err := json.Unmarshal([]byte(in), &n); err != nil || n != want {
			t.Errorf("%s decoded as %#v, %v; want %#v", in, n, err, want)
		}
		b, err := json.Marshal(want)
		if err != nil || string(b) != in {
			t.Errorf("%#v encoded as %s, %v; want %s", want, b, err, in)
		}
	}
	for _, in := range []string{`"lots"`, `1e999`, `-1e999`, `true`, `{}`, `[1]`, `""`} {
		var n Number
		if err := json.Unmarshal([]byte(in), &n); err == nil {
			t.Errorf("%s was accepted as %#v", in, n)
		}
	}
}

func TestNumNeverHoldsNaN(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Num accepted NaN")
		}
	}()
	var zero float64
	Num(zero / zero)
}

func TestNumberTOMLEncodes(t *testing.T) {
	var buf bytes.Buffer
	lim := struct {
		CPU  Number `toml:"cpu,omitempty"`
		PIDs Number `toml:"pids,omitempty"`
		Wall string `toml:"wall,omitempty"`
	}{CPU: Num(1.5), PIDs: NoLimit()}
	if err := toml.NewEncoder(&buf).Encode(lim); err != nil {
		t.Fatal(err)
	}
	var back Limits
	if err := decodeStrict(t, buf.String(), &back); err != nil {
		t.Fatalf("%s: %v", buf.String(), err)
	}
	if back.CPU != Num(1.5) || back.PIDs != NoLimit() {
		t.Errorf("encoded as\n%s\nand read back as %+v", buf.String(), back)
	}
}

func int64p(v int64) *int64 { return &v }

func sampleNormal() Normal {
	return Normal{
		Version: 2,
		Limits: NormalLimits{
			CPUMillis:   int64p(1000),
			MemoryBytes: int64p(512 << 20),
			PIDs:        int64p(256),
			WallNanos:   int64p(60e9),
		},
		Storage:    Storage{Upper: UpperDisk},
		Network:    NormalNetwork{Mode: NetworkNone},
		Filesystem: NormalFilesystem{ReadOnlyRoot: true},
		Syscalls:   Syscalls{Profile: ProfileDefault},
	}
}

// TestCanonicalBytesArePinned holds the canonical form in place. These bytes
// are embedded in signed receipts: if this test fails, the change under test
// altered a published format.
func TestCanonicalBytesArePinned(t *testing.T) {
	const want = `{"version":2,"limits":{"cpu_millis":1000,"memory_bytes":536870912,"pids":256,"wall_ns":60000000000,"disk_bytes":null},"storage":{"upper":"disk"},"network":{"mode":"none","allow":[]},"filesystem":{"read_only_root":true},"syscalls":{"profile":"default"},"process":{"env":{},"env_pass":[],"workdir":""},"workspace":{"exclude":[]}}`
	n := sampleNormal()
	got, err := n.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("canonical bytes\n %s\nwant\n %s", got, want)
	}
	hash, err := n.Hash()
	if err != nil {
		t.Fatal(err)
	}
	if hash != HashBytes([]byte(want)) || len(hash) != 64 || strings.ToLower(hash) != hash {
		t.Errorf("Hash() = %s, HashBytes of the canonical bytes = %s", hash, HashBytes([]byte(want)))
	}
	if n.Network.Allow != nil {
		t.Error("Canonical changed its receiver")
	}

	// The same policy with empty lists spelled out is the same bytes.
	n.Network.Allow = []Dest{}
	n.Process = NormalProcess{Env: map[string]string{}, EnvPass: []string{}}
	n.Workspace.Exclude = []string{}
	again, err := n.Canonical()
	if err != nil || string(again) != want {
		t.Errorf("empty lists changed the bytes: %s, %v", again, err)
	}
}

func TestCanonicalIsDeterministicAndReadsBack(t *testing.T) {
	n := sampleNormal()
	n.Limits.PIDs = nil
	n.Limits.DiskBytes = int64p(64 << 20)
	n.Storage.Upper = UpperTmpfs
	n.Network = NormalNetwork{Mode: NetworkProxy, Allow: []Dest{
		{Host: "pythonhosted.org", Wildcard: true, Port: 443},
		{Host: "pypi.org", Port: 443},
		{Host: "192.0.2.7", Port: 8443, Transport: TransportTLS},
	}}
	n.Process = NormalProcess{
		Env:     map[string]string{"Z": "last", "A": "first", "M": "middle"},
		EnvPass: []string{"NPM_TOKEN"},
		Workdir: "/workspace",
	}
	n.Workspace.Exclude = []string{}
	first, err := n.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		again, err := n.Canonical()
		if err != nil || !bytes.Equal(first, again) {
			t.Fatalf("two encodings differ:\n %s\n %s", first, again)
		}
	}
	for _, want := range []string{`"pids":null`, `"allow":["*.pythonhosted.org:443","pypi.org:443","192.0.2.7:8443/tls"]`, `"env":{"A":"first","M":"middle","Z":"last"}`} {
		if !bytes.Contains(first, []byte(want)) {
			t.Errorf("canonical bytes lack %s:\n %s", want, first)
		}
	}
	var back Normal
	dec := json.NewDecoder(bytes.NewReader(first))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, n) {
		t.Errorf("read back\n %+v\nwant\n %+v", back, n)
	}
}

func TestViolations(t *testing.T) {
	var none Violations
	if none.Err() != nil {
		t.Error("an empty list is an error")
	}
	vs := Violations{{Key: "limits.memory", Reason: "8GiB is above the ceiling of 4GiB"}, {Key: "network.mode", Reason: "the ceiling grants no network"}}
	err := vs.Err()
	if err == nil {
		t.Fatal("a list of two is not an error")
	}
	if want := "limits.memory: 8GiB is above the ceiling of 4GiB\nnetwork.mode: the ceiling grants no network"; err.Error() != want {
		t.Errorf("message %q, want %q", err.Error(), want)
	}
	if got := strings.Join(vs.Keys(), ","); got != "limits.memory,network.mode" {
		t.Errorf("keys %s", got)
	}
}

func TestMissingControlIsNotEnforced(t *testing.T) {
	caps := Capabilities{Backend: "gvisor", Controls: map[ControlID]Control{
		ControlMemory: {Enforced: true, Reason: "left over"},
		ControlPIDs:   {Enforced: false},
		ControlCPU:    {Enforced: false, Reason: "the cpu controller is not delegated"},
	}}
	if got := caps.Control(ControlMemory); got != (Control{Enforced: true}) {
		t.Errorf("an enforced control reads as %+v", got)
	}
	if got := caps.Control(ControlCPU); got.Enforced || got.Reason != "the cpu controller is not delegated" {
		t.Errorf("a refused control reads as %+v", got)
	}
	for _, id := range []ControlID{ControlPIDs, ControlNetworkProxy, "made.up"} {
		got := caps.Control(id)
		if got.Enforced || got.Reason == "" || !strings.Contains(got.Reason, "gvisor") {
			t.Errorf("%s reads as %+v: want not enforced, with a reason that names the backend", id, got)
		}
	}
	if got := (Capabilities{}).Control(ControlMemory); got.Enforced || got.Reason == "" {
		t.Errorf("the zero Capabilities enforce %s: %+v", ControlMemory, got)
	}
	if !(Capabilities{}).Usable() || (Capabilities{Problems: []Problem{{ID: "root"}}}).Usable() {
		t.Error("Usable does not follow Problems")
	}
}

func TestControlsListIsClosedAndComplete(t *testing.T) {
	seen := map[ControlID]bool{}
	for _, id := range Controls {
		if seen[id] || id == "" {
			t.Errorf("control %q is empty or listed twice", id)
		}
		seen[id] = true
	}
	for _, id := range AlwaysRequired {
		if !seen[id] {
			t.Errorf("always-required control %q is not in Controls", id)
		}
	}
	// Whatever a policy can require is a control of the list.
	n := sampleNormal()
	n.Limits.DiskBytes = int64p(1)
	n.Storage.Upper = UpperTmpfs
	for _, mode := range []string{NetworkNone, NetworkProxy} {
		for _, profile := range []string{ProfileDefault, ProfileCompat, ProfileOff} {
			n.Network.Mode, n.Syscalls.Profile = mode, profile
			for _, r := range n.Requires() {
				if !seen[r.Control] {
					t.Errorf("%s requires %q, which is not in Controls", r.Key, r.Control)
				}
			}
		}
	}
}

func requirements(n Normal) string {
	var parts []string
	for _, r := range n.Requires() {
		parts = append(parts, r.Key+"="+string(r.Control))
	}
	return strings.Join(parts, " ")
}

func TestRequires(t *testing.T) {
	const always = " storage.floor=storage.floor userns.nested=userns.nested"
	n := sampleNormal()
	if got, want := requirements(n), "limits.cpu=limits.cpu limits.memory=limits.memory limits.pids=limits.pids limits.wall=limits.wall network.mode=network.none filesystem.read_only_root=filesystem.read_only_root syscalls.profile=syscalls.default"+always; got != want {
		t.Errorf("default policy requires\n %s\nwant\n %s", got, want)
	}

	// Unlimited limits, a writable root and no filter need no control, but
	// the network and the always-on controls are still required.
	n = Normal{Version: 2, Network: NormalNetwork{Mode: NetworkNone}, Syscalls: Syscalls{Profile: ProfileOff}}
	if got, want := requirements(n), "network.mode=network.none"+always; got != want {
		t.Errorf("the widest policy requires\n %s\nwant\n %s", got, want)
	}

	n = sampleNormal()
	n.Limits.DiskBytes = int64p(64 << 20)
	n.Storage.Upper = UpperTmpfs
	n.Network.Mode = NetworkProxy
	n.Syscalls.Profile = ProfileCompat
	got := requirements(n)
	for _, want := range []string{"limits.disk=storage.tmpfs", "storage.upper=storage.tmpfs", "network.mode=network.proxy", "syscalls.profile=syscalls.compat"} {
		if !strings.Contains(got, want) {
			t.Errorf("requirements %q lack %s", got, want)
		}
	}

	// A mode or a profile this build does not know never means "nothing
	// needed": it falls on the strictest control.
	n = sampleNormal()
	n.Network.Mode, n.Syscalls.Profile = "bridge", "relaxed"
	got = requirements(n)
	if !strings.Contains(got, "network.mode=network.none") || !strings.Contains(got, "syscalls.profile=syscalls.default") {
		t.Errorf("unknown values require %q", got)
	}
}

func TestDefaultAndBuiltinCeilingAreWrittenOut(t *testing.T) {
	d := Default()
	if d.Version != Version2 || d.Limits.CPU != Num(1) || d.Limits.Memory != "512MiB" || d.Limits.PIDs != Num(256) || d.Limits.Wall != "60s" || d.Limits.Disk != "" {
		t.Errorf("default limits %+v", d.Limits)
	}
	if d.Network.Mode != NetworkNone || len(d.Network.Allow) != 0 || d.Storage.Upper != UpperDisk || d.Syscalls.Profile != ProfileDefault {
		t.Errorf("default modes %+v %+v %+v", d.Network, d.Storage, d.Syscalls)
	}
	if d.Filesystem.ReadOnlyRoot == nil || !*d.Filesystem.ReadOnlyRoot {
		t.Error("the default root is not read-only")
	}

	c := BuiltinCeiling()
	if c.Network.Mode != NetworkNone || len(c.Network.Allow) != 0 {
		t.Errorf("the built-in ceiling grants a network: %+v", c.Network)
	}
	if len(c.Process.EnvPass) != 0 {
		t.Errorf("the built-in ceiling passes variables: %v", c.Process.EnvPass)
	}
	if c.Syscalls.Profile != ProfileCompat {
		t.Errorf("the built-in ceiling's weakest profile is %q", c.Syscalls.Profile)
	}
	if c.Filesystem.ReadOnlyRoot == nil || !*c.Filesystem.ReadOnlyRoot {
		t.Error("the built-in ceiling grants a writable root")
	}
	for name, lim := range map[string]Number{"cpu": c.Limits.CPU, "pids": c.Limits.PIDs} {
		if _, ok := lim.Value(); !ok {
			t.Errorf("the built-in ceiling has no finite %s", name)
		}
	}
	for name, lim := range map[string]string{"memory": c.Limits.Memory, "wall": c.Limits.Wall, "disk": c.Limits.Disk} {
		if lim == "" || lim == Unlimited {
			t.Errorf("the built-in ceiling has no finite %s: %q", name, lim)
		}
	}
	if c.Limits.CPU != d.Limits.CPU || c.Limits.Memory != d.Limits.Memory || c.Limits.PIDs != d.Limits.PIDs || c.Limits.Wall != d.Limits.Wall {
		t.Errorf("the built-in ceiling %+v is not the default limits %+v", c.Limits, d.Limits)
	}
}

// TestUnbuiltFunctionsFailClosed goes away, function by function, as they are
// written. Until then none of them may accept a policy.
func TestUnbuiltFunctionsFailClosed(t *testing.T) {
	if _, err := Parse([]byte("version = 2\n")); err == nil {
		t.Error("Parse accepted a file")
	}
	if _, err := Load("/nonexistent"); err == nil {
		t.Error("Load accepted a path")
	}
	if vs := Within(Default(), BuiltinCeiling()); vs.Err() == nil {
		t.Error("Within accepted a policy")
	}
	if _, vs := Effective(Default(), BuiltinCeiling()); vs.Err() == nil {
		t.Error("Effective accepted a policy")
	}
	if vs := Check(sampleNormal(), Capabilities{}); vs.Err() == nil {
		t.Error("Check accepted a policy")
	}
	if _, err := BuiltinCeiling().Hash(); err == nil {
		t.Error("Ceiling.Hash returned a hash")
	}
}
