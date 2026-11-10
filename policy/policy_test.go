package policy

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/camilbenameur/ringfence/sandbox"
)

func allCaps() sandbox.Capabilities {
	return sandbox.Capabilities{
		Backend: "test", CPULimit: true, MemoryLimit: true, PIDsLimit: true, WallTimeout: true,
		Networks:     []sandbox.NetworkMode{sandbox.NetworkNone, sandbox.NetworkAllowlist},
		ReadOnlyRoot: true, Seccomp: true, DropCaps: true, Snapshot: true,
	}
}

func fields(err error) []string {
	var out []string
	var j interface{ Unwrap() []error }
	if !errors.As(err, &j) {
		var v Violation
		if errors.As(err, &v) {
			return []string{v.Field}
		}
		return nil
	}
	for _, e := range j.Unwrap() {
		var v Violation
		if errors.As(e, &v) {
			out = append(out, v.Field)
		}
	}
	return out
}

func TestDefaultValidatesOnFullBackend(t *testing.T) {
	spec, err := Default().Validate(allCaps())
	if err != nil {
		t.Fatal(err)
	}
	if spec.Limits.MemoryBytes != 512<<20 || spec.Limits.PIDs != 256 || spec.Limits.Wall != time.Minute {
		t.Fatalf("unexpected limits %+v", spec.Limits)
	}
	if spec.Network != sandbox.NetworkNone || !spec.ReadOnlyRoot {
		t.Fatalf("unexpected spec %+v", spec)
	}
}

func TestBackendWithoutFeaturesRefusesEveryRequestedOne(t *testing.T) {
	_, err := Default().Validate(sandbox.Capabilities{Backend: "empty"})
	got := strings.Join(fields(err), ",")
	want := "limits.cpu,limits.memory,limits.pids,limits.wall,network.mode,filesystem.read_only_root,syscalls.filter"
	if got != want {
		t.Fatalf("violations\n got %s\nwant %s", got, want)
	}
}

func TestPermissivePolicyNeedsNothing(t *testing.T) {
	p := Policy{Network: Network{Mode: "none"}, Syscalls: Syscalls{Filter: "off"}}
	caps := sandbox.Capabilities{Networks: []sandbox.NetworkMode{sandbox.NetworkNone}}
	if _, err := p.Validate(caps); err != nil {
		t.Fatal(err)
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		toml    string
		wantErr string
		check   func(t *testing.T, p Policy)
	}{
		{
			name: "overrides keep defaults",
			toml: "[limits]\nmemory = \"1GiB\"\n",
			check: func(t *testing.T, p Policy) {
				if p.Limits.Memory != "1GiB" || p.Limits.PIDs != 256 || !p.Filesystem.ReadOnlyRoot {
					t.Fatalf("%+v", p)
				}
			},
		},
		{name: "unknown key is an error", toml: "[network]\nmod = \"none\"\n", wantErr: "unknown keys: network.mod"},
		{name: "bad toml", toml: "[limits\n", wantErr: "policy:"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Parse([]byte(tt.toml))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tt.check(t, p)
		})
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	tests := []struct {
		name  string
		edit  func(*Policy)
		field string
	}{
		{"negative cpu", func(p *Policy) { p.Limits.CPU = -1 }, "limits.cpu"},
		{"memory garbage", func(p *Policy) { p.Limits.Memory = "lots" }, "limits.memory"},
		{"memory too small", func(p *Policy) { p.Limits.Memory = "1KiB" }, "limits.memory"},
		{"negative pids", func(p *Policy) { p.Limits.PIDs = -3 }, "limits.pids"},
		{"zero wall", func(p *Policy) { p.Limits.Wall = "0s" }, "limits.wall"},
		{"unknown network", func(p *Policy) { p.Network.Mode = "host" }, "network.mode"},
		{"allow with none", func(p *Policy) { p.Network.Allow = []string{"a.example:443"} }, "network.allow"},
		{"empty allowlist", func(p *Policy) { p.Network.Mode = "allowlist" }, "network.allow"},
		{"wildcard host", func(p *Policy) { p.Network = Network{Mode: "allowlist", Allow: []string{"*.example:443"}} }, "network.allow"},
		{"cidr", func(p *Policy) { p.Network = Network{Mode: "allowlist", Allow: []string{"10.0.0.0/8:443"}} }, "network.allow"},
		{"no port", func(p *Policy) { p.Network = Network{Mode: "allowlist", Allow: []string{"example.org"}} }, "network.allow"},
		{"port zero", func(p *Policy) { p.Network = Network{Mode: "allowlist", Allow: []string{"example.org:0"}} }, "network.allow"},
		{"unknown filter", func(p *Policy) { p.Syscalls.Filter = "strict" }, "syscalls.filter"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Default()
			tt.edit(&p)
			_, err := p.Validate(allCaps())
			got := fields(err)
			if len(got) != 1 || got[0] != tt.field {
				t.Fatalf("violations = %v (err %v), want only %s", got, err, tt.field)
			}
		})
	}
}

func TestAllowlistAccepted(t *testing.T) {
	p := Default()
	p.Network = Network{Mode: "allowlist", Allow: []string{"proxy.golang.org:443", "[2001:db8::1]:53", "10.1.2.3:80"}}
	spec, err := p.Validate(allCaps())
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Allow) != 3 {
		t.Fatalf("allow = %v", spec.Allow)
	}
}

func TestParseBytes(t *testing.T) {
	tests := map[string]int64{
		"0": 0, "1048576": 1 << 20, "512MiB": 512 << 20, "64M": 64 << 20, "1GiB": 1 << 30,
		"2G": 2 << 30, "100MB": 100_000_000, "1KB": 1000, "7B": 7, " 3 KiB ": 3 << 10,
	}
	for in, want := range tests {
		got, err := ParseBytes(in)
		if err != nil || got != want {
			t.Errorf("ParseBytes(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "-1M", "1.5G", "ten", "99999999999G"} {
		if _, err := ParseBytes(in); err == nil {
			t.Errorf("ParseBytes(%q) succeeded, want error", in)
		}
	}
}

func TestHashIgnoresLayout(t *testing.T) {
	a, err := Parse([]byte("[limits]\npids = 10\nmemory = \"64MiB\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse([]byte("[limits]\nmemory = \"64MiB\"\n\n# comment\npids = 10\n"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Hash() != b.Hash() {
		t.Fatal("same policy, different hashes")
	}
	c := a
	c.Limits.PIDs = 11
	if a.Hash() == c.Hash() {
		t.Fatal("different policies, same hash")
	}
}
