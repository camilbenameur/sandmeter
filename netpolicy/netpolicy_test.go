package netpolicy

import (
	"context"
	"errors"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/camilbenameur/ringfence/sandbox"
)

var update = flag.Bool("update", false, "rewrite golden files")

func mustAddr(t *testing.T, i int) Addr {
	t.Helper()
	a, err := Allocate(i)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func goldenPlans(t *testing.T) map[string]Plan {
	ip := netip.MustParseAddr
	return map[string]Plan{
		"empty": {Table: "ringfence_a1", HostIface: "rfh0", Addr: mustAddr(t, 0)},
		"one": {Table: "ringfence_a1", HostIface: "rfh0", Addr: mustAddr(t, 1),
			Allow: []Dest{{IP: ip("93.184.216.34"), Port: 443, Proto: "tcp"}}},
		"several": {Table: "ringfence_b2", HostIface: "rfh-7", Addr: mustAddr(t, 300),
			Allow: []Dest{
				{IP: ip("140.82.112.3"), Port: 443, Proto: "tcp"},
				{IP: ip("1.1.1.1"), Port: 53, Proto: "udp"},
				{IP: ip("1.1.1.1"), Port: 53, Proto: "tcp"},
				{IP: ip("1.1.1.1"), Port: 53, Proto: "udp"}, // duplicate
			}},
	}
}

func TestRulesetGolden(t *testing.T) {
	for name, plan := range goldenPlans(t) {
		t.Run(name, func(t *testing.T) {
			got, err := Ruleset(plan)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", name+".nft")
			if *update {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Errorf("ruleset differs from %s:\n%s", path, got)
			}
		})
	}
}

func TestRulesetValidation(t *testing.T) {
	base := goldenPlans(t)["empty"]
	cases := map[string]func(*Plan){
		"table upper":  func(p *Plan) { p.Table = "Ringfence" },
		"table empty":  func(p *Plan) { p.Table = "" },
		"table inject": func(p *Plan) { p.Table = "a; flush ruleset" },
		"table long":   func(p *Plan) { p.Table = strings.Repeat("a", 33) },
		"iface quote":  func(p *Plan) { p.HostIface = `x" drop` },
		"iface long":   func(p *Plan) { p.HostIface = strings.Repeat("a", 16) },
		"iface empty":  func(p *Plan) { p.HostIface = "" },
		"no addr":      func(p *Plan) { p.Addr = Addr{} },
		"ipv6 dest": func(p *Plan) {
			p.Allow = []Dest{{IP: netip.MustParseAddr("::1"), Port: 1, Proto: "tcp"}}
		},
		"bad proto": func(p *Plan) {
			p.Allow = []Dest{{IP: netip.MustParseAddr("1.2.3.4"), Port: 1, Proto: "icmp"}}
		},
		"port zero": func(p *Plan) {
			p.Allow = []Dest{{IP: netip.MustParseAddr("1.2.3.4"), Proto: "tcp"}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := base
			mutate(&p)
			if s, err := Ruleset(p); err == nil {
				t.Errorf("want error, got script:\n%s", s)
			}
		})
	}
}

func TestAllocate(t *testing.T) {
	for _, bad := range []int{-1, 16384} {
		if _, err := Allocate(bad); err == nil {
			t.Errorf("Allocate(%d): want error", bad)
		}
	}
	first, _ := Allocate(0)
	if first.Host.String() != "10.213.0.1/30" || first.Sandbox.String() != "10.213.0.2/30" {
		t.Errorf("index 0: %v %v", first.Host, first.Sandbox)
	}
	last, _ := Allocate(MaxIndex)
	if last.Host.String() != "10.213.255.253/30" || last.Sandbox.String() != "10.213.255.254/30" {
		t.Errorf("last index: %v %v", last.Host, last.Sandbox)
	}
	seen := map[netip.Prefix]int{}
	for i := 0; i <= MaxIndex; i++ {
		a, err := Allocate(i)
		if err != nil {
			t.Fatal(err)
		}
		if a.Host.Masked() != a.Sandbox.Masked() {
			t.Fatalf("index %d: ends in different subnets", i)
		}
		if j, dup := seen[a.Host.Masked()]; dup {
			t.Fatalf("index %d and %d share subnet %v", i, j, a.Host.Masked())
		}
		seen[a.Host.Masked()] = i
		if !netip.MustParsePrefix("10.213.0.0/16").Contains(a.Sandbox.Addr()) {
			t.Fatalf("index %d outside 10.213.0.0/16", i)
		}
	}
}

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	if network != "ip4" {
		return nil, errors.New("test: resolver must ask for ip4, got " + network)
	}
	if a, ok := f[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

func TestResolve(t *testing.T) {
	ip := netip.MustParseAddr
	r := fakeResolver{
		"pypi.org":  {ip("151.101.64.223"), ip("151.101.0.223"), ip("2a04:4e42::223"), ip("151.101.0.223")},
		"v6.only":   {ip("2a04:4e42::223")},
		"mapped.ex": {ip("::ffff:9.9.9.9")},
	}
	dests, hosts, err := Resolve(context.Background(),
		[]string{"pypi.org:443", "1.1.1.1:53", "pypi.org:80", "1.1.1.1:53", "mapped.ex:443"}, r)
	if err != nil {
		t.Fatal(err)
	}
	wantDests := []Dest{
		{ip("1.1.1.1"), 53, "tcp"},
		{ip("9.9.9.9"), 443, "tcp"},
		{ip("151.101.0.223"), 80, "tcp"},
		{ip("151.101.0.223"), 443, "tcp"},
		{ip("151.101.64.223"), 80, "tcp"},
		{ip("151.101.64.223"), 443, "tcp"},
	}
	if !reflect.DeepEqual(dests, wantDests) {
		t.Errorf("dests:\n got %v\nwant %v", dests, wantDests)
	}
	wantHosts := []HostEntry{
		{"mapped.ex", ip("9.9.9.9")},
		{"pypi.org", ip("151.101.0.223")},
		{"pypi.org", ip("151.101.64.223")},
	}
	if !reflect.DeepEqual(hosts, wantHosts) {
		t.Errorf("hosts:\n got %v\nwant %v", hosts, wantHosts)
	}
}

func TestResolveErrors(t *testing.T) {
	r := fakeResolver{"v6.only": {netip.MustParseAddr("2a04:4e42::223")}}
	for _, entry := range []string{"v6.only:443", "missing.example:443", "[::1]:443", "1.2.3.4:0", "1.2.3.4:99999", "noport"} {
		if _, _, err := Resolve(context.Background(), []string{entry}, r); err == nil {
			t.Errorf("Resolve(%q): want error", entry)
		}
	}
}

// sample is "nft -j list table inet ringfence_a1" as nft 1.0.9 prints it:
// elements of concatenated sets are {"concat": [...]} objects, and the
// protocol is printed by name.
const sample = `{"nftables": [
 {"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}},
 {"table": {"family": "inet", "name": "ringfence_a1", "handle": 7}},
 {"set": {"family": "inet", "name": "allow4", "table": "ringfence_a1", "type": ["ipv4_addr", "inet_proto", "inet_service"], "handle": 1,
   "elem": [{"concat": ["93.184.216.34", "tcp", 443]}]}},
 {"set": {"family": "inet", "name": "seen_ok", "table": "ringfence_a1", "type": ["ipv4_addr", "inet_proto", "inet_service"], "handle": 2, "flags": ["dynamic"], "size": 4096,
   "elem": [{"concat": ["93.184.216.34", "tcp", 443]}]}},
 {"set": {"family": "inet", "name": "seen_denied", "table": "ringfence_a1", "type": ["ipv4_addr", "inet_proto", "inet_service"], "handle": 3, "flags": ["dynamic"], "size": 4096,
   "elem": [{"concat": ["10.213.0.1", "udp", 53]}, {"concat": ["1.1.1.1", "tcp", 22]}, {"elem": {"val": {"concat": ["8.8.8.8", "udp", 53]}, "expires": 12}}]}},
 {"set": {"family": "inet", "name": "seen_denied_other", "table": "ringfence_a1", "type": ["ipv4_addr", "inet_proto"], "handle": 4, "flags": ["dynamic"], "size": 4096,
   "elem": [{"concat": ["1.1.1.1", "icmp"]}, {"concat": ["9.9.9.9", 47]}]}},
 {"chain": {"family": "inet", "table": "ringfence_a1", "name": "fwd", "handle": 5, "type": "filter", "hook": "forward", "prio": -1, "policy": "accept"}}
]}`

func TestParseAttempts(t *testing.T) {
	got, err := parseAttempts([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	want := []sandbox.Connection{
		{Proto: "icmp", DstIP: "1.1.1.1"},
		{Proto: "tcp", DstIP: "1.1.1.1", DstPort: 22},
		{Proto: "udp", DstIP: "10.213.0.1", DstPort: 53},
		{Proto: "47", DstIP: "9.9.9.9"},
		{Proto: "tcp", DstIP: "93.184.216.34", DstPort: 443, Allowed: true},
		{Proto: "udp", DstIP: "8.8.8.8", DstPort: 53},
	}
	// Sorted by destination string, so compare as sets of rows.
	if len(got) != len(want) {
		t.Fatalf("got %d rows: %+v", len(got), got)
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			found = found || g == w
		}
		if !found {
			t.Errorf("missing %+v in %+v", w, got)
		}
	}
}

func TestParseAttemptsEmptyAndBad(t *testing.T) {
	got, err := parseAttempts([]byte(`{"nftables": [{"set": {"name": "seen_ok"}}]}`))
	if err != nil || len(got) != 0 {
		t.Errorf("empty set: %v, %v", got, err)
	}
	for _, bad := range []string{`not json`, `{"nftables":[{"set":{"name":"seen_ok","elem":[{"concat":["1.1.1.1"]}]}}]}`} {
		if _, err := parseAttempts([]byte(bad)); err == nil {
			t.Errorf("parseAttempts(%q): want error", bad)
		}
	}
}

func TestAttemptsUsesNft(t *testing.T) {
	old := runNft
	defer func() { runNft = old }()
	var args []string
	runNft = func(_ context.Context, _ string, a ...string) ([]byte, []byte, error) {
		args = a
		return []byte(sample), nil, nil
	}
	conns, err := Attempts(context.Background(), "ringfence_a1")
	if err != nil || len(conns) != 6 {
		t.Fatalf("%v %v", conns, err)
	}
	if got := strings.Join(args, " "); got != "-j list table inet ringfence_a1" {
		t.Errorf("args: %s", got)
	}
	if _, err := Attempts(context.Background(), "bad name"); err == nil {
		t.Error("want error for bad table")
	}
}

func TestDelete(t *testing.T) {
	old := runNft
	defer func() { runNft = old }()
	var args []string
	runNft = func(_ context.Context, _ string, a ...string) ([]byte, []byte, error) {
		args = a
		return nil, []byte("Error: Could not process rule: No such file or directory"), errors.New("exit status 1")
	}
	if err := Delete(context.Background(), "ringfence_a1"); err != nil {
		t.Errorf("missing table must be ignored: %v", err)
	}
	if got := strings.Join(args, " "); got != "delete table inet ringfence_a1" {
		t.Errorf("args: %s", got)
	}
	runNft = func(context.Context, string, ...string) ([]byte, []byte, error) {
		return nil, []byte("Operation not permitted"), errors.New("exit status 1")
	}
	if err := Delete(context.Background(), "ringfence_a1"); err == nil {
		t.Error("other errors must be reported")
	}
	if err := Delete(context.Background(), "x; y"); err == nil {
		t.Error("bad table name must be refused")
	}
}

func TestApplyPipesScript(t *testing.T) {
	old := runNft
	defer func() { runNft = old }()
	var in string
	var args []string
	runNft = func(_ context.Context, stdin string, a ...string) ([]byte, []byte, error) {
		in, args = stdin, a
		return nil, nil, nil
	}
	if err := Apply(context.Background(), "table inet x {}\n"); err != nil {
		t.Fatal(err)
	}
	if in != "table inet x {}\n" || strings.Join(args, " ") != "-f -" {
		t.Errorf("stdin %q args %v", in, args)
	}
}

func TestFindForwardDrop(t *testing.T) {
	docker := `{"nftables":[
	 {"chain":{"family":"ip","table":"filter","name":"FORWARD","handle":1,"type":"filter","hook":"forward","prio":0,"policy":"drop"}},
	 {"chain":{"family":"inet","table":"ringfence_a1","name":"fwd","type":"filter","hook":"forward","prio":-1,"policy":"drop"}}]}`
	blocked, why, err := findForwardDrop([]byte(docker))
	if err != nil || !blocked || !strings.Contains(why, "filter") {
		t.Errorf("docker case: %v %q %v", blocked, why, err)
	}
	clean := `{"nftables":[
	 {"chain":{"family":"ip","table":"filter","name":"FORWARD","type":"filter","hook":"forward","prio":0,"policy":"accept"}},
	 {"chain":{"family":"inet","table":"ringfence_a1","name":"fwd","type":"filter","hook":"forward","prio":-1,"policy":"drop"}},
	 {"chain":{"family":"ip","table":"filter","name":"INPUT","type":"filter","hook":"input","prio":0,"policy":"drop"}}]}`
	if blocked, _, err := findForwardDrop([]byte(clean)); err != nil || blocked {
		t.Errorf("clean case: %v %v", blocked, err)
	}
}

func TestCheckForwarding(t *testing.T) {
	old := ipForwardPath
	defer func() { ipForwardPath = old }()
	dir := t.TempDir()
	for content, wantErr := range map[string]bool{"1\n": false, "0\n": true} {
		p := filepath.Join(dir, "f")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		ipForwardPath = p
		if err := CheckForwarding(); (err != nil) != wantErr {
			t.Errorf("content %q: err=%v", content, err)
		}
	}
	ipForwardPath = filepath.Join(dir, "missing")
	if CheckForwarding() == nil {
		t.Error("missing file: want error")
	}
}
