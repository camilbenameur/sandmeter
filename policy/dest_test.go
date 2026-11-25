package policy

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

func mustDest(t *testing.T, s string) Dest {
	t.Helper()
	d, err := ParseDest(s)
	if err != nil {
		t.Fatalf("ParseDest(%q): %v", s, err)
	}
	return d
}

func TestParseDest(t *testing.T) {
	for in, want := range map[string]Dest{
		"pypi.org":                   {Host: "pypi.org", Port: 443},
		"pypi.org:443":               {Host: "pypi.org", Port: 443},
		"PyPI.Org.:443":              {Host: "pypi.org", Port: 443},
		"registry.npmjs.org:80":      {Host: "registry.npmjs.org", Port: 80},
		"*.pythonhosted.org":         {Host: "pythonhosted.org", Wildcard: true, Port: 443},
		"*.Files.PythonHosted.org:8": {Host: "files.pythonhosted.org", Wildcard: true, Port: 8},
		"localhost:8080":             {Host: "localhost", Port: 8080},
		"xn--bcher-kva.example:443":  {Host: "xn--bcher-kva.example", Port: 443},
		"a-b.c1.d:65535":             {Host: "a-b.c1.d", Port: 65535},
		"1e100.net":                  {Host: "1e100.net", Port: 443},
		"192.0.2.10":                 {Host: "192.0.2.10", Port: 443},
		"192.0.2.10:22":              {Host: "192.0.2.10", Port: 22},
		"192.0.2.10.:22":             {Host: "192.0.2.10", Port: 22},
		"ssh.example.com:443/raw":    {Host: "ssh.example.com", Port: 443, Transport: TransportRaw},
		"registry.example:8443/tls":  {Host: "registry.example", Port: 8443, Transport: TransportTLS},
		"*.example.com/raw":          {Host: "example.com", Wildcard: true, Port: 443, Transport: TransportRaw},
		// A label that looks like a number is a name wherever it is not the
		// last one, and "0x" needs hexadecimal digits after it to be one.
		"0x7f.example.com":  {Host: "0x7f.example.com", Port: 443},
		"127.0.0.1.nip.io":  {Host: "127.0.0.1.nip.io", Port: 443},
		"registry.0xyz:443": {Host: "registry.0xyz", Port: 443},
	} {
		got, err := ParseDest(in)
		if err != nil || got != want {
			t.Errorf("ParseDest(%q) = %+v, %v; want %+v", in, got, err, want)
			continue
		}
		again, err := ParseDest(got.String())
		if err != nil || again != got {
			t.Errorf("%q: canonical text %q reads back as %+v, %v", in, got.String(), again, err)
		}
	}
}

func TestParseDestRefuses(t *testing.T) {
	for name, in := range map[string]string{
		"empty":                    "",
		"only a port":              ":443",
		"only a dot":               ".",
		"only a wildcard":          "*.",
		"bare star":                "*",
		"star and port":            "*:443",
		"star in the middle":       "a.*.example.com",
		"star without dot":         "*example.com",
		"two stars":                "*.*.example.com",
		"wildcard on one label":    "*.com",
		"wildcard on an address":   "*.192.0.2.1",
		"port zero":                "example.com:0",
		"port too large":           "example.com:65536",
		"port with leading zero":   "example.com:0443",
		"port with sign":           "example.com:+443",
		"port empty":               "example.com:",
		"port not decimal":         "example.com:0x1bb",
		"port with space":          "example.com: 443",
		"port name":                "example.com:https",
		"two ports":                "example.com:443:443",
		"ipv6 in brackets":         "[2001:db8::1]:443",
		"ipv6 loopback":            "[::1]",
		"ipv6 bare":                "2001:db8::1",
		"ipv4 mapped":              "[::ffff:192.0.2.1]:443",
		"short address":            "127.1",
		"integer address":          "2130706433",
		"hex address":              "0x7f.0.0.1",
		"octal address":            "0177.0.0.1",
		"address with zero prefix": "192.0.2.010",
		"five fields":              "1.2.3.4.5",
		"numeric last label":       "example.123",
		"hex integer address":      "0x7f000001",
		"hex integer, upper case":  "0X7F000001",
		"hex last field":           "1.2.3.0x4",
		"hex first and last field": "0x7f.0.0.0x1",
		"metadata address in hex":  "169.254.169.0xfe:80",
		"hex last label of a name": "example.0x1f",
		"bare hex prefix":          "example.0x",
		"wildcard on a hex label":  "*.example.0x7f",
		"underscore":               "my_host.example.com",
		"leading hyphen":           "-a.example.com",
		"trailing hyphen":          "a-.example.com",
		"empty label":              "a..example.com",
		"two trailing dots":        "example.com..",
		"leading dot":              ".example.com",
		"label too long":           strings.Repeat("a", 64) + ".example.com",
		"name too long":            strings.Repeat("a.", 127) + "com",
		"far too long":             strings.Repeat("a", 4096),
		"space inside":             "exa mple.com",
		"leading space":            " example.com",
		"trailing newline":         "example.com\n",
		"tab":                      "example.com\t",
		"nul":                      "example.com\x00",
		"unicode name":             "bücher.example",
		"unicode dot":              "example。com",
		"fullwidth digits":         "example.com:４４３",
		"url":                      "https://example.com",
		"path":                     "example.com/index.html",
		"marker in upper case":     "example.com/TLS",
		"empty marker":             "example.com/",
		"two markers":              "example.com/tls/raw",
		"userinfo":                 "user@example.com",
		"query":                    "example.com?x=1",
		"percent encoding":         "example%2ecom",
		"backslash":                "example.com\\@evil.example",
	} {
		d, err := ParseDest(in)
		if err == nil {
			t.Errorf("%s: ParseDest(%q) accepted it as %+v", name, in, d)
			continue
		}
		if !errors.Is(err, ErrDest) {
			t.Errorf("%s: error %v is not ErrDest", name, err)
		}
		if len(in) > 3 && strings.Contains(err.Error(), in) {
			t.Errorf("%s: the error repeats the input: %v", name, err)
		}
	}
}

// TestSpellingsOfOneDestinationAreEqual is what lets a policy entry, a
// ceiling entry and a request be compared as values.
func TestSpellingsOfOneDestinationAreEqual(t *testing.T) {
	want := mustDest(t, "example.com:443")
	for _, in := range []string{"example.com", "EXAMPLE.COM", "Example.Com.", "example.com.:443", "example.com:443"} {
		if got := mustDest(t, in); got != want {
			t.Errorf("%q parses as %+v, want %+v", in, got, want)
		}
	}
	if mustDest(t, "example.com:443/tls") == want || mustDest(t, "example.com:443/raw") == want {
		t.Error("a marked entry equals an unmarked one")
	}
}

func TestRequiresTLS(t *testing.T) {
	for in, want := range map[string]bool{
		"example.com":          true,
		"example.com:443":      true,
		"example.com:443/tls":  true,
		"example.com:443/raw":  false,
		"example.com:80":       false,
		"example.com:8443":     false,
		"example.com:8443/tls": true,
		"example.com:80/raw":   false,
		"192.0.2.1":            true,
	} {
		if got := mustDest(t, in).RequiresTLS(); got != want {
			t.Errorf("%s: RequiresTLS = %v, want %v", in, got, want)
		}
	}
}

func TestMatches(t *testing.T) {
	for _, tc := range []struct {
		entry, target string
		want          bool
	}{
		{"pypi.org", "pypi.org:443", true},
		{"pypi.org", "PYPI.ORG.", true},
		{"pypi.org", "pypi.org:80", false},
		{"pypi.org", "www.pypi.org", false},
		{"pypi.org", "evilpypi.org", false},
		{"pypi.org", "pypi.org.evil.example", false},
		{"*.pythonhosted.org", "files.pythonhosted.org", true},
		{"*.pythonhosted.org", "a.b.pythonhosted.org", true},
		{"*.pythonhosted.org", "pythonhosted.org", false},
		{"*.pythonhosted.org", "evilpythonhosted.org", false},
		{"*.pythonhosted.org", "pythonhosted.org.evil.example", false},
		{"*.pythonhosted.org", "files.pythonhosted.org:8443", false},
		{"192.0.2.10:22", "192.0.2.10:22", true},
		{"192.0.2.10:22", "192.0.2.11:22", false},
		{"*.0.2.example", "192.0.2.10", false},
		{"example.com:443/raw", "example.com:443", true},
		{"example.com:8443/tls", "example.com:8443", true},
	} {
		if got := mustDest(t, tc.entry).Matches(mustDest(t, tc.target)); got != tc.want {
			t.Errorf("%s matches %s = %v, want %v", tc.entry, tc.target, got, tc.want)
		}
	}
	entry := mustDest(t, "*.example.com")
	if entry.Matches(mustDest(t, "*.a.example.com")) {
		t.Error("a wildcard was admitted as a request target")
	}
	if entry.Matches(Dest{}) || (Dest{}).Matches(mustDest(t, "example.com")) || (Dest{}).Matches(Dest{}) {
		t.Error("the zero Dest matches or is matched")
	}
	// A value that did not come from ParseDest is compared as it stands: an
	// unfolded name matches nothing.
	if mustDest(t, "example.com").Matches(Dest{Host: "EXAMPLE.COM", Port: 443}) {
		t.Error("an unparsed host was folded")
	}
}

func TestCovers(t *testing.T) {
	for _, tc := range []struct {
		ceiling, policy string
		want            bool
	}{
		{"pypi.org", "pypi.org", true},
		{"pypi.org", "pypi.org:80", false},
		{"pypi.org", "www.pypi.org", false},
		{"pypi.org", "*.pypi.org", false},
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "a.b.example.com", true},
		{"*.example.com", "*.example.com", true},
		{"*.example.com", "*.a.example.com", true},
		{"*.a.example.com", "*.example.com", false},
		{"*.example.com", "example.com", false},
		{"*.example.com", "badexample.com", false},
		{"*.example.com", "*.badexample.com", false},
		{"*.example.com", "a.example.com:80", false},
		{"192.0.2.1:22", "192.0.2.1:22", true},
		{"192.0.2.1:22", "192.0.2.2:22", false},
		{"*.0.2.example:22", "192.0.2.1:22", false},
		// The TLS check can be added by a policy and never removed by one.
		{"example.com:443", "example.com:443/raw", false},
		{"example.com:443/raw", "example.com:443/raw", true},
		{"example.com:443/raw", "example.com:443", true},
		{"example.com:443/raw", "example.com:443/tls", true},
		{"example.com:8443/tls", "example.com:8443", false},
		{"example.com:8443/tls", "example.com:8443/tls", true},
		{"example.com:8443", "example.com:8443/tls", true},
		{"example.com:8443", "example.com:8443/raw", true},
		{"*.example.com", "ssh.example.com:443/raw", false},
		{"*.example.com/raw", "ssh.example.com:443/raw", true},
	} {
		if got := mustDest(t, tc.ceiling).Covers(mustDest(t, tc.policy)); got != tc.want {
			t.Errorf("%s covers %s = %v, want %v", tc.ceiling, tc.policy, got, tc.want)
		}
	}
	if (Dest{}).Covers(Dest{}) || mustDest(t, "example.com").Covers(Dest{}) {
		t.Error("the zero Dest covers or is covered")
	}
}

// TestCoveredEntryAdmitsNothingMore checks Covers against Matches: whatever a
// covered policy entry admits, the ceiling entry admits too, and it is
// checked at least as strictly.
func TestCoveredEntryAdmitsNothingMore(t *testing.T) {
	entries := []string{
		"example.com", "example.com:80", "example.com:443/raw", "example.com:8443/tls",
		"*.example.com", "*.a.example.com", "*.example.com/raw", "*.example.com:80",
		"a.example.com", "b.a.example.com", "example.org", "*.example.org", "192.0.2.1", "192.0.2.1:80",
	}
	targets := []string{
		"example.com", "example.com:80", "example.com:8443", "a.example.com", "b.a.example.com", "c.b.a.example.com",
		"a.example.com:80", "example.org", "x.example.org", "192.0.2.1", "192.0.2.1:80", "badexample.com",
	}
	for _, c := range entries {
		for _, p := range entries {
			ceiling, pol := mustDest(t, c), mustDest(t, p)
			if !ceiling.Covers(pol) {
				continue
			}
			for _, tg := range targets {
				target := mustDest(t, tg)
				if pol.Matches(target) && !ceiling.Matches(target) {
					t.Errorf("%s covers %s, but only the second admits %s", c, p, tg)
				}
			}
			if ceiling.RequiresTLS() && !pol.RequiresTLS() {
				t.Errorf("%s covers %s, which drops its TLS check", c, p)
			}
		}
	}
}

func parseDests(t *testing.T, entries ...string) []Dest {
	t.Helper()
	out := make([]Dest, 0, len(entries))
	for _, e := range entries {
		out = append(out, mustDest(t, e))
	}
	return out
}

// TestUncoveredJudgesWholeLists is the check of a policy's allow list against
// a ceiling's. The first rows are the case that an entry-by-entry comparison
// gets wrong: every policy entry is covered by a ceiling entry, and the
// policy still decides one name more loosely than the ceiling does.
func TestUncoveredJudgesWholeLists(t *testing.T) {
	for _, tc := range []struct {
		name            string
		policy, ceiling []string
		want            []int
	}{
		{"a raw wildcard under a ceiling that checks one name below it",
			[]string{"*.example.com:443/raw"},
			[]string{"*.example.com:443/raw", "api.example.com:443"}, []int{0}},
		{"the same policy with the ceiling's stricter entry",
			[]string{"*.example.com:443/raw", "api.example.com:443"},
			[]string{"*.example.com:443/raw", "api.example.com:443"}, nil},
		{"a raw wildcard under a ceiling that checks a deeper wildcard",
			[]string{"*.example.com:443/raw"},
			[]string{"*.example.com:443/raw", "*.git.example.com:443"}, []int{0}},
		{"a raw name under a ceiling whose wildcard checks",
			[]string{"a.example.com:443/raw", "b.example.com"},
			[]string{"*.example.com"}, []int{0}},
		{"a raw name the ceiling's most specific entry leaves raw",
			[]string{"ssh.example.com:443/raw"},
			[]string{"*.example.com", "ssh.example.com:443/raw"}, nil},
		{"a policy stricter than the ceiling",
			[]string{"ssh.example.com:443", "*.example.com:8443/tls"},
			[]string{"*.example.com:443/raw", "*.example.com:8443"}, nil},
		{"a name the ceiling does not list",
			[]string{"pypi.org", "evil.example"},
			[]string{"pypi.org", "*.pythonhosted.org"}, []int{1}},
		{"another port",
			[]string{"pypi.org:80"},
			[]string{"pypi.org"}, []int{0}},
		{"a wildcard wider than the ceiling's",
			[]string{"*.example.com"},
			[]string{"*.a.example.com"}, []int{0}},
		{"a wildcard narrower than the ceiling's",
			[]string{"*.a.example.com", "b.a.example.com"},
			[]string{"*.example.com"}, nil},
		{"a wildcard where the ceiling lists names only",
			[]string{"*.example.com"},
			[]string{"a.example.com", "b.example.com", "c.example.com"}, []int{0}},
		{"the suffix itself is not under the wildcard",
			[]string{"example.com"},
			[]string{"*.example.com"}, []int{0}},
		{"an address",
			[]string{"192.0.2.1:22", "192.0.2.2:22"},
			[]string{"192.0.2.1:22", "*.0.2.example:22"}, []int{1}},
		{"an empty policy list", nil, []string{"pypi.org"}, nil},
		{"an empty ceiling list", []string{"pypi.org", "*.example.com"}, nil, []int{0, 1}},
		{"a policy entry that never decides is not held against the policy",
			[]string{"example.com:443/raw", "example.com:443"},
			[]string{"example.com:443"}, nil},
	} {
		got := Uncovered(parseDests(t, tc.policy...), parseDests(t, tc.ceiling...))
		if len(got) != len(tc.want) {
			t.Errorf("%s: Uncovered = %v, want %v", tc.name, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: Uncovered = %v, want %v", tc.name, got, tc.want)
				break
			}
		}
	}
	// What the first row shows: each entry is covered, the list is not.
	raw, strict := mustDest(t, "*.example.com:443/raw"), mustDest(t, "api.example.com:443")
	if !raw.Covers(raw) {
		t.Fatal("an entry does not cover itself")
	}
	api := mustDest(t, "api.example.com")
	inCeiling, _ := Find([]Dest{raw, strict}, api)
	inPolicy, _ := Find([]Dest{raw}, api)
	if !inCeiling.RequiresTLS() || inPolicy.RequiresTLS() {
		t.Errorf("the ceiling decides %s and the policy %s: the case this test is about is gone", inCeiling, inPolicy)
	}
	// The zero Dest is in no list: it is skipped, never matched.
	if got := Uncovered([]Dest{{}}, []Dest{{}}); len(got) != 0 {
		t.Errorf("zero entries: %v", got)
	}
}

// TestUncoveredAgreesWithFind draws lists from a small world of names and
// compares Uncovered with the definition it implements, evaluated request by
// request with Find over every name of that world.
func TestUncoveredAgreesWithFind(t *testing.T) {
	labels := []string{"a", "b", "example", "com"}
	var names []string
	var grow func(prefix string, depth int)
	grow = func(prefix string, depth int) {
		for _, l := range labels {
			name := l
			if prefix != "" {
				name = l + "." + prefix
			}
			names = append(names, name)
			if depth > 1 {
				grow(name, depth-1)
			}
		}
	}
	grow("", 4)
	var pool []Dest
	for _, n := range names {
		if strings.Count(n, ".") > 2 {
			continue
		}
		for _, suffix := range []string{"", ":80", ":443/raw", ":80/tls"} {
			pool = append(pool, mustDest(t, n+suffix))
			if strings.Contains(n, ".") {
				pool = append(pool, mustDest(t, "*."+n+suffix))
			}
		}
	}
	var targets []Dest
	for _, n := range names {
		targets = append(targets, mustDest(t, n), mustDest(t, n+":80"))
	}

	// A fixed sequence: the test is the same on every run.
	state := uint64(0x9e3779b97f4a7c15)
	next := func(n int) int {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		return int(state % uint64(n))
	}
	draw := func() []Dest {
		list := make([]Dest, next(5))
		for i := range list {
			list[i] = pool[next(len(pool))]
		}
		return list
	}
	position := func(list []Dest, d Dest) int {
		for i, e := range list {
			if e == d {
				return i
			}
		}
		return -1
	}
	refused := 0
	const rounds = 1500
	for round := 0; round < rounds; round++ {
		allow, ceiling := draw(), draw()
		if round%4 == 0 {
			// Lists that share entries are where the two decisions meet.
			allow = append(allow, ceiling...)
		}
		want := map[int]bool{}
		for _, target := range targets {
			pe, ok := Find(allow, target)
			if !ok {
				continue
			}
			ce, ok := Find(ceiling, target)
			if !ok || (ce.RequiresTLS() && !pe.RequiresTLS()) {
				want[position(allow, pe)] = true
			}
		}
		got := Uncovered(allow, ceiling)
		if len(got) > 0 {
			refused++
		}
		same := len(got) == len(want)
		for _, i := range got {
			same = same && want[i]
		}
		if !same {
			t.Fatalf("round %d: allow %v under ceiling %v: Uncovered = %v, request by request %v", round, allow, ceiling, got, want)
		}
	}
	if refused < rounds/8 || refused > rounds*7/8 {
		t.Errorf("%d of %d rounds were refused: the lists drawn do not exercise both answers", refused, rounds)
	}
}

// TestUncoveredOnLongLists holds the cost down: the policy text comes from a
// client, and the check runs in the root service.
func TestUncoveredOnLongLists(t *testing.T) {
	var allow, ceiling []Dest
	for i := 0; i < 20000; i++ {
		name := "h" + strconv.Itoa(i) + ".d" + strconv.Itoa(i%100) + ".example.com"
		allow = append(allow, Dest{Host: name, Port: 443}, Dest{Host: name, Wildcard: true, Port: 443})
		ceiling = append(ceiling, Dest{Host: "d" + strconv.Itoa(i%100) + ".example.com", Wildcard: true, Port: 443})
	}
	began := time.Now()
	if got := Uncovered(allow, ceiling); len(got) != 0 {
		t.Errorf("%d entries are not covered, the first at %d", len(got), got[0])
	}
	if d := time.Since(began); d > 5*time.Second {
		t.Errorf("checking %d entries against %d took %v", len(allow), len(ceiling), d)
	}
}

// TestUnclaimedUnder covers the search for a name that stands for "any other
// name under this suffix".
func TestUnclaimedUnder(t *testing.T) {
	ix := indexDests(parseDests(t, "a.example.com", "b.example.com", "a.example.com:80"))
	if name, ok := unclaimedUnder("example.com", 443, ix); !ok || name != "c.example.com" {
		t.Errorf("under example.com: %q, %v", name, ok)
	}
	if name, ok := unclaimedUnder("example.com", 80, ix); !ok || name != "b.example.com" {
		t.Errorf("under example.com on port 80: %q, %v", name, ok)
	}
	// A suffix with room for one more byte: 36 names exist under it. With
	// all of them named there is nothing left to stand for the rest.
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 59)
	if len(long) != 251 {
		t.Fatalf("the suffix is %d bytes long", len(long))
	}
	var all []Dest
	for _, c := range "abcdefghijklmnopqrstuvwxyz0123456789" {
		all = append(all, Dest{Host: string(c) + "." + long, Port: 443})
	}
	if name, ok := unclaimedUnder(long, 443, indexDests(all[:35])); !ok || name != "9."+long {
		t.Errorf("with one name left: %q, %v", name, ok)
	}
	if name, ok := unclaimedUnder(long, 443, indexDests(all)); ok {
		t.Errorf("with every name taken: %q", name)
	}
	if name, ok := unclaimedUnder(long+"ee", 443, indexDests(nil)); ok {
		t.Errorf("under a suffix of 253 bytes: %q", name)
	}
	// Two labels are tried once every single one is taken.
	var singles []Dest
	for _, c := range "abcdefghijklmnopqrstuvwxyz0123456789" {
		singles = append(singles, Dest{Host: string(c) + ".example.com", Port: 443})
	}
	if name, ok := unclaimedUnder("example.com", 443, indexDests(singles)); !ok || name != "aa.example.com" {
		t.Errorf("with every one-byte label taken: %q, %v", name, ok)
	}
}

func TestFindPicksTheMostSpecificEntry(t *testing.T) {
	parse := func(entries ...string) []Dest {
		var out []Dest
		for _, e := range entries {
			out = append(out, mustDest(t, e))
		}
		return out
	}
	allow := parse("*.example.com", "*.git.example.com/raw", "ssh.git.example.com:443/raw", "other.example:80")
	for target, want := range map[string]string{
		"www.example.com":       "*.example.com:443",
		"a.git.example.com":     "*.git.example.com:443/raw",
		"ssh.git.example.com":   "ssh.git.example.com:443/raw",
		"x.ssh.git.example.com": "*.git.example.com:443/raw",
		"other.example:80":      "other.example:80",
	} {
		got, ok := Find(allow, mustDest(t, target))
		if !ok || got.String() != want {
			t.Errorf("Find(%s) = %s, %v; want %s", target, got, ok, want)
		}
	}
	for _, target := range []string{"example.com", "other.example", "www.example.com:80", "192.0.2.1"} {
		if got, ok := Find(allow, mustDest(t, target)); ok {
			t.Errorf("Find(%s) = %s, want no entry", target, got)
		}
	}
	if _, ok := Find(nil, mustDest(t, "example.com")); ok {
		t.Error("an empty list admits a target")
	}

	// The order of the list does not change the answer, and of two entries
	// that differ only by their marker the one that checks TLS decides.
	a := parse("example.com:443/raw", "example.com:443")
	b := parse("example.com:443", "example.com:443/raw")
	for _, list := range [][]Dest{a, b} {
		got, ok := Find(list, mustDest(t, "example.com"))
		if !ok || !got.RequiresTLS() {
			t.Errorf("Find in %v = %s, %v; want the entry that requires TLS", list, got, ok)
		}
	}
}

func TestDestJSON(t *testing.T) {
	in := []Dest{mustDest(t, "*.example.com"), mustDest(t, "192.0.2.1:22/raw")}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if want := `["*.example.com:443","192.0.2.1:22/raw"]`; string(b) != want {
		t.Fatalf("encoded as %s, want %s", b, want)
	}
	var back []Dest
	if err := json.Unmarshal(b, &back); err != nil || len(back) != 2 || back[0] != in[0] || back[1] != in[1] {
		t.Fatalf("decoded as %+v, %v", back, err)
	}
	if err := json.Unmarshal([]byte(`["[::1]:443"]`), &back); err == nil {
		t.Error("an IPv6 destination was decoded")
	}
}

func FuzzParseDest(f *testing.F) {
	for _, s := range []string{"example.com", "*.example.com:8443/tls", "192.0.2.1:22/raw", "[::1]:443", "a..b", "*.com", "x:0", "0x7f000001", "1.2.3.0x4", strings.Repeat("a", 300)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, err := ParseDest(s)
		if err != nil {
			if d != (Dest{}) {
				t.Fatalf("ParseDest(%q) failed and returned %+v", s, d)
			}
			return
		}
		if d.Host == "" || d.Port == 0 || strings.ToLower(d.Host) != d.Host || strings.HasSuffix(d.Host, ".") || strings.ContainsAny(d.Host, "*:/ ") {
			t.Fatalf("ParseDest(%q) returned a Dest that is not normalised: %+v", s, d)
		}
		again, err := ParseDest(d.String())
		if err != nil || again != d {
			t.Fatalf("ParseDest(%q) = %+v, whose text %q reads back as %+v, %v", s, d, d.String(), again, err)
		}
		if d.IsAddr() && d.Wildcard {
			t.Fatalf("ParseDest(%q) returned a wildcard on an address", s)
		}
		// A name never ends in something an address parser takes for a
		// number.
		if last := d.Host[strings.LastIndexByte(d.Host, '.')+1:]; !d.IsAddr() && numericLabel(last) {
			t.Fatalf("ParseDest(%q) kept the name %q, whose last label is a number", s, d.Host)
		}
		// An exact entry admits itself and covers itself.
		if !d.Wildcard && (!d.Matches(d) || !d.Covers(d)) {
			t.Fatalf("%+v does not admit or cover itself", d)
		}
	})
}
