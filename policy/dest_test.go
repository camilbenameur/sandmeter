package policy

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
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
	for _, s := range []string{"example.com", "*.example.com:8443/tls", "192.0.2.1:22/raw", "[::1]:443", "a..b", "*.com", "x:0", strings.Repeat("a", 300)} {
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
		// An exact entry admits itself and covers itself.
		if !d.Wildcard && (!d.Matches(d) || !d.Covers(d)) {
			t.Fatalf("%+v does not admit or cover itself", d)
		}
	})
}
