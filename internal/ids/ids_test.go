package ids

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewRoundTrips(t *testing.T) {
	seen := map[ID]bool{}
	for range 64 {
		id, err := New()
		if err != nil {
			t.Fatal(err)
		}
		if id.IsZero() || seen[id] {
			t.Fatalf("New returned %s: zero or repeated", id)
		}
		seen[id] = true
		s := id.String()
		if len(s) != 32 || strings.ToLower(s) != s {
			t.Fatalf("text form %q is not 32 lower-case characters", s)
		}
		back, err := Parse(s)
		if err != nil || back != id {
			t.Fatalf("Parse(%q) = %v, %v", s, back, err)
		}
	}
}

func TestParseRefuses(t *testing.T) {
	good := "0123456789abcdef0123456789abcdef"
	if _, err := Parse(good); err != nil {
		t.Fatalf("Parse(%q): %v", good, err)
	}
	for name, in := range map[string]string{
		"empty":            "",
		"short":            good[:31],
		"long":             good + "0",
		"upper case":       strings.ToUpper(good),
		"one upper letter": "0123456789abcdeF0123456789abcdef",
		"not hex":          "0123456789abcdeg0123456789abcdef",
		"dot segments":     "../../../../../../../../../../etc",
		"slash":            "0123456789abcdef/123456789abcdef",
		"nul":              "0123456789abcdef\x00123456789abcdef",
		"leading space":    " 123456789abcdef0123456789abcdef",
		"newline":          "0123456789abcdef0123456789abcde\n",
		"prefix":           "0x23456789abcdef0123456789abcdef",
		"zero":             strings.Repeat("0", 32),
		"percent encoding": "%2e%2e%2f%2e%2e%2fetc%2fpasswd00",
		"non-ascii digits": "٠١٢٣٤٥٦٧٨٩abcdef01234567",
	} {
		id, err := Parse(in)
		if err == nil {
			t.Errorf("%s: Parse(%q) accepted it as %s", name, in, id)
			continue
		}
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: error %v is not ErrInvalid", name, err)
		}
		if len(in) > 8 && strings.Contains(err.Error(), in) {
			t.Errorf("%s: the error echoes the input: %v", name, err)
		}
	}
}

// TestTextFormIsOnePathComponent states the invariant the callers rely on
// when they name a directory after an ID.
func TestTextFormIsOnePathComponent(t *testing.T) {
	for range 32 {
		id, err := New()
		if err != nil {
			t.Fatal(err)
		}
		s := id.String()
		if filepath.Base(s) != s || filepath.Clean(s) != s || !filepath.IsLocal(s) || strings.ContainsAny(s, "/\\.\x00") {
			t.Fatalf("%q is not a plain path component", s)
		}
	}
}

func TestJSON(t *testing.T) {
	type msg struct {
		Session ID `json:"session"`
		Other   ID `json:"other,omitzero"`
	}
	id, err := Parse("00000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(msg{Session: id})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"session":"00000000000000000000000000000001"}`; string(b) != want {
		t.Fatalf("encoded as %s, want %s", b, want)
	}
	var back msg
	if err := json.Unmarshal(b, &back); err != nil || back.Session != id || !back.Other.IsZero() {
		t.Fatalf("decoded %+v, %v", back, err)
	}

	if _, err := json.Marshal(msg{}); err == nil {
		t.Error("a zero ID in a required field was encoded")
	}
	for _, in := range []string{
		`{"session":"../../etc"}`,
		`{"session":""}`,
		`{"session":"00000000000000000000000000000000"}`,
		`{"session":42}`,
		`{"session":"` + strings.Repeat("a", 1<<16) + `"}`,
	} {
		var m msg
		if err := json.Unmarshal([]byte(in), &m); err == nil {
			t.Errorf("decoded %.40s as %s", in, m.Session)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add("0123456789abcdef0123456789abcdef")
	f.Add("../../etc/passwd")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		id, err := Parse(s)
		if err != nil {
			return
		}
		if id.String() != s {
			t.Fatalf("Parse(%q) accepted a second spelling of %s", s, id)
		}
	})
}
