package receipt

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func byPath(d Diff) map[string]Entry {
	m := map[string]Entry{}
	for _, e := range d.Entries {
		m[e.Path+"|"+e.Op] = e
	}
	return m
}

func TestDiffUpperAddModify(t *testing.T) {
	lower, upper := t.TempDir(), t.TempDir()
	write(t, lower, "etc/conf", "old")
	write(t, lower, "keep/x", "x")
	write(t, upper, "etc/conf", "new!")
	write(t, upper, "new/deep/file", "hello")
	write(t, upper, "keep/added", "a")

	d, err := DiffUpper(upper, []string{t.TempDir(), lower}, 0)
	if err != nil {
		t.Fatal(err)
	}
	m := byPath(d)
	if e := m["etc/conf|modify"]; e.Type != "file" || e.Size != 4 || e.SHA256 == "" {
		t.Errorf("etc/conf = %+v", e)
	}
	if e := m["new/deep/file|add"]; e.Size != 5 {
		t.Errorf("new/deep/file = %+v", e)
	}
	if _, ok := m["new|add"]; !ok {
		t.Error("new dir not listed")
	}
	if _, ok := m["new/deep|add"]; !ok {
		t.Error("new/deep dir not listed")
	}
	if _, ok := m["etc|add"]; ok {
		t.Error("etc exists in a lower and must not be listed")
	}
	if _, ok := m["keep/added|add"]; !ok {
		t.Error("keep/added missing")
	}
	for i := 1; i < len(d.Entries); i++ {
		if d.Entries[i-1].Path > d.Entries[i].Path {
			t.Fatal("entries not sorted")
		}
	}
}

func TestDiffUpperSymlinkNotFollowed(t *testing.T) {
	upper := t.TempDir()
	host := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(host, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	must(t, os.Symlink(host, filepath.Join(upper, "abs")))
	must(t, os.Symlink("/nonexistent/path", filepath.Join(upper, "dangling")))
	must(t, os.Symlink("loop2", filepath.Join(upper, "loop1")))
	must(t, os.Symlink("loop1", filepath.Join(upper, "loop2")))
	must(t, os.Symlink("../..", filepath.Join(upper, "dirlink")))

	d, err := DiffUpper(upper, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	m := byPath(d)
	cases := map[string]string{"abs": host, "dangling": "/nonexistent/path", "loop1": "loop2", "loop2": "loop1", "dirlink": "../.."}
	for name, target := range cases {
		e, ok := m[name+"|add"]
		if !ok || e.Type != "symlink" || e.Target != target {
			t.Errorf("%s = %+v", name, e)
		}
		// A followed link would have produced a size or a hash.
		if e.SHA256 != "" || e.Size != 0 {
			t.Errorf("%s was read: %+v", name, e)
		}
	}
	if len(d.Entries) != len(cases) {
		t.Errorf("dirlink was walked: %d entries", len(d.Entries))
	}
}

func TestDiffUpperFIFODoesNotBlock(t *testing.T) {
	upper := t.TempDir()
	must(t, syscall.Mkfifo(filepath.Join(upper, "pipe"), 0o600))

	done := make(chan struct{})
	var d Diff
	var err error
	go func() {
		d, err = DiffUpper(upper, nil, 0)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("DiffUpper blocked on a FIFO")
	}
	if err != nil {
		t.Fatal(err)
	}
	e := byPath(d)["pipe|add"]
	if e.Type != "other" || e.SHA256 != "" {
		t.Errorf("pipe = %+v", e)
	}
}

func TestDiffUpperLimit(t *testing.T) {
	upper := t.TempDir()
	for _, n := range []string{"a", "b", "c", "d"} {
		write(t, upper, n, n)
	}
	d, err := DiffUpper(upper, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Truncated || len(d.Entries) != 2 || d.Entries[0].Path != "a" || d.Entries[1].Path != "b" {
		t.Errorf("diff = %+v", d)
	}
	d, err = DiffUpper(upper, nil, 4)
	if err != nil || d.Truncated || len(d.Entries) != 4 {
		t.Errorf("exact limit: %+v, %v", d, err)
	}
}

func TestDiffUpperDeterministic(t *testing.T) {
	upper := t.TempDir()
	write(t, upper, "z/a", "1")
	write(t, upper, "b", "2")
	d1, err := DiffUpper(upper, nil, 0)
	must(t, err)
	d2, err := DiffUpper(upper, nil, 0)
	must(t, err)
	if d1.SHA256 == "" || d1.SHA256 != d2.SHA256 {
		t.Errorf("hash differs: %q %q", d1.SHA256, d2.SHA256)
	}
	write(t, upper, "b", "3")
	d3, err := DiffUpper(upper, nil, 0)
	must(t, err)
	if d3.SHA256 == d1.SHA256 {
		t.Error("hash ignores content")
	}
}

func TestDiffUpperEmpty(t *testing.T) {
	d, err := DiffUpper(t.TempDir(), nil, 0)
	if err != nil || d.Entries == nil || len(d.Entries) != 0 || d.SHA256 == "" {
		t.Errorf("empty diff = %+v, %v", d, err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
