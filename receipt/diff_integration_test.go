//go:build integration

package receipt

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDiffUpperWhiteout(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a character device")
	}
	lower, upper := t.TempDir(), t.TempDir()
	write(t, lower, "gone", "x")
	// An overlayfs whiteout is a character device with device number 0:0.
	if err := unix.Mknod(filepath.Join(upper, "gone"), unix.S_IFCHR|0o600, 0); err != nil {
		t.Fatal(err)
	}
	d, err := DiffUpper(upper, []string{lower}, 0)
	if err != nil {
		t.Fatal(err)
	}
	e := byPath(d)["gone|delete"]
	if e.Path != "gone" || e.Type != "file" {
		t.Errorf("whiteout entry = %+v (all: %+v)", e, d.Entries)
	}
}

func TestDiffUpperOpaque(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to set a trusted.* xattr")
	}
	lower, upper := t.TempDir(), t.TempDir()
	write(t, lower, "dir/old", "x")
	write(t, upper, "dir/new", "y")
	err := unix.Setxattr(filepath.Join(upper, "dir"), "trusted.overlay.opaque", []byte("y"), 0)
	if errors.Is(err, unix.ENOTSUP) {
		t.Skip("filesystem of the temp dir has no trusted xattr support")
	}
	if err != nil {
		t.Fatal(err)
	}
	d, err := DiffUpper(upper, []string{lower}, 0)
	if err != nil {
		t.Fatal(err)
	}
	m := byPath(d)
	if e, ok := m["dir|opaque"]; !ok || e.Type != "dir" {
		t.Errorf("no opaque entry: %+v", d.Entries)
	}
	if _, ok := m["dir/new|add"]; !ok {
		t.Errorf("dir/new missing: %+v", d.Entries)
	}
}
