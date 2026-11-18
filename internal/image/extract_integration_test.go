//go:build integration

package image

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
}

func TestIntegrationOverlayWhiteouts(t *testing.T) {
	requireRoot(t)
	dst, _ := sandboxDirs(t)
	stats, err := ExtractLayer(buildTar(t,
		fileE("d/.wh.gone", "", 0o644),
		fileE("opq/.wh..wh..opq", "", 0o644),
		fileE("opq/f", "x", 0o644),
	), dst, ExtractOptions{Whiteouts: WhiteoutOverlay})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Whiteouts != 1 || stats.Opaques != 1 {
		t.Fatalf("stats = %+v", stats)
	}

	fi, err := os.Lstat(filepath.Join(dst, "d/gone"))
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if fi.Mode()&os.ModeCharDevice == 0 || st.Rdev != 0 {
		t.Fatalf("whiteout is %v rdev %d, want char device 0:0", fi.Mode(), st.Rdev)
	}

	buf := make([]byte, 8)
	n, err := unix.Getxattr(filepath.Join(dst, "opq"), "trusted.overlay.opaque", buf)
	if err != nil {
		// tmpfs before kernel 6.6 refuses trusted.* xattrs; the failure would
		// then come from extraction itself, so reaching here is a real miss.
		t.Fatalf("getxattr: %v", err)
	}
	if string(buf[:n]) != "y" {
		t.Fatalf("opaque xattr = %q", buf[:n])
	}
}

func TestIntegrationIDShift(t *testing.T) {
	requireRoot(t)
	dst, _ := sandboxDirs(t)
	f := fileE("d/f", "x", 0o4755)
	f.hdr.Uid, f.hdr.Gid = 1000, 100
	d := dirE("d/", 0o755)
	d.hdr.Uid, d.hdr.Gid = 5, 6
	l := linkE("d/l", "f")
	l.hdr.Uid, l.hdr.Gid = 7, 8

	const shift = 100000
	if _, err := ExtractLayer(buildTar(t, d, f, l), dst, ExtractOptions{IDShift: shift, Whiteouts: WhiteoutRecord}); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string][2]uint32{
		"d":   {shift + 5, shift + 6},
		"d/f": {shift + 1000, shift + 100},
		"d/l": {shift + 7, shift + 8},
	} {
		fi, err := os.Lstat(filepath.Join(dst, p))
		if err != nil {
			t.Fatal(err)
		}
		st := fi.Sys().(*syscall.Stat_t)
		if st.Uid != want[0] || st.Gid != want[1] {
			t.Errorf("%s owner = %d:%d, want %d:%d", p, st.Uid, st.Gid, want[0], want[1])
		}
	}
	// chown must not have stripped setuid: the mode is applied afterwards.
	fi, _ := os.Stat(filepath.Join(dst, "d/f"))
	if fi.Mode()&os.ModeSetuid == 0 {
		t.Errorf("setuid lost: %v", fi.Mode())
	}
}
