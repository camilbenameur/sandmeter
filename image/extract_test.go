package image

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type ent struct {
	hdr  tar.Header
	body string
}

func dirE(name string, mode int64) ent {
	return ent{hdr: tar.Header{Typeflag: tar.TypeDir, Name: name, Mode: mode}}
}

func fileE(name, body string, mode int64) ent {
	return ent{hdr: tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: mode, Size: int64(len(body))}, body: body}
}

func linkE(name, target string) ent {
	return ent{hdr: tar.Header{Typeflag: tar.TypeSymlink, Name: name, Linkname: target, Mode: 0o777}}
}

func hardE(name, target string) ent {
	return ent{hdr: tar.Header{Typeflag: tar.TypeLink, Name: name, Linkname: target, Mode: 0o644}}
}

func buildTar(t *testing.T, ents ...ent) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range ents {
		h := e.hdr
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatalf("write header %q: %v", h.Name, err)
		}
		if e.body != "" {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(buf.Bytes())
}

// sandboxDirs returns a layer dir plus a sibling dir that must stay empty.
func sandboxDirs(t *testing.T) (dst, sibling string) {
	t.Helper()
	base := t.TempDir()
	dst = filepath.Join(base, "layer")
	sibling = filepath.Join(base, "outside")
	for _, d := range []string{dst, sibling} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dst, sibling
}

func assertEmpty(t *testing.T, dir string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Fatalf("%s should be empty, has %d entries (first: %s)", dir, len(ents), ents[0].Name())
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestExtractBasics(t *testing.T) {
	dst, sibling := sandboxDirs(t)
	stats, err := ExtractLayer(buildTar(t,
		dirE("etc/", 0o755),
		fileE("etc/hello", "hi", 0o640),
		fileE("bin/tool", "x", 0o4755),
		linkE("etc/abs", "/etc/passwd"),
		linkE("etc/rel", "hello"),
		hardE("etc/hard", "etc/hello"),
	), dst, ExtractOptions{Whiteouts: WhiteoutRecord})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Files != 2 || stats.Dirs != 1 || stats.Symlinks != 2 || stats.Hardlinks != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	if got := readFile(t, filepath.Join(dst, "etc/hello")); got != "hi" {
		t.Fatalf("content = %q", got)
	}
	if got := readFile(t, filepath.Join(dst, "etc/hard")); got != "hi" {
		t.Fatalf("hardlink content = %q", got)
	}
	if got, _ := os.Readlink(filepath.Join(dst, "etc/abs")); got != "/etc/passwd" {
		t.Fatalf("abs symlink target = %q", got)
	}
	fi, err := os.Stat(filepath.Join(dst, "bin/tool"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSetuid == 0 || fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode = %v, want setuid 0755", fi.Mode())
	}
	assertEmpty(t, sibling)
}

func TestExtractRootModeIsTraversable(t *testing.T) {
	dst := t.TempDir()
	if err := os.Chmod(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractLayer(buildTar(t, fileE("a", "1", 0o644)), dst, ExtractOptions{Whiteouts: WhiteoutRecord}); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(dst)
	if fi.Mode().Perm() != 0o755 {
		t.Fatalf("layer root mode = %v", fi.Mode().Perm())
	}
}

func TestExtractPathEscapes(t *testing.T) {
	dst, sibling := sandboxDirs(t)
	stats, err := ExtractLayer(buildTar(t,
		fileE("../outside/pwn", "x", 0o644),
		fileE("a/../../outside/pwn2", "x", 0o644),
		fileE("/abs/file", "abs", 0o644),
		fileE("/../outside/pwn3", "x", 0o644),
		hardE("h", "../outside/target"),
		hardE("h2", "/../../etc/passwd"),
	), dst, ExtractOptions{Whiteouts: WhiteoutRecord})
	if err != nil {
		t.Fatal(err)
	}
	assertEmpty(t, sibling)
	if got := readFile(t, filepath.Join(dst, "abs/file")); got != "abs" {
		t.Fatalf("absolute name content = %q", got)
	}
	if len(stats.Skipped) != 5 {
		t.Fatalf("skipped = %v, want 5 entries", stats.Skipped)
	}
	if _, err := os.Lstat(filepath.Join(dst, "h")); err == nil {
		t.Fatal("escaping hardlink was created")
	}
}

// archive/tar cannot write a NUL into a name and truncates it when reading,
// so the check is exercised on the header directly.
func TestExtractNULName(t *testing.T) {
	dst, _ := sandboxDirs(t)
	root, err := os.OpenRoot(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	e := &extractor{root: root, dirs: map[string]dirMeta{}, times: map[string]time.Time{}, maxBytes: 100}
	err = e.entry(&tar.Header{Typeflag: tar.TypeReg, Name: "a\x00b"}, bytes.NewReader(nil))
	if err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("err = %v, want NUL error", err)
	}
	err = e.entry(&tar.Header{Typeflag: tar.TypeSymlink, Name: "l", Linkname: "a\x00b"}, bytes.NewReader(nil))
	if err == nil {
		t.Fatal("NUL in link target accepted")
	}
	assertEmpty(t, dst)
}

func TestExtractSymlinkParentEscape(t *testing.T) {
	cases := map[string]string{
		"relative": "../outside",
		"deep":     "../../../../../../tmp",
		"absolute": "", // filled in below with the sibling path
	}
	for label, target := range cases {
		t.Run(label, func(t *testing.T) {
			dst, sibling := sandboxDirs(t)
			if target == "" {
				target = sibling
			}
			_, err := ExtractLayer(buildTar(t,
				linkE("link", target),
				fileE("link/evil", "pwn", 0o644),
			), dst, ExtractOptions{Whiteouts: WhiteoutRecord})
			if err == nil {
				t.Fatal("write through escaping symlink did not fail")
			}
			assertEmpty(t, sibling)
			if _, err := os.Lstat(filepath.Join(dst, "link")); err != nil {
				t.Fatalf("symlink itself should have been stored: %v", err)
			}
		})
	}
}

func TestExtractSymlinkDirEscape(t *testing.T) {
	dst, sibling := sandboxDirs(t)
	_, err := ExtractLayer(buildTar(t,
		linkE("link", "../outside"),
		dirE("link/sub", 0o755),
	), dst, ExtractOptions{Whiteouts: WhiteoutRecord})
	if err == nil {
		t.Fatal("mkdir through escaping symlink did not fail")
	}
	assertEmpty(t, sibling)
}

func TestExtractInTreeSymlinkIsFollowed(t *testing.T) {
	dst, sibling := sandboxDirs(t)
	_, err := ExtractLayer(buildTar(t,
		dirE("real", 0o755),
		linkE("alias", "real"),
		fileE("alias/f", "ok", 0o644),
	), dst, ExtractOptions{Whiteouts: WhiteoutRecord})
	if err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(dst, "real/f")); got != "ok" {
		t.Fatalf("content = %q", got)
	}
	assertEmpty(t, sibling)
}

func TestExtractOverwriteThroughSymlinkReplacesIt(t *testing.T) {
	// A regular file replacing a symlink must not write to the link target.
	dst, sibling := sandboxDirs(t)
	if err := os.WriteFile(filepath.Join(sibling, "victim"), []byte("safe"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := ExtractLayer(buildTar(t,
		linkE("f", "../outside/victim"),
		fileE("f", "new", 0o644),
	), dst, ExtractOptions{Whiteouts: WhiteoutRecord})
	if err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, filepath.Join(sibling, "victim")); got != "safe" {
		t.Fatalf("victim overwritten: %q", got)
	}
	if got := readFile(t, filepath.Join(dst, "f")); got != "new" {
		t.Fatalf("f = %q", got)
	}
}

func TestExtractWhiteoutsRecorded(t *testing.T) {
	dst, _ := sandboxDirs(t)
	stats, err := ExtractLayer(buildTar(t,
		fileE("d/gone", "x", 0o644),
		fileE("d/keep", "y", 0o644),
		fileE("d/.wh.gone", "", 0o644),
		fileE("d/.wh.absent", "", 0o644),
		fileE("opq/.wh..wh..opq", "", 0o644),
		fileE("opq/after", "z", 0o644),
		fileE("x/.wh..wh.plnk", "", 0o644),
	), dst, ExtractOptions{Whiteouts: WhiteoutRecord})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Whiteouts != 2 || stats.Opaques != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	if strings.Join(stats.WhiteoutPaths, ",") != "d/gone,d/absent" {
		t.Fatalf("whiteout paths = %v", stats.WhiteoutPaths)
	}
	if strings.Join(stats.OpaquePaths, ",") != "opq" {
		t.Fatalf("opaque paths = %v", stats.OpaquePaths)
	}
	if _, err := os.Lstat(filepath.Join(dst, "d/gone")); err == nil {
		t.Fatal("whited-out file still present in the same layer")
	}
	if _, err := os.Lstat(filepath.Join(dst, "d/.wh.gone")); err == nil {
		t.Fatal("whiteout marker file was created")
	}
	if _, err := os.Lstat(filepath.Join(dst, "d/keep")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dst, "opq/after")); err != nil {
		t.Fatal(err)
	}
	if len(stats.Skipped) != 1 {
		t.Fatalf("skipped = %v, want the aufs entry", stats.Skipped)
	}
}

func TestExtractDirModesAppliedLast(t *testing.T) {
	dst, _ := sandboxDirs(t)
	// The read-only parent is listed after its child, and a file arrives after
	// the read-only directory entry.
	stats, err := ExtractLayer(buildTar(t,
		dirE("ro/", 0o555),
		fileE("ro/inside", "x", 0o644),
		dirE("ro/sub/", 0o500),
		fileE("ro/sub/deep", "y", 0o644),
		dirE("sticky/", 0o1777),
	), dst, ExtractOptions{Whiteouts: WhiteoutRecord})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Join(dst, "ro"), 0o755)
		_ = os.Chmod(filepath.Join(dst, "ro/sub"), 0o755)
	})
	if stats.Dirs != 3 {
		t.Fatalf("stats = %+v", stats)
	}
	for p, want := range map[string]os.FileMode{
		"ro":     0o555,
		"ro/sub": 0o500,
	} {
		fi, err := os.Stat(filepath.Join(dst, p))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Fatalf("%s mode = %v, want %v", p, fi.Mode().Perm(), want)
		}
	}
	fi, err := os.Stat(filepath.Join(dst, "sticky"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSticky == 0 || fi.Mode().Perm() != 0o777 {
		t.Fatalf("sticky mode = %v", fi.Mode())
	}
}

func TestExtractDirAfterChildKeepsContents(t *testing.T) {
	dst, _ := sandboxDirs(t)
	_, err := ExtractLayer(buildTar(t,
		fileE("d/f", "x", 0o644),
		dirE("d/", 0o700),
	), dst, ExtractOptions{Whiteouts: WhiteoutRecord})
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(filepath.Join(dst, "d"))
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode = %v", fi.Mode().Perm())
	}
	if readFile(t, filepath.Join(dst, "d/f")) != "x" {
		t.Fatal("child lost")
	}
}

func TestExtractDevicesSkipped(t *testing.T) {
	dst, _ := sandboxDirs(t)
	stats, err := ExtractLayer(buildTar(t,
		ent{hdr: tar.Header{Typeflag: tar.TypeChar, Name: "dev/null", Devmajor: 1, Devminor: 3, Mode: 0o666}},
		ent{hdr: tar.Header{Typeflag: tar.TypeBlock, Name: "dev/sda", Devmajor: 8, Mode: 0o660}},
		ent{hdr: tar.Header{Typeflag: tar.TypeFifo, Name: "run/fifo", Mode: 0o600}},
		fileE("ok", "1", 0o644),
	), dst, ExtractOptions{Whiteouts: WhiteoutRecord})
	if err != nil {
		t.Fatal(err)
	}
	if len(stats.Skipped) != 3 || stats.Files != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	for _, p := range []string{"dev/null", "dev/sda", "run/fifo"} {
		if _, err := os.Lstat(filepath.Join(dst, p)); err == nil {
			t.Fatalf("%s was created", p)
		}
	}
}

func TestExtractSizeCap(t *testing.T) {
	dst, _ := sandboxDirs(t)
	_, err := ExtractLayer(buildTar(t,
		fileE("a", strings.Repeat("x", 600), 0o644),
		fileE("b", strings.Repeat("x", 600), 0o644),
	), dst, ExtractOptions{Whiteouts: WhiteoutRecord, MaxBytes: 1000})
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("err = %v, want size limit error", err)
	}
	// Exactly at the cap is fine.
	dst2, _ := sandboxDirs(t)
	if _, err := ExtractLayer(buildTar(t, fileE("a", strings.Repeat("x", 1000), 0o644)),
		dst2, ExtractOptions{Whiteouts: WhiteoutRecord, MaxBytes: 1000}); err != nil {
		t.Fatalf("at the cap: %v", err)
	}
}

func TestExtractReplacesAcrossTypes(t *testing.T) {
	dst, _ := sandboxDirs(t)
	_, err := ExtractLayer(buildTar(t,
		fileE("x", "file", 0o644),
		dirE("x/", 0o755),
		fileE("x/in", "i", 0o644),
		linkE("y", "x"),
		fileE("y", "now a file", 0o644),
	), dst, ExtractOptions{Whiteouts: WhiteoutRecord})
	if err != nil {
		t.Fatal(err)
	}
	if readFile(t, filepath.Join(dst, "x/in")) != "i" || readFile(t, filepath.Join(dst, "y")) != "now a file" {
		t.Fatal("replacement failed")
	}
}

func TestExtractMtime(t *testing.T) {
	dst, _ := sandboxDirs(t)
	ts := time.Unix(1_600_000_000, 0)
	e := fileE("f", "x", 0o644)
	e.hdr.ModTime = ts
	if _, err := ExtractLayer(buildTar(t, e), dst, ExtractOptions{Whiteouts: WhiteoutRecord}); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(filepath.Join(dst, "f"))
	if !fi.ModTime().Equal(ts) {
		t.Fatalf("mtime = %v", fi.ModTime())
	}
}

func TestExtractIDShiftOverflow(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("covered by the integration test when root")
	}
	dst, _ := sandboxDirs(t)
	e := fileE("f", "x", 0o644)
	e.hdr.Uid = 1 << 31
	stats, err := ExtractLayer(buildTar(t, e), dst, ExtractOptions{IDShift: 1 << 31, Whiteouts: WhiteoutRecord})
	// The range check runs even when chown is skipped, so a bad layer fails
	// the same way for root and non-root callers.
	if err == nil {
		t.Fatal("expected out-of-range error")
	}
	if !stats.OwnershipSkipped {
		t.Fatal("OwnershipSkipped should be set for non-root")
	}
}
