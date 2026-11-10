// Package image pulls OCI/Docker images and unpacks their layers into
// directories that can be used as overlayfs lower dirs.
//
// Layer tars are untrusted input. Every write goes through an os.Root opened
// on the destination, so a name or a symlink inside the layer cannot make the
// extractor touch anything outside it.
package image

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// WhiteoutMode selects what extraction does with OCI whiteout entries.
type WhiteoutMode int

const (
	// WhiteoutOverlay creates what overlayfs expects: a character device 0:0
	// for a deleted name and the trusted.overlay.opaque xattr for an opaque
	// directory. Both need root (CAP_MKNOD, CAP_SYS_ADMIN).
	WhiteoutOverlay WhiteoutMode = iota
	// WhiteoutRecord creates nothing and lists the whiteouts in the returned
	// stats. It works without privileges and is meant for tests and callers
	// that apply the deletions another way.
	WhiteoutRecord
)

// DefaultMaxBytes caps the bytes extracted from one layer when
// ExtractOptions.MaxBytes is zero.
const DefaultMaxBytes int64 = 8 << 30

const (
	opaqueMarker   = ".wh..wh..opq"
	whiteoutPrefix = ".wh."
	// aufsPrefix covers aufs bookkeeping entries such as .wh..wh.plnk.
	aufsPrefix  = ".wh..wh."
	opaqueXattr = "trusted.overlay.opaque"
	keptModes   = os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky
)

// errNUL is returned for tar names that contain a NUL byte.
var errNUL = errors.New("name contains NUL")

// ExtractOptions tunes ExtractLayer.
type ExtractOptions struct {
	// IDShift is added to every uid and gid. It is applied only when the
	// process runs as root; otherwise ownership is left alone.
	IDShift uint32
	// Whiteouts selects how whiteouts are materialized.
	Whiteouts WhiteoutMode
	// MaxBytes caps the total size of regular file content. Zero means
	// DefaultMaxBytes.
	MaxBytes int64
}

// ExtractStats counts what one extraction did.
type ExtractStats struct {
	Files     int
	Dirs      int
	Symlinks  int
	Hardlinks int
	Whiteouts int
	Opaques   int
	// Skipped lists entries that were not extracted, each with the reason.
	Skipped []string
	// WhiteoutPaths and OpaquePaths list, relative to the layer root, the
	// deleted names and the opaque directories seen. They are filled in both
	// modes so callers can inspect or re-apply them.
	WhiteoutPaths []string
	OpaquePaths   []string
	// OwnershipSkipped is true when ownership was not applied because the
	// process is not root.
	OwnershipSkipped bool
	// Bytes is the total regular file content written.
	Bytes int64
}

type dirMeta struct {
	name  string
	mode  os.FileMode
	uid   int
	gid   int
	mtime time.Time
}

type extractor struct {
	root     *os.Root
	opt      ExtractOptions
	maxBytes int64
	isRoot   bool
	stats    ExtractStats
	dirs     map[string]dirMeta
	times    map[string]time.Time
}

// ExtractLayer unpacks the uncompressed layer tar r into the existing
// directory dst.
func ExtractLayer(r io.Reader, dst string, opt ExtractOptions) (ExtractStats, error) {
	root, err := os.OpenRoot(dst)
	if err != nil {
		return ExtractStats{}, fmt.Errorf("open layer root: %w", err)
	}
	defer root.Close()

	e := &extractor{
		root:     root,
		opt:      opt,
		maxBytes: opt.MaxBytes,
		isRoot:   os.Geteuid() == 0,
		dirs:     map[string]dirMeta{},
		times:    map[string]time.Time{},
	}
	if e.maxBytes <= 0 {
		e.maxBytes = DefaultMaxBytes
	}
	e.stats.OwnershipSkipped = !e.isRoot

	// The destination is often a 0700 temp dir; the layer root must be
	// traversable by the container's non-root users.
	if err := root.Chmod(".", 0o755); err != nil {
		return e.stats, fmt.Errorf("chmod layer root: %w", err)
	}

	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return e.stats, fmt.Errorf("read tar: %w", err)
		}
		if err := e.entry(hdr, tr); err != nil {
			return e.stats, fmt.Errorf("extract %q: %w", hdr.Name, err)
		}
	}
	if err := e.finish(); err != nil {
		return e.stats, err
	}
	return e.stats, nil
}

func (e *extractor) skip(name, why string) {
	e.stats.Skipped = append(e.stats.Skipped, name+": "+why)
}

// cleanName turns a tar name into a path relative to the layer root. Absolute
// names become relative; names that climb above the root are rejected.
func cleanName(name string) (string, error) {
	if strings.IndexByte(name, 0) >= 0 {
		return "", errNUL
	}
	c := path.Clean(strings.TrimLeft(name, "/"))
	if c == ".." || strings.HasPrefix(c, "../") {
		return "", errors.New("path escapes the layer")
	}
	return c, nil
}

func (e *extractor) entry(hdr *tar.Header, body io.Reader) error {
	if strings.IndexByte(hdr.Linkname, 0) >= 0 {
		return errNUL
	}
	if hdr.Typeflag == tar.TypeXGlobalHeader {
		return nil
	}
	name, err := cleanName(hdr.Name)
	if errors.Is(err, errNUL) {
		return err
	}
	if err != nil {
		e.skip(hdr.Name, err.Error())
		return nil
	}
	if name != "." {
		if handled, err := e.whiteout(name, hdr); handled || err != nil {
			return err
		}
		if err := e.root.MkdirAll(path.Dir(name), 0o755); err != nil {
			return fmt.Errorf("create parents: %w", err)
		}
	}

	switch hdr.Typeflag {
	case tar.TypeDir:
		return e.dir(name, hdr)
	case tar.TypeReg, tar.TypeCont:
		return e.file(name, hdr, body)
	case tar.TypeSymlink:
		return e.symlink(name, hdr)
	case tar.TypeLink:
		return e.hardlink(name, hdr)
	case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
		e.skip(name, "device or fifo; the sandbox gets its own /dev")
	default:
		e.skip(name, fmt.Sprintf("unsupported tar type %q", hdr.Typeflag))
	}
	return nil
}

// whiteout handles ".wh." entries and reports whether hdr was one.
func (e *extractor) whiteout(name string, hdr *tar.Header) (bool, error) {
	dir, base := path.Dir(name), path.Base(name)
	if !strings.HasPrefix(base, whiteoutPrefix) {
		return false, nil
	}
	if base == opaqueMarker {
		return true, e.opaque(dir)
	}
	if strings.HasPrefix(base, aufsPrefix) {
		e.skip(name, "aufs bookkeeping entry")
		return true, nil
	}
	target := path.Join(dir, strings.TrimPrefix(base, whiteoutPrefix))
	return true, e.whiteoutName(dir, target, hdr)
}

func (e *extractor) opaque(dir string) error {
	if err := e.root.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create opaque dir: %w", err)
	}
	e.stats.Opaques++
	e.stats.OpaquePaths = append(e.stats.OpaquePaths, dir)
	if e.opt.Whiteouts != WhiteoutOverlay {
		return nil
	}
	// The xattr API has no root-relative form, so go through a descriptor
	// that os.Root resolved for us.
	f, err := e.root.Open(dir)
	if err != nil {
		return fmt.Errorf("open opaque dir: %w", err)
	}
	defer f.Close()
	if err := unix.Fsetxattr(int(f.Fd()), opaqueXattr, []byte("y"), 0); err != nil {
		return fmt.Errorf("set opaque xattr: %w", err)
	}
	return nil
}

func (e *extractor) whiteoutName(dir, target string, hdr *tar.Header) error {
	if err := e.root.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create whiteout parent: %w", err)
	}
	// A whiteout hides lower layers; anything this layer already put there
	// must go as well.
	if err := e.root.RemoveAll(target); err != nil {
		return fmt.Errorf("remove whited-out entry: %w", err)
	}
	e.stats.Whiteouts++
	e.stats.WhiteoutPaths = append(e.stats.WhiteoutPaths, target)
	if e.opt.Whiteouts != WhiteoutOverlay {
		return nil
	}
	parent, err := e.root.Open(dir)
	if err != nil {
		return fmt.Errorf("open whiteout parent: %w", err)
	}
	defer parent.Close()
	if err := unix.Mknodat(int(parent.Fd()), path.Base(target), unix.S_IFCHR, 0); err != nil {
		return fmt.Errorf("create whiteout device: %w", err)
	}
	return e.chown(target, hdr)
}

// replace removes an existing entry that cannot be overwritten in place.
func (e *extractor) replace(name string, keepDir bool) error {
	fi, err := e.root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if keepDir && fi.IsDir() {
		return nil
	}
	return e.root.RemoveAll(name)
}

func (e *extractor) ids(hdr *tar.Header) (uid, gid int, err error) {
	u := int64(hdr.Uid) + int64(e.opt.IDShift)
	g := int64(hdr.Gid) + int64(e.opt.IDShift)
	// 2^32-1 is the "no id" value for chown.
	if hdr.Uid < 0 || hdr.Gid < 0 || u >= 1<<32-1 || g >= 1<<32-1 {
		return 0, 0, fmt.Errorf("uid/gid %d/%d out of range after shift %d", hdr.Uid, hdr.Gid, e.opt.IDShift)
	}
	return int(u), int(g), nil
}

func (e *extractor) chown(name string, hdr *tar.Header) error {
	if !e.isRoot {
		return nil
	}
	uid, gid, err := e.ids(hdr)
	if err != nil {
		return err
	}
	if err := e.root.Lchown(name, uid, gid); err != nil {
		return fmt.Errorf("chown: %w", err)
	}
	return nil
}

func (e *extractor) dir(name string, hdr *tar.Header) error {
	if name != "." {
		if err := e.replace(name, true); err != nil {
			return err
		}
		if err := e.root.MkdirAll(name, 0o755); err != nil {
			return fmt.Errorf("mkdir: %w", err)
		}
	}
	uid, gid, err := e.ids(hdr)
	if err != nil {
		return err
	}
	// Mode, owner and time are applied in finish, children first, so a
	// read-only directory does not block its own contents.
	e.dirs[name] = dirMeta{
		name: name, mode: hdr.FileInfo().Mode() & keptModes,
		uid: uid, gid: gid, mtime: hdr.ModTime,
	}
	e.stats.Dirs++
	return nil
}

func (e *extractor) file(name string, hdr *tar.Header, body io.Reader) error {
	if hdr.Size < 0 || e.stats.Bytes+hdr.Size > e.maxBytes {
		return fmt.Errorf("layer exceeds the %d byte limit", e.maxBytes)
	}
	if err := e.replace(name, false); err != nil {
		return err
	}
	f, err := e.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	// Read one byte past the cap so a header that understates the size
	// cannot get around it.
	n, err := io.Copy(f, io.LimitReader(body, e.maxBytes-e.stats.Bytes+1))
	e.stats.Bytes += n
	if err == nil && e.stats.Bytes > e.maxBytes {
		err = fmt.Errorf("layer exceeds the %d byte limit", e.maxBytes)
	}
	if err == nil {
		err = e.finishFile(f, hdr)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	e.times[name] = hdr.ModTime
	e.stats.Files++
	return nil
}

func (e *extractor) finishFile(f *os.File, hdr *tar.Header) error {
	// Range-check ids even when not root so a bad layer fails the same way
	// for every caller.
	uid, gid, err := e.ids(hdr)
	if err != nil {
		return err
	}
	if e.isRoot {
		// chown clears setuid/setgid, so it must come before chmod.
		if err := f.Chown(uid, gid); err != nil {
			return fmt.Errorf("chown: %w", err)
		}
	}
	if err := f.Chmod(hdr.FileInfo().Mode() & keptModes); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	return nil
}

func (e *extractor) symlink(name string, hdr *tar.Header) error {
	if err := e.replace(name, false); err != nil {
		return err
	}
	// The target is stored verbatim and never resolved here. A symlink that
	// points outside is harmless until something follows it, and os.Root
	// refuses to follow it for the rest of this extraction.
	if err := e.root.Symlink(hdr.Linkname, name); err != nil {
		return fmt.Errorf("symlink: %w", err)
	}
	if err := e.chown(name, hdr); err != nil {
		return err
	}
	e.stats.Symlinks++
	return nil
}

func (e *extractor) hardlink(name string, hdr *tar.Header) error {
	target, err := cleanName(hdr.Linkname)
	if err != nil {
		e.skip(name, "hardlink target: "+err.Error())
		return nil
	}
	if err := e.replace(name, false); err != nil {
		return err
	}
	if err := e.root.Link(target, name); err != nil {
		return fmt.Errorf("hardlink to %q: %w", target, err)
	}
	e.stats.Hardlinks++
	return nil
}

// finish applies timestamps and directory metadata, deepest directories
// first so that a restrictive mode on a parent never blocks a child.
func (e *extractor) finish() error {
	for name, t := range e.times {
		if !t.IsZero() {
			// Best effort: timestamps are not part of the security contract.
			_ = e.root.Chtimes(name, t, t)
		}
	}
	list := make([]dirMeta, 0, len(e.dirs))
	for _, d := range e.dirs {
		list = append(list, d)
	}
	sort.Slice(list, func(i, j int) bool {
		di, dj := depth(list[i].name), depth(list[j].name)
		if di != dj {
			return di > dj
		}
		return list[i].name < list[j].name
	})
	for _, d := range list {
		if !d.mtime.IsZero() {
			_ = e.root.Chtimes(d.name, d.mtime, d.mtime)
		}
		if e.isRoot {
			if err := e.root.Lchown(d.name, d.uid, d.gid); err != nil {
				return fmt.Errorf("chown dir %q: %w", d.name, err)
			}
		}
		if err := e.root.Chmod(d.name, d.mode); err != nil {
			return fmt.Errorf("chmod dir %q: %w", d.name, err)
		}
	}
	return nil
}

func depth(n string) int {
	if n == "." {
		return 0
	}
	return strings.Count(n, "/") + 1
}
