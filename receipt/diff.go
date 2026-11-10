package receipt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"syscall"

	"golang.org/x/sys/unix"
)

// Diff is the change set of a writable overlay layer.
type Diff struct {
	// SHA256 is the hex sha256 of the canonical JSON (encoding/json, no
	// indentation) of Entries, with a nil slice encoded as [].
	SHA256    string  `json:"sha256"`
	Truncated bool    `json:"truncated"`
	Entries   []Entry `json:"entries"`
}

// Entry is one changed path. Path is slash separated and relative to the root.
type Entry struct {
	Path string `json:"path"`
	// Op is "add", "modify", "delete" or "opaque".
	Op string `json:"op"`
	// Type is "file", "dir", "symlink" or "other".
	Type   string `json:"type"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	// Target is a symlink target, verbatim. It is never resolved or opened.
	Target string `json:"target"`
}

const opaqueXattr = "trusted.overlay.opaque"

var errLimit = errors.New("entry limit reached")

type differ struct {
	upper  *os.Root
	lowers []*os.Root
	limit  int
	out    []Entry
}

// DiffUpper lists what an overlayfs upper directory changes over its lowers.
//
// The upper directory is controlled by the sandboxed program, so nothing here
// follows a symlink: all access goes through os.Root, entries are inspected
// with Lstat, symlinks are recorded with their target text and never opened,
// and only regular files are opened (O_NOFOLLOW, O_NONBLOCK, then checked
// again with fstat), so a FIFO cannot block the host.
//
// Rules, kept simple on purpose:
//   - A whiteout (character device 0:0) is a "delete" of that name.
//   - A non-directory is "modify" if its path exists in any lower, else "add".
//   - A directory is an entry only if it does not exist in any lower ("add"),
//     or replaces a non-directory ("modify"). Directories that exist in a
//     lower are walked but not listed.
//   - A directory with trusted.overlay.opaque=y gets an extra "opaque" entry.
//     The xattr is unreadable without privilege; that counts as not opaque.
//   - Existence in a lower uses Root.Lstat, so symlinks inside a lower are
//     followed within that lower and never escape it.
//
// Entries are sorted by Path (then Op). Walking stops after limit entries and
// sets Truncated; the kept set is the first entries in name order, so it is
// deterministic. A limit <= 0 means no limit.
func DiffUpper(upper string, lowers []string, limit int) (Diff, error) {
	u, err := os.OpenRoot(upper)
	if err != nil {
		return Diff{}, fmt.Errorf("open upper %q: %w", upper, err)
	}
	defer u.Close()

	d := &differ{upper: u, limit: limit}
	for _, l := range lowers {
		r, err := os.OpenRoot(l)
		if err != nil {
			return Diff{}, fmt.Errorf("open lower %q: %w", l, err)
		}
		defer r.Close()
		d.lowers = append(d.lowers, r)
	}

	truncated := false
	if err := d.walk("."); err != nil {
		if !errors.Is(err, errLimit) {
			return Diff{}, fmt.Errorf("walk upper %q: %w", upper, err)
		}
		truncated = true
	}

	entries := d.out
	if entries == nil {
		entries = []Entry{}
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Path != entries[j].Path {
			return entries[i].Path < entries[j].Path
		}
		return entries[i].Op < entries[j].Op
	})
	sum, err := entriesHash(entries)
	if err != nil {
		return Diff{}, err
	}
	return Diff{SHA256: sum, Truncated: truncated, Entries: entries}, nil
}

func entriesHash(entries []Entry) (string, error) {
	b, err := json.Marshal(entries)
	if err != nil {
		return "", fmt.Errorf("encode diff entries: %w", err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func (d *differ) emit(e Entry) error {
	if d.limit > 0 && len(d.out) >= d.limit {
		return errLimit
	}
	d.out = append(d.out, e)
	return nil
}

func (d *differ) walk(dir string) error {
	names, err := d.readDir(dir)
	if err != nil {
		return err
	}
	for _, name := range names {
		p := name
		if dir != "." {
			p = path.Join(dir, name)
		}
		if err := d.visit(p); err != nil {
			return err
		}
	}
	return nil
}

// readDir lists names in a directory of the upper, sorted. The directory is
// opened with O_NOFOLLOW|O_DIRECTORY so a racing swap for a symlink fails.
func (d *differ) readDir(dir string) ([]string, error) {
	f, err := d.upper.OpenFile(dir, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, fmt.Errorf("open dir %q: %w", dir, err)
	}
	defer f.Close()
	ents, err := f.ReadDir(-1)
	if err != nil {
		return nil, fmt.Errorf("read dir %q: %w", dir, err)
	}
	names := make([]string, len(ents))
	for i, e := range ents {
		names[i] = e.Name()
	}
	sort.Strings(names)
	return names, nil
}

func (d *differ) visit(p string) error {
	info, err := d.upper.Lstat(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil // removed while walking
		}
		return fmt.Errorf("lstat %q: %w", p, err)
	}
	st, _ := info.Sys().(*syscall.Stat_t)
	mode := uint32(info.Mode().Perm())
	if st != nil {
		mode = st.Mode & 0o7777
	}

	if info.Mode()&fs.ModeCharDevice != 0 && st != nil && st.Rdev == 0 {
		return d.visitWhiteout(p, mode)
	}

	lowerInfo, err := d.inLowers(p)
	if err != nil {
		return err
	}
	e := Entry{Path: p, Mode: mode, Type: typeOf(info.Mode()), Op: "add"}
	if lowerInfo != nil {
		e.Op = "modify"
	}

	switch e.Type {
	case "dir":
		return d.visitDir(p, e, lowerInfo)
	case "symlink":
		t, err := d.upper.Readlink(p)
		if err != nil {
			return fmt.Errorf("readlink %q: %w", p, err)
		}
		e.Target = t
	case "file":
		size, sum, err := d.hashFile(p)
		if err != nil {
			return err
		}
		e.Size, e.SHA256 = size, sum
	}
	return d.emit(e)
}

func (d *differ) visitWhiteout(p string, mode uint32) error {
	t := "other"
	if li, err := d.inLowers(p); err == nil && li != nil {
		t = typeOf(li.Mode())
	}
	return d.emit(Entry{Path: p, Op: "delete", Type: t, Mode: mode})
}

func (d *differ) visitDir(p string, e Entry, lowerInfo fs.FileInfo) error {
	if lowerInfo == nil || !lowerInfo.IsDir() {
		if err := d.emit(e); err != nil {
			return err
		}
	}
	if d.isOpaque(p) {
		op := e
		op.Op = "opaque"
		if err := d.emit(op); err != nil {
			return err
		}
	}
	return d.walk(p)
}

// isOpaque reads the opaque xattr through an fd, so no path is resolved again.
func (d *differ) isOpaque(p string) bool {
	f, err := d.upper.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 2)
	n, err := unix.Fgetxattr(int(f.Fd()), opaqueXattr, buf)
	// ENODATA, EPERM, ENOTSUP, ERANGE and the like all mean "not opaque".
	return err == nil && n == 1 && buf[0] == 'y'
}

// inLowers returns the Lstat result from the first lower holding p, or nil.
func (d *differ) inLowers(p string) (fs.FileInfo, error) {
	for _, l := range d.lowers {
		info, err := l.Lstat(p)
		if err == nil {
			return info, nil
		}
		if lowerMissing(err) {
			continue
		}
		return nil, fmt.Errorf("lstat lower %q: %w", p, err)
	}
	return nil, nil
}

// lowerMissing reports errors that mean "not present in this lower": absent,
// a parent that is not a directory, a symlink loop, or a symlink pointing
// outside the lower (os.Root refuses it, and we never follow it anyway).
func lowerMissing(err error) bool {
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ELOOP) {
		return true
	}
	var pe *fs.PathError
	return errors.As(err, &pe) && pe.Err.Error() == "path escapes from parent"
}

// hashFile streams a regular file through sha256 and counts its bytes.
// O_NONBLOCK keeps a FIFO swapped in after the Lstat from blocking open; the
// fstat check then refuses anything that is not a regular file.
func (d *differ) hashFile(p string) (int64, string, error) {
	f, err := d.upper.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return 0, "", fmt.Errorf("open %q: %w", p, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, "", fmt.Errorf("stat %q: %w", p, err)
	}
	if !fi.Mode().IsRegular() {
		return 0, "", fmt.Errorf("%q changed type while walking", p)
	}
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", fmt.Errorf("hash %q: %w", p, err)
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

func typeOf(m fs.FileMode) string {
	switch {
	case m.IsRegular():
		return "file"
	case m.IsDir():
		return "dir"
	case m&fs.ModeSymlink != 0:
		return "symlink"
	}
	return "other"
}
