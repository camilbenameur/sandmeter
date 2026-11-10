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
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

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

	// PathEscaped and TargetEscaped are set when the name or link target is
	// not valid UTF-8. JSON would silently replace the bad bytes, so two
	// different names could collide in the signed record. The field then holds
	// the strconv.Quote form (\xff style escapes) instead of the raw bytes.
	PathEscaped   bool `json:"path_escaped,omitempty"`
	TargetEscaped bool `json:"target_escaped,omitempty"`

	// Skipped is empty for a normal entry. Otherwise the entry is recorded
	// without content: "unreadable" (permission error, type swapped during
	// the walk, I/O error) or "too_large" (over the hashing budget). A
	// hostile program must not be able to suppress the diff by making one
	// entry hard to read, so such entries are listed instead of failing.
	Skipped string `json:"skipped,omitempty"`
}

// Overlayfs stores the opaque marker as a trusted.* xattr for mounts made by
// root, and as user.* for mounts made from an unprivileged user namespace
// (the "userxattr" mount option).
var opaqueXattrs = []string{"trusted.overlay.opaque", "user.overlay.opaque"}

// Hashing budgets. They bound the I/O a hostile upper layer can cost the host
// (for example a sparse multi-exabyte file). Variables so tests can lower them.
var (
	maxFileBytes  int64 = 1 << 30
	maxTotalBytes int64 = 8 << 30
)

var errLimit = errors.New("entry limit reached")

type differ struct {
	upper  *os.Root
	lowers []*os.Root
	limit  int
	out    []Entry

	hashed    int64 // bytes read so far, against maxTotalBytes
	truncated bool  // set when a hashing budget was exceeded
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
//   - A directory with trusted.overlay.opaque=y (or user.overlay.opaque=y, used
//     by userns mounts) gets an extra "opaque" entry. An unreadable xattr
//     counts as not opaque. Paths below an opaque directory are still compared
//     with the lowers by name, so they can read "modify" although overlayfs
//     hides the lower content; the opaque entry is the signal for that.
//   - Existence in a lower is checked one path component at a time with
//     Lstat. Like overlayfs, a lower symlink or file in the middle of a path
//     means "not present" (an upper directory shadows it); no symlink is ever
//     followed, so none can point outside the lower.
//   - Per-entry failures (unreadable, type swapped, over the hashing budget)
//     produce an entry with Skipped set; only failing to open the roots is an
//     error. Names or targets that are not valid UTF-8 are stored quoted, with
//     PathEscaped/TargetEscaped set.
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
	if err := d.walkRoot(); err != nil {
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
	return Diff{SHA256: sum, Truncated: truncated || d.truncated, Entries: entries}, nil
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
	if !utf8.ValidString(e.Path) {
		e.Path, e.PathEscaped = strconv.Quote(e.Path), true
	}
	if !utf8.ValidString(e.Target) {
		e.Target, e.TargetEscaped = strconv.Quote(e.Target), true
	}
	d.out = append(d.out, e)
	return nil
}

// walkRoot is the only place a directory failure is fatal.
func (d *differ) walkRoot() error {
	names, err := d.readDir(".")
	if err != nil {
		return err
	}
	return d.walk(".", names)
}

func (d *differ) walk(dir string, names []string) error {
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
		return d.emit(Entry{Path: p, Op: "add", Type: "other", Skipped: "unreadable"})
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
			e.Skipped = "unreadable"
		}
		e.Target = t
	case "file":
		e.Size, e.SHA256, e.Skipped = d.hashFile(p)
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
	names, rerr := d.readDir(p)
	if rerr != nil {
		// Always list a directory we could not enter, even one that exists
		// in a lower, so its unseen content is not silently omitted.
		e.Skipped = "unreadable"
		return d.emit(e)
	}
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
	return d.walk(p, names)
}

// isOpaque reads the opaque xattrs through an fd, so no path is resolved again.
func (d *differ) isOpaque(p string) bool {
	f, err := d.upper.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 2)
	for _, name := range opaqueXattrs {
		n, err := unix.Fgetxattr(int(f.Fd()), name, buf)
		// ENODATA, EPERM, ENOTSUP, ERANGE and the like all mean "not opaque".
		if err == nil && n == 1 && buf[0] == 'y' {
			return true
		}
	}
	return false
}

// inLowers returns the Lstat result from the first lower holding p, or nil.
func (d *differ) inLowers(p string) (fs.FileInfo, error) {
	for _, l := range d.lowers {
		info, err := lowerLstat(l, p)
		if err == nil {
			return info, nil
		}
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		return nil, fmt.Errorf("lstat lower %q: %w", p, err)
	}
	return nil, nil
}

// lowerLstat is Lstat that treats a non-directory parent as "not present".
// Lstat on every prefix means no symlink is ever traversed: a lower holding
// an absolute link such as var/run -> /run would otherwise make os.Root fail
// with "path escapes from parent", and a relative one would be followed,
// both giving the wrong add/modify answer.
func lowerLstat(l *os.Root, p string) (fs.FileInfo, error) {
	parts := strings.Split(p, "/")
	var info fs.FileInfo
	for i := range parts {
		var err error
		info, err = l.Lstat(strings.Join(parts[:i+1], "/"))
		if err != nil {
			if errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ELOOP) {
				return nil, fs.ErrNotExist
			}
			return nil, err
		}
		if i < len(parts)-1 && !info.IsDir() {
			return nil, fs.ErrNotExist
		}
	}
	return info, nil
}

// hashFile streams a regular file through sha256 and counts its bytes.
// O_NONBLOCK keeps a FIFO swapped in after the Lstat from blocking open; the
// fstat check then refuses anything that is not a regular file. It never
// fails the diff: the last result is "" on success, else the Skipped marker.
// The size is checked against the budgets before reading, so a sparse file
// of absurd length costs nothing.
func (d *differ) hashFile(p string) (int64, string, string) {
	f, err := d.upper.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return 0, "", "unreadable"
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return 0, "", "unreadable"
	}
	room := min(maxFileBytes, maxTotalBytes-d.hashed)
	if fi.Size() > room {
		d.truncated = true
		return fi.Size(), "", "too_large"
	}
	h := sha256.New()
	// One extra byte detects a file that grew past the budget while reading.
	n, err := io.Copy(h, io.LimitReader(f, room+1))
	d.hashed += n
	if err != nil {
		return 0, "", "unreadable"
	}
	if n > room {
		d.truncated = true
		return fi.Size(), "", "too_large"
	}
	return n, hex.EncodeToString(h.Sum(nil)), ""
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
