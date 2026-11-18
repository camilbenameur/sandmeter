//go:build integration && linux

package kernelfacts

import (
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// The mount table of a process and directory trees: what the tests about
// mounts compare.

// mountEntry is one line of /proc/self/mountinfo, as far as the tests need it.
type mountEntry struct {
	point     string // mount point, unescaped
	options   string // per-mount options
	fstype    string
	source    string
	superOpts string // per-superblock options
}

// parseMountinfo reads the format of proc_pid_mountinfo(5): six fixed
// fields, optional fields, a hyphen, then type, source and super options.
func parseMountinfo(data string) []mountEntry {
	var out []mountEntry
	for _, line := range strings.Split(data, "\n") {
		left, right, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		l, r := strings.Fields(left), strings.Fields(right)
		if len(l) < 6 || len(r) < 2 {
			continue
		}
		e := mountEntry{point: unescapeMount(l[4]), options: l[5], fstype: r[0], source: r[1]}
		if len(r) > 2 {
			e.superOpts = r[2]
		}
		out = append(out, e)
	}
	return out
}

// unescapeMount undoes the octal escapes (\040 for a space) of mountinfo.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// mountinfoText is the mount table of this process's mount namespace.
func mountinfoText() string {
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "unreadable: " + err.Error()
	}
	return string(b)
}

// mountAt finds the mount at exactly this point. Of several stacked there,
// the last line is the one on top.
func mountAt(entries []mountEntry, point string) (mountEntry, bool) {
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].point == point {
			return entries[i], true
		}
	}
	return mountEntry{}, false
}

// mountHolding finds the mount a path lives on: the longest mount point
// that is a prefix of it.
func mountHolding(entries []mountEntry, path string) (mountEntry, bool) {
	best, found := mountEntry{}, false
	for _, e := range entries {
		under := e.point == "/" || path == e.point || strings.HasPrefix(path, e.point+"/")
		if under && len(e.point) >= len(best.point) {
			best, found = e, true
		}
	}
	return best, found
}

// fsTypeOf names the filesystem a path lives on, as mountinfo calls it
// ("ext4"); statfs alone cannot tell ext4 from ext2.
func fsTypeOf(path string) string {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "unknown (" + errnoName(err) + ")"
	}
	e, ok := mountHolding(parseMountinfo(mountinfoText()), real)
	if !ok {
		return "unknown (no mount holds " + real + ")"
	}
	return e.fstype
}

// overlayExtras keeps, of the super options of an overlay, the ones that are
// not directories: what the kernel says it applied.
func overlayExtras(superOpts string) string {
	var keep []string
	for _, o := range strings.Split(superOpts, ",") {
		if strings.HasPrefix(o, "lowerdir=") || strings.HasPrefix(o, "upperdir=") || strings.HasPrefix(o, "workdir=") {
			continue
		}
		keep = append(keep, o)
	}
	return strings.Join(keep, ",")
}

// lineDiff lists the lines that are in only one of two texts, "-" for the
// first and "+" for the second. It is empty when the texts have the same
// lines.
func lineDiff(a, b string) string {
	count := map[string]int{}
	for _, l := range strings.Split(a, "\n") {
		count[l]++
	}
	var out []string
	for _, l := range strings.Split(b, "\n") {
		if count[l] > 0 {
			count[l]--
			continue
		}
		out = append(out, "+"+l)
	}
	for _, l := range strings.Split(a, "\n") {
		if count[l] > 0 {
			count[l]--
			out = append(out, "-"+l)
		}
	}
	const most = 8
	if len(out) > most {
		out = append(out[:most], fmt.Sprintf("(and %d more lines)", len(out)-most))
	}
	return strings.Join(out, " ; ")
}

// tree describes a directory tree by path: "d" for a directory,
// "f:<content>" for a regular file, "l:<target>" for a symbolic link.
type tree map[string]string

// writeTree creates the tree under root, parents first.
func writeTree(root string, tr tree) error {
	for _, p := range slices.Sorted(maps.Keys(tr)) {
		full := filepath.Join(root, p)
		kind, body, _ := strings.Cut(tr[p], ":")
		var err error
		switch kind {
		case "d":
			err = os.MkdirAll(full, 0o755)
		case "f":
			if err = os.MkdirAll(filepath.Dir(full), 0o755); err == nil {
				err = os.WriteFile(full, []byte(body), 0o644)
			}
		case "l":
			err = os.Symlink(body, full)
		default:
			err = fmt.Errorf("unknown entry kind %q for %s", kind, p)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// readTree reads back what is under root. An entry that cannot be read is
// kept, with the errno in place of its content: an anomaly must show in the
// comparison, not end it.
func readTree(root string) tree {
	out := tree{}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		rel, _ := filepath.Rel(root, path)
		if rel == "." {
			if err != nil {
				out["."] = "error:" + errnoName(err)
			}
			return nil
		}
		if err != nil {
			out[rel] = "error:" + errnoName(err)
			return nil
		}
		switch {
		case d.IsDir():
			out[rel] = "d"
		case d.Type() == fs.ModeSymlink:
			target, err := os.Readlink(path)
			if err != nil {
				target = "error:" + errnoName(err)
			}
			out[rel] = "l:" + target
		case d.Type().IsRegular():
			b, err := os.ReadFile(path)
			if err != nil {
				out[rel] = "error:" + errnoName(err)
				return nil
			}
			out[rel] = "f:" + string(b)
		default:
			out[rel] = "other:" + d.Type().String()
		}
		return nil
	})
	return out
}

// diffTrees says how got differs from want. It is empty when they are equal.
func diffTrees(want, got tree) string {
	keys := map[string]bool{}
	for k := range want {
		keys[k] = true
	}
	for k := range got {
		keys[k] = true
	}
	var out []string
	for _, k := range slices.Sorted(maps.Keys(keys)) {
		w, inWant := want[k]
		g, inGot := got[k]
		switch {
		case !inGot:
			out = append(out, fmt.Sprintf("%s: expected %q, found nothing", k, w))
		case !inWant:
			out = append(out, fmt.Sprintf("%s: expected nothing, found %q", k, g))
		case w != g:
			out = append(out, fmt.Sprintf("%s: expected %q, found %q", k, w, g))
		}
	}
	return strings.Join(out, "; ")
}
