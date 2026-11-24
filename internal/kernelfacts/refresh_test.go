//go:build integration && linux

package kernelfacts

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The refresh of the project between two commands.
//
// The workspace overlay is mounted for the length of one command. Between
// two commands the worker applies the host's edits to the lower tree, then
// drops the upper entries of the paths that changed ("host wins"). The
// kernel allows a lower tree to change while the overlay is not mounted
// only if index, metacopy, xino and redirect_dir were never used, which is
// what overlayOpts pins. Three cases cover what a refresh does to a lower
// tree: a file replaced, a file deleted, a directory deleted that has an
// upper counterpart.

// projectTree is the project as the first command finds it.
var projectTree = tree{
	"keep.txt":      "f:keep v1",
	"ro.txt":        "f:ro v1",
	"mod.txt":       "f:mod v1",
	"gone.txt":      "f:gone v1",
	"dir":           "d",
	"dir/a.txt":     "f:a v1",
	"dir/b.txt":     "f:b v1",
	"dir/sub":       "d",
	"dir/sub/c.txt": "f:c v1",
}

// sandboxWrites is what the first command does through the overlay. It
// leaves in the upper layer: a full copy of mod.txt, a new file, a whiteout
// for gone.txt, and a directory "dir" that holds a new file and a whiteout
// for b.txt.
func sandboxWrites(merged string) error {
	_, readErr := os.ReadFile(filepath.Join(merged, "ro.txt"))
	return errors.Join(
		readErr,
		os.WriteFile(filepath.Join(merged, "mod.txt"), []byte("mod sandbox"), 0o644),
		os.WriteFile(filepath.Join(merged, "new.txt"), []byte("new sandbox"), 0o644),
		os.Remove(filepath.Join(merged, "gone.txt")),
		os.WriteFile(filepath.Join(merged, "dir/n.txt"), []byte("n sandbox"), 0o644),
		os.Remove(filepath.Join(merged, "dir/b.txt")),
	)
}

// replaceFile puts new content at path the way editors and agents do: a new
// inode renamed over the old name.
func replaceFile(path, content string) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// refreshCase is one change of the lower tree and the two views it must give.
type refreshCase struct {
	// change is what the host does to the lower tree while nothing is mounted.
	change func(lower string) error
	// kept is the merged view expected at the next mount when the upper
	// layer is as the sandbox left it: upper entries win.
	kept tree
	// drop names the upper entries the worker removes because their lower
	// path changed, and dropped is the merged view expected after that.
	drop    []string
	dropped tree
}

var refreshCases = map[string]refreshCase{
	"replace": {
		change: func(lower string) error {
			return errors.Join(
				// In place: same inode, new content.
				os.WriteFile(filepath.Join(lower, "keep.txt"), []byte("keep v2, rewritten in place"), 0o644),
				replaceFile(filepath.Join(lower, "ro.txt"), "ro v2"),
				replaceFile(filepath.Join(lower, "mod.txt"), "mod v2"),
				replaceFile(filepath.Join(lower, "gone.txt"), "gone v2"),
				replaceFile(filepath.Join(lower, "dir/a.txt"), "a v2"),
			)
		},
		kept: tree{
			"keep.txt":      "f:keep v2, rewritten in place",
			"ro.txt":        "f:ro v2",
			"mod.txt":       "f:mod sandbox",
			"new.txt":       "f:new sandbox",
			"dir":           "d",
			"dir/a.txt":     "f:a v2",
			"dir/n.txt":     "f:n sandbox",
			"dir/sub":       "d",
			"dir/sub/c.txt": "f:c v1",
		},
		drop: []string{"mod.txt", "gone.txt"},
		dropped: tree{
			"keep.txt":      "f:keep v2, rewritten in place",
			"ro.txt":        "f:ro v2",
			"mod.txt":       "f:mod v2",
			"gone.txt":      "f:gone v2",
			"new.txt":       "f:new sandbox",
			"dir":           "d",
			"dir/a.txt":     "f:a v2",
			"dir/n.txt":     "f:n sandbox",
			"dir/sub":       "d",
			"dir/sub/c.txt": "f:c v1",
		},
	},
	"delete-file": {
		change: func(lower string) error {
			return errors.Join(
				os.Remove(filepath.Join(lower, "ro.txt")),
				os.Remove(filepath.Join(lower, "mod.txt")),
				os.Remove(filepath.Join(lower, "gone.txt")),
				os.Remove(filepath.Join(lower, "dir/a.txt")),
			)
		},
		kept: tree{
			"keep.txt":      "f:keep v1",
			"mod.txt":       "f:mod sandbox",
			"new.txt":       "f:new sandbox",
			"dir":           "d",
			"dir/n.txt":     "f:n sandbox",
			"dir/sub":       "d",
			"dir/sub/c.txt": "f:c v1",
		},
		drop: []string{"mod.txt", "gone.txt"},
		dropped: tree{
			"keep.txt":      "f:keep v1",
			"new.txt":       "f:new sandbox",
			"dir":           "d",
			"dir/n.txt":     "f:n sandbox",
			"dir/sub":       "d",
			"dir/sub/c.txt": "f:c v1",
		},
	},
	"delete-dir": {
		change: func(lower string) error {
			return os.RemoveAll(filepath.Join(lower, "dir"))
		},
		kept: tree{
			"keep.txt":  "f:keep v1",
			"ro.txt":    "f:ro v1",
			"mod.txt":   "f:mod sandbox",
			"new.txt":   "f:new sandbox",
			"dir":       "d",
			"dir/n.txt": "f:n sandbox",
		},
		drop: []string{"dir"},
		dropped: tree{
			"keep.txt": "f:keep v1",
			"ro.txt":   "f:ro v1",
			"mod.txt":  "f:mod sandbox",
			"new.txt":  "f:new sandbox",
		},
	},
}

// refreshReport is what the helper found. An empty difference means the merged
// view was the expected tree.
type refreshReport struct {
	Options string `json:"options"` // overlay options as the kernel reports them
	Kept    string `json:"kept"`    // difference with the upper layer kept
	Dropped string `json:"dropped"` // difference after the stale upper entries were dropped
}

// childRefresh runs one case in a private mount namespace. args: directory,
// case.
func childRefresh(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: refresh DIR CASE")
	}
	kase, ok := refreshCases[args[1]]
	if !ok {
		return fmt.Errorf("unknown case %q", args[1])
	}
	if err := privateMounts(); err != nil {
		return err
	}
	o, err := makeOverlay(args[0])
	if err != nil {
		return err
	}
	if err := writeTree(o.lower, projectTree); err != nil {
		return err
	}

	// First command: mount, write through the overlay, unmount.
	if err := o.mount(overlayOpts); err != nil {
		return err
	}
	var rep refreshReport
	if e, ok := mountAt(parseMountinfo(mountinfoText()), o.merged); ok {
		rep.Options = overlayExtras(e.superOpts)
	}
	if err := sandboxWrites(o.merged); err != nil {
		return fmt.Errorf("writes through the first mount: %w", err)
	}
	if err := o.unmount(); err != nil {
		return err
	}

	// Nothing is mounted: the host changes the lower tree.
	if err := kase.change(o.lower); err != nil {
		return fmt.Errorf("change of the lower tree: %w", err)
	}

	// Second command, upper layer as the sandbox left it.
	if err := o.mount(overlayOpts); err != nil {
		return fmt.Errorf("second mount, after the lower tree changed: %w", err)
	}
	rep.Kept = diffTrees(kase.kept, readTree(o.merged))
	if err := o.unmount(); err != nil {
		return err
	}

	// Host wins: the worker drops the upper entries of the changed paths.
	for _, p := range kase.drop {
		if err := os.RemoveAll(filepath.Join(o.upper, p)); err != nil {
			return fmt.Errorf("drop the upper entry %s: %w", p, err)
		}
	}
	if err := o.mount(overlayOpts); err != nil {
		return fmt.Errorf("third mount, after the upper entries were dropped: %w", err)
	}
	rep.Dropped = diffTrees(kase.dropped, readTree(o.merged))
	if err := o.unmount(); err != nil {
		return err
	}
	return sayResult(rep)
}

func TestLowerChangedWhileUnmounted(t *testing.T) {
	r := declare(t, "refresh-replace", "refresh-delete-file", "refresh-delete-dir")
	r.needRoot()

	for _, kase := range []string{"replace", "delete-file", "delete-dir"} {
		id := "refresh-" + kase
		dir := scratch(t, "refresh-"+kase)
		var rep refreshReport
		if err := runChild(t, spawn{name: "refresh", args: []string{dir, kase}, clone: unix.CLONE_NEWNS}, &rep); err != nil {
			r.no(id, "the case did not complete on %s: %v", fsTypeOf(dir), err)
			continue
		}
		r.judge(id, rep.Kept == "" && rep.Dropped == "",
			"on %s with %s (the kernel reports %s): at the next mount with the upper layer kept, differences from the expected tree: %s; after the stale upper entries were dropped: %s",
			fsTypeOf(dir), overlayOpts, rep.Options, orNothing(rep.Kept), orNothing(rep.Dropped))
	}
}

// unionOf is the rule overlayfs documents for a merged view, written out
// once more in Go: an upper entry wins, a whiteout hides the lower entry of
// the same name and everything under it, and the rest of the lower tree
// shows through. Whiteouts are "w" in the upper tree given here.
func unionOf(lower, upper tree) tree {
	out := tree{}
	hidden := func(p string) bool {
		for q := p; q != "." && q != "/"; q = filepath.Dir(q) {
			if upper[q] == "w" {
				return true
			}
		}
		return false
	}
	for p, v := range lower {
		if !hidden(p) {
			out[p] = v
		}
	}
	for p, v := range upper {
		if v != "w" {
			out[p] = v
		}
	}
	return out
}

// The expected trees of the cases are written by hand, above, so that they
// can be read. This test derives them a second way, from the real change
// functions applied to a real lower tree and from the union rule, and
// requires both to agree. It needs no mount.
func TestSelfRefreshExpectations(t *testing.T) {
	// What sandboxWrites leaves in the upper layer.
	sandboxUpper := tree{
		"mod.txt":   "f:mod sandbox",
		"new.txt":   "f:new sandbox",
		"gone.txt":  "w",
		"dir":       "d",
		"dir/n.txt": "f:n sandbox",
		"dir/b.txt": "w",
	}
	for name, kase := range refreshCases {
		lower := filepath.Join(t.TempDir(), "lower")
		if err := writeTree(lower, projectTree); err != nil {
			t.Fatal(err)
		}
		if err := kase.change(lower); err != nil {
			t.Fatalf("%s: change of the lower tree: %v", name, err)
		}
		after := readTree(lower)

		if d := diffTrees(kase.kept, unionOf(after, sandboxUpper)); d != "" {
			t.Errorf("%s: the tree expected with the upper layer kept is not the union of the layers: %s", name, d)
		}
		upper := maps.Clone(sandboxUpper)
		for _, dropped := range kase.drop {
			for p := range upper {
				if p == dropped || strings.HasPrefix(p, dropped+"/") {
					delete(upper, p)
				}
			}
		}
		if d := diffTrees(kase.dropped, unionOf(after, upper)); d != "" {
			t.Errorf("%s: the tree expected after the drop is not the union of the layers: %s", name, d)
		}
	}
}
