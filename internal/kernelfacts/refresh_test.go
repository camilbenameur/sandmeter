//go:build integration && linux

package kernelfacts

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The refresh of the project between two commands.
//
// The overlay of a sandbox is mounted for the length of one command.
// Between two commands the worker applies the host's edits to the layer
// that holds the copy of the project, then drops the upper entries of the
// paths that changed ("host wins"). The kernel documents a lower tree
// changed while the overlay is not mounted as allowed only if index,
// metacopy, redirect_dir and xino were never used. The design switches the
// first three off and leaves xino to the kernel, which uses it as soon as
// the layers are on two filesystems: with the upper directory on a tmpfs,
// the opt-in disk quota. So nothing but a measurement says what the next
// mount shows, and it is made on the mount the service makes: the project
// layer above an image layer, with the upper directory on the state
// filesystem and on a tmpfs.
//
// Three cases cover what a refresh does to a lower tree: a file replaced, a
// file deleted, a directory deleted that has an upper counterpart.

// refreshRuns are the runs of the test: each case on each placement of the
// upper directory, and the fact it settles.
var refreshRuns = []struct{ fact, upper, kase string }{
	{"refresh-disk-replace", "disk", "replace"},
	{"refresh-disk-delete-file", "disk", "delete-file"},
	{"refresh-disk-delete-dir", "disk", "delete-dir"},
	{"refresh-tmpfs-replace", "tmpfs", "replace"},
	{"refresh-tmpfs-delete-file", "tmpfs", "delete-file"},
	{"refresh-tmpfs-delete-dir", "tmpfs", "delete-dir"},
}

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

// sandboxWrites is what the first command does to the project, through the
// overlay. It leaves in the upper layer, under workspace/: a full copy of
// mod.txt, a new file, a whiteout for gone.txt, and a directory "dir" that
// holds a new file and a whiteout for b.txt.
func sandboxWrites(workspace string) error {
	_, readErr := os.ReadFile(filepath.Join(workspace, "ro.txt"))
	return errors.Join(
		readErr,
		os.WriteFile(filepath.Join(workspace, "mod.txt"), []byte("mod sandbox"), 0o644),
		os.WriteFile(filepath.Join(workspace, "new.txt"), []byte("new sandbox"), 0o644),
		os.Remove(filepath.Join(workspace, "gone.txt")),
		os.WriteFile(filepath.Join(workspace, "dir/n.txt"), []byte("n sandbox"), 0o644),
		os.Remove(filepath.Join(workspace, "dir/b.txt")),
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

// refreshReport is what the helper found. An empty difference means the
// merged view was the expected tree.
type refreshReport struct {
	Lower   string `json:"lower"`   // filesystem of the lower layers
	Upper   string `json:"upper"`   // filesystem of the upper directory
	Options string `json:"options"` // overlay options as the kernel reports them
	Inodes  string `json:"inodes"`  // how the overlay numbers a lower file: whether xino is in use
	Kept    string `json:"kept"`    // difference with the upper layer kept
	Dropped string `json:"dropped"` // difference after the stale upper entries were dropped
}

// refreshTmpfs is the size of the tmpfs that holds the upper directory in
// the runs that have it there.
const refreshTmpfs = "size=16m,nr_inodes=1024,mode=0700"

// childRefresh runs one case in a private mount namespace. args: directory,
// case, and where the upper directory lives: "disk" or "tmpfs".
func childRefresh(args []string) error {
	if len(args) != 3 || (args[2] != "disk" && args[2] != "tmpfs") {
		return errors.New("usage: refresh DIR CASE disk|tmpfs")
	}
	dir := args[0]
	kase, ok := refreshCases[args[1]]
	if !ok {
		return fmt.Errorf("unknown case %q", args[1])
	}
	if err := privateMounts(); err != nil {
		return err
	}
	upperDir := dir
	if args[2] == "tmpfs" {
		upperDir = filepath.Join(dir, "tmpfs")
		if err := os.Mkdir(upperDir, 0o700); err != nil {
			return err
		}
		if err := unix.Mount("tmpfs", upperDir, "tmpfs", unix.MS_NODEV|unix.MS_NOSUID, refreshTmpfs); err != nil {
			return fmt.Errorf("mount a tmpfs with %s for the upper directory: %w", refreshTmpfs, err)
		}
	}
	s, err := makeStack(dir, upperDir)
	if err != nil {
		return err
	}
	if err := writeTree(s.workspace(), projectTree); err != nil {
		return err
	}
	rep := refreshReport{Lower: fsTypeOf(s.project), Upper: fsTypeOf(s.upper)}

	// First command: mount, write to the project through the overlay,
	// unmount.
	if err := s.mount(overlayOpts); err != nil {
		return err
	}
	rep.Options = s.reportedOptions()
	rep.Inodes = s.inodeNumbering("etc/issue")
	if err := sandboxWrites(filepath.Join(s.merged, "workspace")); err != nil {
		return fmt.Errorf("writes through the first mount: %w", err)
	}
	if err := s.unmount(); err != nil {
		return err
	}

	// Nothing is mounted: the host's edits reach the project layer.
	if err := kase.change(s.workspace()); err != nil {
		return fmt.Errorf("change of the lower tree: %w", err)
	}

	// Second command, upper layer as the sandbox left it.
	if err := s.mount(overlayOpts); err != nil {
		return fmt.Errorf("second mount, after the lower tree changed: %w", err)
	}
	rep.Kept = diffTrees(view(kase.kept), readTree(s.merged))
	if err := s.unmount(); err != nil {
		return err
	}

	// Host wins: the worker drops the upper entries of the changed paths.
	for _, p := range kase.drop {
		if err := os.RemoveAll(filepath.Join(s.upper, "workspace", p)); err != nil {
			return fmt.Errorf("drop the upper entry %s: %w", p, err)
		}
	}
	if err := s.mount(overlayOpts); err != nil {
		return fmt.Errorf("third mount, after the upper entries were dropped: %w", err)
	}
	rep.Dropped = diffTrees(view(kase.dropped), readTree(s.merged))
	if err := s.unmount(); err != nil {
		return err
	}
	if upperDir != dir {
		if err := unix.Unmount(upperDir, 0); err != nil {
			return fmt.Errorf("unmount the tmpfs of the upper directory: %w", err)
		}
	}
	return sayResult(rep)
}

func TestLowerChangedWhileUnmounted(t *testing.T) {
	r := declare(t,
		"refresh-disk-replace", "refresh-disk-delete-file", "refresh-disk-delete-dir",
		"refresh-tmpfs-replace", "refresh-tmpfs-delete-file", "refresh-tmpfs-delete-dir")
	r.needRoot()

	for _, run := range refreshRuns {
		dir := scratch(t, "refresh-"+run.upper+"-"+run.kase)
		var rep refreshReport
		if err := runChild(t, spawn{name: "refresh", args: []string{dir, run.kase, run.upper}, clone: unix.CLONE_NEWNS}, &rep); err != nil {
			r.no(run.fact, "the case did not complete, lower layers on %s and upper directory on %s: %v", fsTypeOf(dir), run.upper, err)
			continue
		}
		r.judge(run.fact, rep.Kept == "" && rep.Dropped == "",
			"project layer above an image layer on %s, upper directory on %s, mounted with %s (the kernel reports %s; %s); at the next mount with the upper layer kept, differences from the expected tree: %s; after the stale upper entries were dropped: %s",
			rep.Lower, rep.Upper, overlayOpts, rep.Options, rep.Inodes, orNothing(rep.Kept), orNothing(rep.Dropped))
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

	// Every case runs on both placements of the upper directory, each run
	// under a fact of its own that gates.
	seen := map[string]bool{}
	for _, run := range refreshRuns {
		if d, ok := catalogued(run.fact); !ok || !d.required {
			t.Errorf("the run %s on %s records %q, which is not a required fact of the catalogue", run.kase, run.upper, run.fact)
		}
		if _, ok := refreshCases[run.kase]; !ok {
			t.Errorf("the run that records %s names the case %q, which does not exist", run.fact, run.kase)
		}
		if run.upper != "disk" && run.upper != "tmpfs" {
			t.Errorf("the run that records %s puts the upper directory on %q", run.fact, run.upper)
		}
		seen[run.upper+" "+run.kase] = true
	}
	if len(seen) != 2*len(refreshCases) || len(refreshRuns) != len(seen) {
		t.Errorf("%d runs cover %d of the %d combinations of a case and a placement", len(refreshRuns), len(seen), 2*len(refreshCases))
	}
}

// The directories of a stack and the view expected of it, without a mount.
func TestSelfStack(t *testing.T) {
	dir := t.TempDir()
	upperDir := filepath.Join(dir, "elsewhere")
	s, err := makeStack(dir, upperDir)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.lowers, []string{s.project, s.image}) {
		t.Errorf("lower layers %v: the project layer must come first, above the image layer", s.lowers)
	}
	if filepath.Dir(s.upper) != upperDir || filepath.Dir(s.work) != upperDir || filepath.Dir(s.merged) != dir {
		t.Errorf("upper %s, work %s, merged %s: the first two belong under %s", s.upper, s.work, s.merged, upperDir)
	}
	if d := diffTrees(imageLayer, readTree(s.image)); d != "" {
		t.Errorf("the image layer is not what makeStack is said to write: %s", d)
	}
	if d := diffTrees(tree{"workspace": "d"}, readTree(s.project)); d != "" {
		t.Errorf("the project layer must hold workspace/ and nothing else: %s", d)
	}
	// What the two layers give once merged is the union of both.
	if err := writeTree(s.workspace(), tree{"a.txt": "f:a", "d": "d"}); err != nil {
		t.Fatal(err)
	}
	union := readTree(s.image)
	maps.Copy(union, readTree(s.project))
	if d := diffTrees(view(tree{"a.txt": "f:a", "d": "d"}), union); d != "" {
		t.Errorf("view is not the union of the image layer and the project layer: %s", d)
	}
	// The numbering of a file that no overlay shows is an errno, not a claim.
	if got := s.inodeNumbering("etc/issue"); !strings.Contains(got, "ENOENT") {
		t.Errorf("inodeNumbering without a mount = %q, want it to name ENOENT", got)
	}
	if dev, ino, err := devIno(filepath.Join(s.image, "etc/issue")); err != nil || dev == 0 || ino == 0 {
		t.Errorf("devIno of a file = %d, %d, %v", dev, ino, err)
	}
	if got := (overlay{merged: s.merged}).reportedOptions(); !strings.HasPrefix(got, "no mount at ") {
		t.Errorf("reportedOptions of a directory nothing is mounted on = %q", got)
	}
}
