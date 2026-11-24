//go:build integration && linux

package kernelfacts

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// The opt-in disk quota.
//
// With storage.upper = "tmpfs", the upper and work directories of a session
// live on a tmpfs mounted with size= and nr_inodes= taken from limits.disk.
// That is a hard quota only if overlayfs is content with a tmpfs upper
// layer (whiteouts are device nodes, opaque directories are trusted.*
// extended attributes) and if both caps answer ENOSPC through the overlay.
// The pages are memory: where they are charged decides whether the quota
// also eats the sandbox's memory limit.

const (
	tmpfsSize   = 8 << 20 // size= of the tmpfs, in bytes
	tmpfsInodes = 96      // nr_inodes= of the tmpfs
)

// tmpfsReport is what the helper measured. Empty strings mean "as expected".
type tmpfsReport struct {
	Whiteout    string `json:"whiteout"`     // what is wrong with the whiteout left in the upper layer
	Opaque      string `json:"opaque"`       // what is wrong with the opaque directory left there
	View        string `json:"view"`         // difference between the merged view and the expected tree
	Remounted   string `json:"remounted"`    // the same after an unmount and a new mount
	SizeErr     string `json:"size_err"`     // what stopped one growing file
	SizeBytes   int64  `json:"size_bytes"`   // bytes written before that
	InodeErr    string `json:"inode_err"`    // what stopped the creation of empty files
	InodeCount  int    `json:"inode_count"`  // files created before that
	MemBefore   int64  `json:"mem_before"`   // memory.current of the writer's cgroup, -1 when unknown
	MemAfter    int64  `json:"mem_after"`    // the same while the big file exists
	ShmemBefore int64  `json:"shmem_before"` // "shmem" of its memory.stat
	ShmemAfter  int64  `json:"shmem_after"`
}

// isWhiteout says what is wrong when path is not an overlay whiteout: a
// character device with device number 0.
func isWhiteout(path string) string {
	fi, err := os.Lstat(path)
	if err != nil {
		return "the upper layer has no entry: " + errnoName(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if fi.Mode()&os.ModeCharDevice == 0 || st.Rdev != 0 {
		return fmt.Sprintf("the upper entry is %v with device number %d, expected a character device 0", fi.Mode(), st.Rdev)
	}
	return ""
}

// isOpaque says what is wrong when path is not an opaque overlay directory.
func isOpaque(path string) string {
	buf := make([]byte, 8)
	n, err := unix.Getxattr(path, "trusted.overlay.opaque", buf)
	if err != nil {
		return "trusted.overlay.opaque on the upper directory: " + errnoName(err)
	}
	if string(buf[:n]) != "y" {
		return fmt.Sprintf("trusted.overlay.opaque is %q, expected \"y\"", buf[:n])
	}
	return ""
}

// memoryOf reads memory.current and the shmem line of memory.stat of a
// cgroup; -1 when there is no cgroup to read.
func memoryOf(leaf string) (current, shmem int64) {
	if leaf == "" {
		return -1, -1
	}
	current, err := cgInt(leaf, "memory.current")
	if err != nil {
		return -1, -1
	}
	return current, cgCounter(leaf, "memory.stat", "shmem")
}

// childTmpfsUpper runs in a private mount namespace, inside the cgroup whose
// memory is read. args: directory, cgroup directory or "".
func childTmpfsUpper(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: tmpfsupper DIR LEAF")
	}
	dir, leaf := args[0], args[1]
	if err := privateMounts(); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "tmpfs")
	if err := os.Mkdir(tmp, 0o700); err != nil {
		return err
	}
	opts := fmt.Sprintf("size=%d,nr_inodes=%d,mode=0700", tmpfsSize, tmpfsInodes)
	if err := unix.Mount("tmpfs", tmp, "tmpfs", unix.MS_NODEV|unix.MS_NOSUID, opts); err != nil {
		return fmt.Errorf("mount a tmpfs with %s: %w", opts, err)
	}
	o := overlay{
		lower:  filepath.Join(dir, "lower"),
		upper:  filepath.Join(tmp, "upper"),
		work:   filepath.Join(tmp, "work"),
		merged: filepath.Join(dir, "merged"),
	}
	for _, d := range []string{o.lower, o.upper, o.work, o.merged} {
		if err := os.Mkdir(d, 0o755); err != nil {
			return err
		}
	}
	if err := writeTree(o.lower, tree{"a.txt": "f:a", "d": "d", "d/x.txt": "f:x", "d/y.txt": "f:y", "keep": "d", "keep/k.txt": "f:k"}); err != nil {
		return err
	}
	if err := o.mount(overlayOpts); err != nil {
		return fmt.Errorf("with the upper and work directories on a tmpfs: %w", err)
	}

	var rep tmpfsReport
	// A lower file removed: a whiteout in the upper layer.
	if err := os.Remove(filepath.Join(o.merged, "a.txt")); err != nil {
		rep.Whiteout = "remove a lower file through the overlay: " + errnoName(err)
	} else {
		rep.Whiteout = isWhiteout(filepath.Join(o.upper, "a.txt"))
	}
	// A lower directory removed and created again: an opaque directory.
	err := errors.Join(
		os.RemoveAll(filepath.Join(o.merged, "d")),
		os.Mkdir(filepath.Join(o.merged, "d"), 0o755),
		os.WriteFile(filepath.Join(o.merged, "d", "new.txt"), []byte("new"), 0o644),
	)
	if err != nil {
		rep.Opaque = "replace a lower directory through the overlay: " + errnoName(err)
	} else {
		rep.Opaque = isOpaque(filepath.Join(o.upper, "d"))
	}
	want := tree{"keep": "d", "keep/k.txt": "f:k", "d": "d", "d/new.txt": "f:new"}
	rep.View = diffTrees(want, readTree(o.merged))
	if err := o.unmount(); err != nil {
		return err
	}
	if err := o.mount(overlayOpts); err != nil {
		return fmt.Errorf("second mount on the same tmpfs: %w", err)
	}
	rep.Remounted = diffTrees(want, readTree(o.merged))

	// One file that grows past size=.
	rep.MemBefore, rep.ShmemBefore = memoryOf(leaf)
	big := filepath.Join(o.merged, "big")
	rep.SizeBytes, rep.SizeErr = fill(big, 2*tmpfsSize)
	rep.MemAfter, rep.ShmemAfter = memoryOf(leaf)
	if err := os.Remove(big); err != nil {
		return fmt.Errorf("remove the big file: %w", err)
	}

	// Empty files past nr_inodes=.
	rep.InodeErr = "no error"
	for i := 0; i < 2*tmpfsInodes; i++ {
		f, err := os.Create(filepath.Join(o.merged, fmt.Sprintf("f-%04d", i)))
		if err != nil {
			rep.InodeErr = errnoName(err)
			break
		}
		f.Close()
		rep.InodeCount++
	}

	if err := o.unmount(); err != nil {
		return err
	}
	if err := unix.Unmount(tmp, 0); err != nil {
		return fmt.Errorf("unmount the tmpfs: %w", err)
	}
	return sayResult(rep)
}

func TestTmpfsUpper(t *testing.T) {
	r := declare(t, "tmpfs-upper-whiteouts", "tmpfs-upper-size", "tmpfs-upper-inodes", "tmpfs-upper-memory")
	r.needRoot()

	dir := scratch(t, "tmpfsupper")
	// The writer runs in a leaf of its own so that its memory can be read.
	leaf, noLeaf := "", "cgroup v2 is not mounted at "+cgroupRoot
	if haveCgroup2() {
		tr, err := newCgTree(t, "tmpfsupper")
		if err != nil {
			noLeaf = "the cgroup layout could not be created: " + err.Error()
		} else {
			leaf = tr.leaf
		}
	}

	var rep tmpfsReport
	if err := runChild(t, spawn{name: "tmpfsupper", args: []string{dir, leaf}, clone: unix.CLONE_NEWNS, cgroup: leaf}, &rep); err != nil {
		r.no("tmpfs-upper-whiteouts", "the overlay on a tmpfs upper layer did not complete (lower layer on %s): %v", fsTypeOf(dir), err)
		return
	}
	r.judge("tmpfs-upper-whiteouts", rep.Whiteout == "" && rep.Opaque == "" && rep.View == "" && rep.Remounted == "",
		"tmpfs with size=%d,nr_inodes=%d, lower layer on %s; whiteout: %s; opaque directory: %s; merged view against the expected tree: %s; after a remount: %s",
		tmpfsSize, tmpfsInodes, fsTypeOf(dir), orOK(rep.Whiteout), orOK(rep.Opaque), orNothing(rep.View), orNothing(rep.Remounted))
	r.judge("tmpfs-upper-size", rep.SizeErr == "ENOSPC" && rep.SizeBytes > tmpfsSize/2 && rep.SizeBytes <= tmpfsSize,
		"a file written through the overlay grew to %d bytes and was stopped by %s (expected ENOSPC at or just under size=%d)", rep.SizeBytes, rep.SizeErr, tmpfsSize)
	r.judge("tmpfs-upper-inodes", rep.InodeErr == "ENOSPC" && rep.InodeCount > 0 && rep.InodeCount < tmpfsInodes,
		"%d empty files were created through the overlay before %s (expected ENOSPC under nr_inodes=%d)", rep.InodeCount, rep.InodeErr, tmpfsInodes)

	switch {
	case leaf == "":
		r.skip("tmpfs-upper-memory", "%s", noLeaf)
	case rep.MemBefore < 0 || rep.MemAfter < 0:
		r.skip("tmpfs-upper-memory", "memory.current of the writer's cgroup could not be read")
	default:
		grown := rep.MemAfter - rep.MemBefore
		r.judge("tmpfs-upper-memory", rep.SizeBytes > 0 && grown >= rep.SizeBytes*3/4,
			"while a %d-byte file sat in the tmpfs upper layer, memory.current of the writer's cgroup went from %d to %d (+%d) and its shmem from %d to %d",
			rep.SizeBytes, rep.MemBefore, rep.MemAfter, grown, rep.ShmemBefore, rep.ShmemAfter)
	}
}

// What is not a whiteout or an opaque directory must not pass for one. The
// positive cases need a mounted overlay: they are the root test itself.
func TestSelfUpperChecks(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{file, dir, filepath.Join(dir, "absent")} {
		if isWhiteout(p) == "" {
			t.Errorf("isWhiteout accepted %s", p)
		}
	}
	if isOpaque(dir) == "" {
		t.Errorf("isOpaque accepted a plain directory")
	}
	if current, shmem := memoryOf(""); current != -1 || shmem != -1 {
		t.Errorf("memoryOf without a cgroup = %d, %d; want -1, -1", current, shmem)
	}
}
