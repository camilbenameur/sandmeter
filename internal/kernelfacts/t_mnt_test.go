//go:build integration && linux

package kernelfacts

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// T-mnt: the mount targets of the init.
//
// The init mounts on directories of a root filesystem that an earlier
// command may have rewritten. A target replaced by a symbolic link would
// send the mount somewhere else. So every target is opened beneath the root
// with openat2 and RESOLVE_IN_ROOT, RESOLVE_NO_SYMLINKS and
// RESOLVE_NO_MAGICLINKS, and the mount goes to /proc/self/fd/N: the kernel
// then mounts on the directory that was opened, whatever its name has
// become since. A link anywhere in the path is a set-up error.

// The planted paths, relative to the root, and what they are.
var mntPlanted = []string{
	"workspace", // a link to a directory outside the root
	"alias",     // a link to the honest target, inside the root
	"via/tmp",   // the honest target behind a link in the middle of the path
}

// mntReport is what the stand-in for the init found.
type mntReport struct {
	Open    string            `json:"open"`    // openat2 of the honest target
	Mount   string            `json:"mount"`   // mount on /proc/self/fd/N
	Landed  string            `json:"landed"`  // filesystem now mounted on the honest target
	Planted map[string]string `json:"planted"` // openat2 of each planted path
	Outside string            `json:"outside"` // filesystem mounted on the outside directory after those
	Naive   string            `json:"naive"`   // where a mount by path through the first planted link went
}

// openBeneath opens the directory at path beneath the root descriptor the
// way the init opens a mount target: the root is the root for this lookup,
// and no symbolic or magic link is followed, wherever it is in the path.
//
// There is no O_NOFOLLOW on purpose: with it and O_PATH, openat2 hands back
// a descriptor of a trailing link instead of refusing it (openat2(2)).
func openBeneath(rootfd int, path string) (int, error) {
	how := unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	}
	return unix.Openat2(rootfd, path, &how)
}

// plantLinks puts in root the links a hostile first command could leave
// where mount targets are expected (see mntPlanted).
func plantLinks(root, outside string) error {
	return errors.Join(
		os.Symlink(outside, filepath.Join(root, "workspace")),
		os.Symlink("tmp", filepath.Join(root, "alias")),
		os.Symlink(".", filepath.Join(root, "via")),
	)
}

// mountedOn names the filesystem type mounted exactly at a path in this
// mount namespace, or "nothing".
func mountedOn(path string) string {
	if e, ok := mountAt(parseMountinfo(mountinfoText()), path); ok {
		return e.fstype
	}
	return "nothing"
}

// childMnt runs in new user, mount and pid namespaces, like the init, with
// the host's procfs still in place. args: root directory, outside directory.
func childMnt(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: tmnt ROOT OUTSIDE")
	}
	root, outside := args[0], args[1]
	if err := privateMounts(); err != nil {
		return err
	}
	rootfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open the root: %w", err)
	}
	const tmpfs = "size=1m,mode=0755"

	rep := mntReport{Mount: "not tried", Landed: "nothing", Planted: map[string]string{}}
	fd, err := openBeneath(rootfd, "tmp")
	rep.Open = errnoName(err)
	if err == nil {
		rep.Mount = errnoName(unix.Mount("tmpfs", fmt.Sprintf("/proc/self/fd/%d", fd), "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, tmpfs))
		rep.Landed = mountedOn(filepath.Join(root, "tmp"))
		unix.Close(fd)
	}

	for _, p := range mntPlanted {
		fd, err := openBeneath(rootfd, p)
		rep.Planted[p] = errnoName(err)
		if err == nil {
			unix.Close(fd)
		}
	}
	rep.Outside = mountedOn(outside)

	// The control: what the guard is for. A mount by path follows the link
	// and lands outside the root. It happens in this helper's own mount
	// namespace and goes away with it.
	if err := unix.Mount("tmpfs", filepath.Join(root, "workspace"), "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, tmpfs); err != nil {
		rep.Naive = "mount by path: " + errnoName(err)
	} else {
		rep.Naive = "a mount by path through the link put a " + mountedOn(outside) + " on the outside directory"
	}
	return sayResult(rep)
}

func TestMountTargetByDescriptor(t *testing.T) {
	r := declare(t, "T-mnt", "T-mnt-symlink")
	r.needRoot()

	dir := scratch(t, "tmnt")
	root, outside := filepath.Join(dir, "root"), filepath.Join(dir, "outside")
	// A root filesystem as a first command could have left it: an honest
	// target, and links where targets are expected.
	for _, d := range []string{root, filepath.Join(root, "tmp"), outside} {
		if err := errors.Join(os.Mkdir(d, 0o755), os.Chown(d, idShift, idShift)); err != nil {
			t.Fatalf("prepare the root: %v", err)
		}
	}
	if err := plantLinks(root, outside); err != nil {
		t.Fatalf("plant the links: %v", err)
	}

	var rep mntReport
	err := runChild(t, spawn{name: "tmnt", args: []string{root, outside}, clone: unix.CLONE_NEWNS | unix.CLONE_NEWPID, userns: true}, &rep)
	if err != nil {
		r.no("T-mnt", "the stand-in for the init did not complete: %v", err)
		return
	}
	r.judge("T-mnt", rep.Open == "ok" && rep.Mount == "ok" && rep.Landed == "tmpfs",
		"openat2 of the target beneath the root: %s; mount of a tmpfs on /proc/self/fd/N: %s; mounted on the target afterwards: %s (expected ok, ok, tmpfs)",
		rep.Open, rep.Mount, rep.Landed)

	refused := true
	var planted []string
	for _, p := range mntPlanted {
		refused = refused && rep.Planted[p] == "ELOOP"
		planted = append(planted, p+": "+rep.Planted[p])
	}
	slices.Sort(planted)
	r.judge("T-mnt-symlink", refused && rep.Outside == "nothing",
		"openat2 of the planted paths (workspace: link to a directory outside the root; alias: link to the target; via/tmp: link in the middle): %v (expected ELOOP for each); mounted on the outside directory afterwards: %s (expected nothing); control without the guard: %s",
		planted, rep.Outside, rep.Naive)
}

// The open half of T-mnt: openat2 needs no privilege, so the refusals the
// init relies on are checked on every host, and so is the claim that
// /proc/self/fd/N names the directory that was opened.
func TestSelfOpenBeneath(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root, outside := filepath.Join(dir, "root"), filepath.Join(dir, "outside")
	for _, d := range []string{root, filepath.Join(root, "tmp"), outside} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := plantLinks(root, outside); err != nil {
		t.Fatal(err)
	}
	rootfd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootfd)

	for _, honest := range []string{"tmp", "/tmp", "../tmp"} {
		fd, err := openBeneath(rootfd, honest)
		if err != nil {
			t.Errorf("openBeneath(%q): %v", honest, err)
			continue
		}
		if got, _ := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd)); got != filepath.Join(root, "tmp") {
			t.Errorf("openBeneath(%q) opened %s, want the tmp directory of the root", honest, got)
		}
		unix.Close(fd)
	}
	for _, p := range mntPlanted {
		fd, err := openBeneath(rootfd, p)
		if err == nil {
			unix.Close(fd)
		}
		if got := errnoName(err); got != "ELOOP" {
			t.Errorf("openBeneath(%q) = %s, want ELOOP", p, got)
		}
	}
	// Leaving the root by name leads nowhere: the outside directory is
	// not beneath it.
	if fd, err := openBeneath(rootfd, "../outside"); err == nil {
		unix.Close(fd)
		t.Errorf("openBeneath reached a directory outside the root")
	} else if got := errnoName(err); got != "ENOENT" {
		t.Errorf("openBeneath(\"../outside\") = %s, want ENOENT", got)
	}
}
