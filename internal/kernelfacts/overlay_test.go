//go:build integration && linux

package kernelfacts

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// overlayOpts are the options of the one overlay of a sandbox, as the
// service mounts it. index, metacopy and redirect_dir are features the
// kernel wants unused before a lower tree may change between two mounts,
// and redirect_dir is "nofollow" because "off" means "follow" on kernels
// built with OVERLAY_FS_REDIRECT_ALWAYS_FOLLOW, as Ubuntu's are. xino is
// left to the kernel: it then numbers inodes across filesystems as soon as
// the layers are on more than one, which an upper directory on a tmpfs
// brings about. The same documentation counts xino among the features that
// forbid changing a lower tree, so the tests of that change run on both
// placements of the upper directory (refresh_test.go).
const overlayOpts = "index=off,metacopy=off,redirect_dir=nofollow,xino=auto"

// overlay is the directories of one overlay mount.
type overlay struct {
	lowers              []string // read-only layers, top first, as lowerdir= takes them
	upper, work, merged string
}

// mount mounts the overlay with the given options. Only helpers call it,
// after privateMounts.
func (o overlay) mount(opts string) error {
	data := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s,%s", strings.Join(o.lowers, ":"), o.upper, o.work, opts)
	if err := unix.Mount("overlay", o.merged, "overlay", unix.MS_NODEV|unix.MS_NOSUID, data); err != nil {
		return fmt.Errorf("mount overlay on %s with %s: %w", o.merged, opts, err)
	}
	return nil
}

func (o overlay) unmount() error {
	if err := unix.Unmount(o.merged, 0); err != nil {
		return fmt.Errorf("unmount %s: %w", o.merged, err)
	}
	return nil
}

// reportedOptions is what the kernel says it applied to the overlay now
// mounted, read from the mount table: the options that are not directories.
func (o overlay) reportedOptions() string {
	e, ok := mountAt(parseMountinfo(mountinfoText()), o.merged)
	if !ok {
		return "no mount at " + o.merged
	}
	return overlayExtras(e.superOpts)
}

// stack is the overlay of one sandbox as the design builds it: what the
// image brings at the bottom, above it a layer whose only content is the
// copy of the project under workspace/, and the session's upper directory
// on top. One mount, so that what a command writes to the project lands in
// the same upper directory as everything else it writes.
type stack struct {
	overlay
	image   string // the bottom layer
	project string // the layer above it: holds workspace/ and nothing else
}

// imageLayer is what makeStack puts in the image layer: a file, and the
// empty directory an image has where the project goes.
var imageLayer = tree{
	"etc":       "d",
	"etc/issue": "f:from the image layer",
	"workspace": "d",
}

// stackAt names the directories of a stack and creates nothing. The layers
// and the mount point are under dir. The upper and work directories are
// under upperDir, which is dir itself unless the upper layer lives on a
// filesystem of its own.
func stackAt(dir, upperDir string) stack {
	s := stack{
		image:   filepath.Join(dir, "image"),
		project: filepath.Join(dir, "project"),
	}
	s.overlay = overlay{
		lowers: []string{s.project, s.image},
		upper:  filepath.Join(upperDir, "upper"),
		work:   filepath.Join(upperDir, "work"),
		merged: filepath.Join(dir, "merged"),
	}
	return s
}

// makeStack creates the directories of the stack at dir and upperDir, and
// fills the image layer.
func makeStack(dir, upperDir string) (stack, error) {
	s := stackAt(dir, upperDir)
	for _, d := range []string{s.image, s.workspace(), s.upper, s.work, s.merged} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return s, err
		}
	}
	return s, writeTree(s.image, imageLayer)
}

// workspace is the project inside its layer: where the host's copy of the
// project is written, and refreshed between two commands.
func (s stack) workspace() string { return filepath.Join(s.project, "workspace") }

// view is the merged tree expected of a stack whose project is the given
// tree: the image layer, and the project under workspace/.
func view(project tree) tree {
	out := maps.Clone(imageLayer)
	for p, v := range project {
		out[filepath.Join("workspace", p)] = v
	}
	return out
}

// devIno is the device and inode number of a path, as lstat reports them.
func devIno(path string) (dev, ino uint64, err error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, 0, err
	}
	st := fi.Sys().(*syscall.Stat_t)
	return uint64(st.Dev), st.Ino, nil
}

// inodeNumbering says how a mounted stack numbers a file that only exists
// in a lower layer, which is how one tells whether the kernel turned xino
// on: the mount table does not say. rel is such a file, relative to the
// image layer and to the mount point.
//
// On one filesystem the overlay shows the inode number of the file itself.
// With xino, a file of another filesystem than the upper directory's keeps
// the device of the overlay and gets the number of its filesystem in the
// high bits of its inode number. Without it, such a file shows a device of
// its own.
func (s stack) inodeNumbering(rel string) string {
	rootDev, _, err := devIno(s.merged)
	if err != nil {
		return "the mount point cannot be read: " + errnoName(err)
	}
	dev, ino, err := devIno(filepath.Join(s.merged, rel))
	if err != nil {
		return "a lower file cannot be read through the overlay: " + errnoName(err)
	}
	lowerDev, lowerIno, err := devIno(filepath.Join(s.image, rel))
	if err != nil {
		return "the lower file itself cannot be read: " + errnoName(err)
	}
	upperDev, _, err := devIno(s.upper)
	if err != nil {
		return "the upper directory cannot be read: " + errnoName(err)
	}
	what := fmt.Sprintf("a lower file with inode %#x shows through the overlay as inode %#x", lowerIno, ino)
	switch {
	case lowerDev == upperDev && dev == rootDev && ino == lowerIno:
		return "all layers on one filesystem, xino not needed: " + what + " on the device of the overlay"
	case lowerDev == upperDev:
		return "all layers on one filesystem, and yet " + what + fmt.Sprintf(", device %#x where the overlay has %#x", dev, rootDev)
	case dev == rootDev && ino != lowerIno:
		return "layers on two filesystems, xino in use: " + what + " on the device of the overlay"
	case dev != rootDev:
		return "layers on two filesystems, xino not in use: " + what + fmt.Sprintf(" on device %#x where the overlay has %#x", dev, rootDev)
	default:
		return "layers on two filesystems, and yet " + what + " on the device of the overlay"
	}
}
