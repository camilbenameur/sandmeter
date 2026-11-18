//go:build integration && linux

package kernelfacts

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// overlayOpts are the options of the workspace overlay. They are what makes
// a lower tree changed between two mounts legal for the kernel, and
// redirect_dir is "nofollow" because "off" means "follow" on kernels built
// with OVERLAY_FS_REDIRECT_ALWAYS_FOLLOW, as Ubuntu's are.
const overlayOpts = "index=off,metacopy=off,redirect_dir=nofollow,xino=off"

// overlay is the four directories of one overlay mount.
type overlay struct{ lower, upper, work, merged string }

// makeOverlay creates the four directories under dir.
func makeOverlay(dir string) (overlay, error) {
	o := overlay{
		lower:  filepath.Join(dir, "lower"),
		upper:  filepath.Join(dir, "upper"),
		work:   filepath.Join(dir, "work"),
		merged: filepath.Join(dir, "merged"),
	}
	for _, d := range []string{o.lower, o.upper, o.work, o.merged} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return o, err
		}
	}
	return o, nil
}

// mount mounts the overlay with the given options. Only helpers call it,
// after privateMounts.
func (o overlay) mount(opts string) error {
	data := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s,%s", o.lower, o.upper, o.work, opts)
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
