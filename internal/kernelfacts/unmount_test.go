//go:build integration && linux

package kernelfacts

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The price of mounting per command.
//
// Unmounting an overlay makes the kernel sync the filesystem of its upper
// directory, which is the state filesystem of the host with everybody
// else's dirty pages. The design accepts that cost, answers the client
// before it unmounts, and reports the time as its own benchmark row. This
// test records what the cost is on each runner. It decides nothing.

// unmountReport holds the time of one unmount per workload, in milliseconds.
type unmountReport struct {
	Idle    float64 `json:"idle"`    // nothing written
	Bulk    float64 `json:"bulk"`    // after one file of 50 MiB
	Small   float64 `json:"small"`   // after 5,000 files of 128 bytes
	Remount string  `json:"remount"` // a mount of the same directories right after that unmount
	Large   float64 `json:"large"`   // after one file of 500 MiB; -1 when it was not measured
	NoLarge string  `json:"nolarge"` // why it was not
}

const (
	unmountBulk  = 50 << 20
	unmountSmall = 5000
	unmountLarge = 500 << 20
	// unmountRoom is the free space below which the large file is not
	// written: the test must not be what fills the disk of a host.
	unmountRoom = 2 << 30
)

// childUnmount runs in a private mount namespace. args: directory.
func childUnmount(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: unmount DIR")
	}
	if err := privateMounts(); err != nil {
		return err
	}
	// unmountAfter mounts a fresh overlay, lets write fill it through the
	// merged directory, and times the unmount alone.
	unmountAfter := func(name string, write func(merged string) error) (stack, float64, error) {
		o, err := makeStack(filepath.Join(args[0], name), filepath.Join(args[0], name))
		if err != nil {
			return o, 0, err
		}
		if err := o.mount(overlayOpts); err != nil {
			return o, 0, err
		}
		if err := write(o.merged); err != nil {
			_ = o.unmount()
			return o, 0, fmt.Errorf("%s: %w", name, err)
		}
		start := time.Now()
		if err := o.unmount(); err != nil {
			return o, 0, err
		}
		return o, since(start), nil
	}

	var rep unmountReport
	var err error
	if _, rep.Idle, err = unmountAfter("idle", func(string) error { return nil }); err != nil {
		return err
	}
	if _, rep.Bulk, err = unmountAfter("bulk", func(merged string) error {
		n, how := fill(filepath.Join(merged, "bulk"), unmountBulk)
		if n < unmountBulk {
			return fmt.Errorf("wrote %d of %d bytes: %s", n, unmountBulk, how)
		}
		return nil
	}); err != nil {
		return err
	}
	last, small, err := unmountAfter("small", func(merged string) error {
		content := make([]byte, 128)
		for i := range unmountSmall {
			if err := os.WriteFile(filepath.Join(merged, fmt.Sprintf("f-%05d", i)), content, 0o644); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	rep.Small = small

	// The next command mounts the same directories at once.
	err = last.mount(overlayOpts)
	rep.Remount = errnoName(err)
	if err == nil {
		_ = last.unmount()
	}

	// The large file last: nothing else is timed behind its dirty pages.
	rep.Large = -1
	var st unix.Statfs_t
	if err := unix.Statfs(args[0], &st); err != nil {
		rep.NoLarge = "statfs: " + errnoName(err)
	} else if free := st.Bavail * uint64(st.Bsize); free < unmountRoom {
		rep.NoLarge = fmt.Sprintf("only %d MiB are free on the filesystem", free>>20)
	} else if _, rep.Large, err = unmountAfter("large", func(merged string) error {
		n, how := fill(filepath.Join(merged, "large"), unmountLarge)
		if n < unmountLarge {
			return fmt.Errorf("wrote %d of %d bytes: %s", n, unmountLarge, how)
		}
		return nil
	}); err != nil {
		rep.Large, rep.NoLarge = -1, err.Error()
	}
	return sayResult(rep)
}

// largeRow prints the row of the 500 MiB file.
func largeRow(rep unmountReport) string {
	if rep.Large < 0 {
		return "not measured (" + rep.NoLarge + ")"
	}
	return fmt.Sprintf("%.1f ms", rep.Large)
}

func TestUnmountTime(t *testing.T) {
	r := declare(t, "overlay-unmount-time")
	r.needRoot()

	dir := scratch(t, "unmount")
	var rep unmountReport
	if err := runChild(t, spawn{name: "unmount", args: []string{dir}, clone: unix.CLONE_NEWNS}, &rep); err != nil {
		r.skip("overlay-unmount-time", "the measurement did not complete on %s: %v", fsTypeOf(dir), err)
		return
	}
	r.judge("overlay-unmount-time", rep.Bulk < 1000 && rep.Small < 1000,
		"on %s, umount of an overlay took %.1f ms with nothing written, %.1f ms after one file of 50 MiB, %.1f ms after 5,000 files of 128 bytes; mounting the same directories again at once: %s; after one file of 500 MiB, which is not part of the verdict: %s",
		fsTypeOf(dir), rep.Idle, rep.Bulk, rep.Small, rep.Remount, largeRow(rep))
}
