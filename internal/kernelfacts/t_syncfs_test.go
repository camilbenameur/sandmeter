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

// T-syncfs: the price of mounting per command.
//
// Unmounting an overlay makes the kernel sync the filesystem of its upper
// directory, which is the state filesystem of the host with everybody
// else's dirty pages. The design accepts that cost, answers the client
// before it unmounts, and reports the time as its own benchmark row. This
// test records what the cost is on each runner. It decides nothing.

// syncfsReport holds the time of one unmount per workload, in milliseconds.
type syncfsReport struct {
	Idle    float64 `json:"idle"`    // nothing written
	Bulk    float64 `json:"bulk"`    // after one file of 50 MiB
	Small   float64 `json:"small"`   // after 5,000 files of 128 bytes
	Remount string  `json:"remount"` // a mount of the same directories right after the last unmount
}

const (
	syncfsBulk  = 50 << 20
	syncfsSmall = 5000
)

// childSyncfs runs in a private mount namespace. args: directory.
func childSyncfs(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: tsyncfs DIR")
	}
	if err := privateMounts(); err != nil {
		return err
	}
	// unmountAfter mounts a fresh overlay, lets write fill it through the
	// merged directory, and times the unmount alone.
	unmountAfter := func(name string, write func(merged string) error) (overlay, float64, error) {
		o, err := makeOverlay(filepath.Join(args[0], name))
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

	var rep syncfsReport
	var err error
	if _, rep.Idle, err = unmountAfter("idle", func(string) error { return nil }); err != nil {
		return err
	}
	if _, rep.Bulk, err = unmountAfter("bulk", func(merged string) error {
		n, how := fill(filepath.Join(merged, "bulk"), syncfsBulk)
		if n < syncfsBulk {
			return fmt.Errorf("wrote %d of %d bytes: %s", n, syncfsBulk, how)
		}
		return nil
	}); err != nil {
		return err
	}
	last, small, err := unmountAfter("small", func(merged string) error {
		content := make([]byte, 128)
		for i := range syncfsSmall {
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
	return sayResult(rep)
}

func TestSyncfsOnUnmount(t *testing.T) {
	r := declare(t, "T-syncfs")
	r.needRoot()

	dir := scratch(t, "tsyncfs")
	var rep syncfsReport
	if err := runChild(t, spawn{name: "tsyncfs", args: []string{dir}, clone: unix.CLONE_NEWNS}, &rep); err != nil {
		r.skip("T-syncfs", "the measurement did not complete on %s: %v", fsTypeOf(dir), err)
		return
	}
	r.judge("T-syncfs", rep.Bulk < 1000 && rep.Small < 1000,
		"on %s, umount of an overlay took %.1f ms with nothing written, %.1f ms after one file of 50 MiB, %.1f ms after 5,000 files of 128 bytes; mounting the same directories again at once: %s",
		fsTypeOf(dir), rep.Idle, rep.Bulk, rep.Small, rep.Remount)
}
