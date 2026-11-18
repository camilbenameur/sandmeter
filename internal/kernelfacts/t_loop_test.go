//go:build integration && linux

package kernelfacts

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// T-loop: the loop-image quota, which v0.1.0 leaves out.
//
// A per-session ext4 image on a loop device would bound bytes and inodes on
// any host filesystem. v0.1.0 does not ship it: the free-space floor is
// always on and the tmpfs quota is opt-in (K9). This test records what the
// driver would cost and whether the kernel takes the device back by itself,
// after an unmount and after the death of the process that holds the mount,
// so that the decision for the next release starts from measurements.

const loopImageSize = 2 << 30 // sparse: only what is written is allocated

// loopReport is what the helper measured. Times are in milliseconds.
type loopReport struct {
	Step      string  `json:"step"`      // "" when every step worked, else the first that failed and why
	Number    int     `json:"number"`    // the loop device, -1 before one was attached
	Flags     string  `json:"flags"`     // what the kernel reports of the flags asked
	Sparse    float64 `json:"sparse"`    // create the image
	Mkfs      float64 `json:"mkfs"`      // mkfs.ext4, lazy tables, no journal
	Configure float64 `json:"configure"` // LOOP_CTL_GET_FREE and LOOP_CONFIGURE
	Mount     float64 `json:"mount"`     // mount the image
	Overlay   float64 `json:"overlay"`   // mount an overlay whose upper directory is on it
	Write     string  `json:"write"`     // a write through that overlay
	Unmount   float64 `json:"unmount"`   // unmount both
	Released  float64 `json:"released"`  // until the device had no backing file; -1 when it still had one after 2 s
}

// attachLoop binds the open file to a free loop device with autoclear: the
// kernel detaches the device when its last user (here, the mount) is gone.
// It returns the device number and an open descriptor of the device.
func attachLoop(backing int) (number, fd int, err error) {
	ctl, err := unix.Open("/dev/loop-control", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, -1, fmt.Errorf("open /dev/loop-control: %w", err)
	}
	defer unix.Close(ctl)
	for range 8 {
		number, err = unix.IoctlRetInt(ctl, unix.LOOP_CTL_GET_FREE)
		if err != nil {
			return -1, -1, fmt.Errorf("LOOP_CTL_GET_FREE: %w", err)
		}
		fd, err = unix.Open(fmt.Sprintf("/dev/loop%d", number), unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			return -1, -1, fmt.Errorf("open /dev/loop%d: %w", number, err)
		}
		// Direct I/O first, as the design asks; a backing file that cannot
		// do it is still worth measuring.
		for _, flags := range []uint32{unix.LO_FLAGS_AUTOCLEAR | unix.LO_FLAGS_DIRECT_IO, unix.LO_FLAGS_AUTOCLEAR} {
			cfg := unix.LoopConfig{Fd: uint32(backing), Info: unix.LoopInfo64{Flags: flags}}
			if err = unix.IoctlLoopConfigure(fd, &cfg); err == nil {
				return number, fd, nil
			}
			if !errors.Is(err, unix.EINVAL) {
				break
			}
		}
		unix.Close(fd)
		if !errors.Is(err, unix.EBUSY) {
			return -1, -1, fmt.Errorf("LOOP_CONFIGURE on /dev/loop%d: %w", number, err)
		}
		// Somebody took the device between the two calls: ask again.
	}
	return -1, -1, fmt.Errorf("LOOP_CONFIGURE: %w", err)
}

// loopFlagNames prints the flags of a loop device that matter here.
func loopFlagNames(flags uint32) string {
	var names []string
	if flags&unix.LO_FLAGS_AUTOCLEAR != 0 {
		names = append(names, "autoclear")
	}
	if flags&unix.LO_FLAGS_DIRECT_IO != 0 {
		names = append(names, "direct I/O")
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

// childLoop runs in a private mount namespace.
// args: directory, mkfs.ext4, and "unmount" or "hold".
func childLoop(args []string) error {
	if len(args) != 3 {
		return errors.New("usage: tloop DIR MKFS unmount|hold")
	}
	dir, mkfs, mode := args[0], args[1], args[2]
	if err := privateMounts(); err != nil {
		return err
	}
	rep := loopReport{Number: -1, Released: -1, Write: "not tried"}
	failed := func(step string, err error) error {
		rep.Step = step + ": " + errnoName(err)
		return sayResult(rep)
	}

	start := time.Now()
	image, err := os.OpenFile(filepath.Join(dir, "image"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return failed("create the image", err)
	}
	defer image.Close()
	if err := image.Truncate(loopImageSize); err != nil {
		return failed("size the image", err)
	}
	rep.Sparse = since(start)

	start = time.Now()
	out, err := exec.Command(mkfs, "-q", "-F", "-t", "ext4", "-m", "0", "-O", "^has_journal",
		"-E", "lazy_itable_init=1,nodiscard", image.Name()).CombinedOutput()
	if err != nil {
		rep.Step = fmt.Sprintf("%s: %v: %s", mkfs, err, strings.TrimSpace(string(out)))
		return sayResult(rep)
	}
	rep.Mkfs = since(start)

	start = time.Now()
	number, loopfd, err := attachLoop(int(image.Fd()))
	if err != nil {
		return failed("attach a loop device", err)
	}
	rep.Number, rep.Configure = number, since(start)
	if info, err := unix.IoctlLoopGetStatus64(loopfd); err == nil {
		rep.Flags = loopFlagNames(info.Flags)
	}

	mnt := filepath.Join(dir, "mnt")
	if err := os.Mkdir(mnt, 0o700); err != nil {
		unix.Close(loopfd)
		return err
	}
	start = time.Now()
	err = unix.Mount(fmt.Sprintf("/dev/loop%d", number), mnt, "ext4", unix.MS_NODEV|unix.MS_NOSUID, "")
	// From here the mount is the device's only user. Had the descriptor
	// been closed before the mount, autoclear would already have fired.
	unix.Close(loopfd)
	if err != nil {
		return failed("mount the image", err)
	}
	rep.Mount = since(start)

	o := overlay{
		lower:  filepath.Join(dir, "lower"),
		upper:  filepath.Join(mnt, "upper"),
		work:   filepath.Join(mnt, "work"),
		merged: filepath.Join(dir, "merged"),
	}
	for _, d := range []string{o.lower, o.upper, o.work, o.merged} {
		if err := os.Mkdir(d, 0o755); err != nil {
			_ = unix.Unmount(mnt, 0)
			return err
		}
	}
	start = time.Now()
	if err := o.mount(overlayOpts); err != nil {
		_ = unix.Unmount(mnt, 0)
		return failed("mount an overlay on the image", err)
	}
	rep.Overlay = since(start)
	rep.Write = errnoName(os.WriteFile(filepath.Join(o.merged, "written"), []byte("on the image"), 0o644))

	if mode == "hold" {
		if err := sayReady(rep); err != nil {
			return err
		}
		waitRelease()
		return nil
	}

	start = time.Now()
	if err := o.unmount(); err != nil {
		return failed("unmount the overlay", err)
	}
	if err := unix.Unmount(mnt, 0); err != nil {
		return failed("unmount the image", err)
	}
	rep.Unmount = since(start)
	start = time.Now()
	if poll(2*time.Second, func() bool { return loopBacking(number) == "" }) {
		rep.Released = since(start)
	}
	return sayResult(rep)
}

// loopBacking is the backing file of one loop device, "" when it has none.
func loopBacking(number int) string {
	s, err := readTrim(fmt.Sprintf("/sys/block/loop%d/loop/backing_file", number))
	if err != nil {
		return ""
	}
	return s
}

// detachLoopsUnder detaches every loop device whose backing file is under
// dir: what a start-up sweep of the service would do.
func detachLoopsUnder(t *testing.T, dir string) {
	for name, backing := range boundLoops() {
		if !strings.HasPrefix(backing, dir+"/") {
			continue
		}
		fd, err := unix.Open("/dev/"+name, unix.O_RDWR|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Errorf("%s is still attached to %s and cannot be opened: %v", name, backing, err)
			continue
		}
		if err := unix.IoctlSetInt(fd, unix.LOOP_CLR_FD, 0); err != nil {
			t.Errorf("%s is still attached to %s and LOOP_CLR_FD failed: %v", name, backing, err)
		}
		unix.Close(fd)
	}
}

// removeLoopsNotIn removes the loop devices that did not exist before the
// test and have no backing file: LOOP_CTL_GET_FREE creates a device when
// every existing one is taken, and the test leaves the host as it found it.
func removeLoopsNotIn(t *testing.T, before []string) {
	ctl, err := unix.Open("/dev/loop-control", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	defer unix.Close(ctl)
	bound := boundLoops()
	for _, name := range loopNames() {
		if _, attached := bound[name]; attached || slices.Contains(before, name) {
			continue
		}
		number, err := strconv.Atoi(strings.TrimPrefix(name, "loop"))
		if err != nil {
			continue
		}
		// EBUSY while udev still looks at the new device.
		var last error
		if !poll(2*time.Second, func() bool {
			last = unix.IoctlSetInt(ctl, unix.LOOP_CTL_REMOVE, number)
			return last == nil
		}) {
			t.Logf("the unattached device %s, created by this test, could not be removed: %v", name, last)
		}
	}
}

func (rep loopReport) String() string {
	return fmt.Sprintf("sparse 2 GiB image %.1f ms, mkfs.ext4 without journal and with lazy tables %.1f ms, LOOP_CONFIGURE %.1f ms (loop%d, flags in force: %s), mount %.1f ms, overlay on it %.1f ms, write through the overlay: %s",
		rep.Sparse, rep.Mkfs, rep.Configure, rep.Number, rep.Flags, rep.Mount, rep.Overlay, rep.Write)
}

func TestLoopImage(t *testing.T) {
	r := declare(t, "T-loop", "T-loop-kill")
	r.needRoot()
	mkfs, err := exec.LookPath("mkfs.ext4")
	if err != nil {
		r.skipRest("mkfs.ext4 is not installed")
		return
	}
	if !exists("/dev/loop-control") {
		r.skipRest("/dev/loop-control does not exist")
		return
	}

	before := loopNames()
	dir := scratch(t, "tloop")
	// Registered after scratch, so it runs before the directory is removed.
	t.Cleanup(func() {
		detachLoopsUnder(t, dir)
		removeLoopsNotIn(t, before)
	})
	unmounted, held := filepath.Join(dir, "unmount"), filepath.Join(dir, "hold")
	for _, d := range []string{unmounted, held} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	var rep loopReport
	if err := runChild(t, spawn{name: "tloop", args: []string{unmounted, mkfs, "unmount"}, clone: unix.CLONE_NEWNS}, &rep); err != nil {
		r.skip("T-loop", "the measurement did not complete (image on %s): %v", fsTypeOf(dir), err)
	} else if rep.Step != "" {
		r.no("T-loop", "image on %s; failed at: %s; before that: %v", fsTypeOf(dir), rep.Step, rep)
	} else {
		released := "the device still had its backing file 2 s after the unmount"
		if rep.Released >= 0 {
			released = fmt.Sprintf("the device had no backing file %.1f ms after the unmount", rep.Released)
		}
		r.judge("T-loop", rep.Write == "ok" && rep.Released >= 0,
			"image on %s; %v; unmount of both %.1f ms; %s", fsTypeOf(dir), rep, rep.Unmount, released)
	}

	c, err := spawnChild(t, spawn{name: "tloop", args: []string{held, mkfs, "hold"}, clone: unix.CLONE_NEWNS})
	if err != nil {
		r.skip("T-loop-kill", "the helper did not start: %v", err)
		return
	}
	var holding loopReport
	if err := c.ready(&holding); err != nil {
		r.skip("T-loop-kill", "the helper did not get as far as holding a mounted image: %v", err)
		return
	}
	backing := loopBacking(holding.Number)
	killed := time.Now()
	c.kill()
	released := poll(2*time.Second, func() bool { return loopBacking(holding.Number) == "" })
	r.judge("T-loop-kill", backing != "" && released,
		"loop%d was attached to %q while a process held the mounts in its mount namespace; after SIGKILL of that process the device had no backing file: %v, %s after the kill (limit 2 s)",
		holding.Number, backing, released, millis(time.Since(killed)))
}
