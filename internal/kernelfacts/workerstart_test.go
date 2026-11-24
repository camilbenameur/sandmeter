//go:build integration && linux

package kernelfacts

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Two more things about the worker, which decide nothing by themselves.
//
// Its mount namespace is made a slave of the host's, not a private copy:
// what the worker mounts stays with the worker, and what the host mounts
// afterwards still reaches it. A private copy would be frozen at the start
// of the worker, without a disk plugged in or a home directory mounted
// later. That direction of the propagation is recorded here. It needs a
// mount made on the host itself, so it only runs on a throwaway host.
//
// And a worker is started for every connection, so the time from the clone
// to a worker that is ready is paid by every command. It is recorded as a
// number, for a process that does what a worker does first and nothing
// else.

// lateMarker is the content of the file on the mount the host makes late.
const lateMarker = "mounted by the host after the worker started"

// lateView is what the worker sees at the mount point at one moment.
type lateView struct {
	Mounted string `json:"mounted"` // filesystem mounted at the point, or "nothing"
	Marker  string `json:"marker"`  // the marker file there, or the errno
	Parent  string `json:"parent"`  // propagation of the mount that holds the point, "private" when it has none
}

// propagationOf prints the propagation of the mount a path lives on.
func propagationOf(path string) string {
	e, ok := mountHolding(parseMountinfo(mountinfoText()), path)
	switch {
	case !ok:
		return "unknown"
	case e.propagation == "":
		return "private"
	default:
		return e.propagation
	}
}

// childLateMount is a worker that mounts nothing and looks three times at
// a directory: when it is ready, and each time the test nudges it. args:
// the directory.
func childLateMount(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: latemount POINT")
	}
	point := args[0]
	if err := privateMounts(); err != nil {
		return err
	}
	look := func() lateView {
		return lateView{
			Mounted: mountedOn(point),
			Marker:  contentOf(filepath.Join(point, "marker")),
			Parent:  propagationOf(filepath.Dir(point)),
		}
	}
	if err := sayReady(look()); err != nil {
		return err
	}
	if !waitNudge() {
		return errors.New("the test let go before the host mounted anything")
	}
	if err := say("seen ", look()); err != nil {
		return err
	}
	if !waitNudge() {
		return errors.New("the test let go before the host unmounted")
	}
	return sayResult(look())
}

func TestWorkerSeesHostMounts(t *testing.T) {
	r := declare(t, "worker-sees-host-mounts")
	r.needRoot()
	if !throwawayHost() {
		r.skip("worker-sees-host-mounts", "not a throwaway host: this test mounts a tmpfs in the mount namespace of the host for a moment (set CI=true and %s=1)", throwawayEnv)
		return
	}

	point := filepath.Join(scratch(t, "latemount"), "late")
	if err := os.Mkdir(point, 0o755); err != nil {
		t.Fatalf("mount point: %v", err)
	}
	hostParent := propagationOf(filepath.Dir(point))
	c, err := spawnChild(t, spawn{name: "latemount", args: []string{point}, clone: unix.CLONE_NEWNS})
	if err != nil {
		r.skip("worker-sees-host-mounts", "a helper in a new mount namespace did not start: %v", err)
		return
	}
	var before lateView
	if err := c.ready(&before); err != nil {
		r.skip("worker-sees-host-mounts", "the worker did not get ready: %v", err)
		return
	}

	// The one mount of this package that is made in the mount namespace of
	// the host. It is undone a few lines below, and by the cleanup when the
	// test does not get there.
	mounted := false
	t.Cleanup(func() {
		if !mounted {
			return
		}
		if err := unix.Unmount(point, unix.MNT_DETACH); err != nil {
			t.Errorf("the tmpfs this test mounted on the host at %s could NOT be unmounted: %v. Unmount it by hand.", point, err)
		}
	})
	if err := unix.Mount("tmpfs", point, "tmpfs", unix.MS_NODEV|unix.MS_NOSUID|unix.MS_NOEXEC, "size=1m,mode=0755"); err != nil {
		r.skip("worker-sees-host-mounts", "a tmpfs could not be mounted on the host at %s: %v", point, err)
		return
	}
	mounted = true
	if err := os.WriteFile(filepath.Join(point, "marker"), []byte(lateMarker), 0o644); err != nil {
		t.Errorf("marker on the late mount: %v", err)
	}

	var during, after lateView
	seenErr := c.nudge()
	if seenErr == nil {
		seenErr = c.message("seen ", &during, readyTimeout)
	}
	// Unmounted whatever the worker said, before anything is judged.
	if err := unix.Unmount(point, 0); err != nil {
		t.Errorf("unmount the late mount from the host: %v", err)
	} else {
		mounted = false
	}
	if seenErr != nil {
		r.skip("worker-sees-host-mounts", "the worker did not look at the mount the host made: %v", seenErr)
		return
	}
	if err := c.nudge(); err != nil {
		r.skip("worker-sees-host-mounts", "the worker could not be told that the host unmounted: %v", err)
		return
	}
	if err := c.result(&after); err != nil {
		r.skip("worker-sees-host-mounts", "the worker did not look after the host unmounted: %v", err)
		return
	}

	r.judge("worker-sees-host-mounts",
		before.Mounted == "nothing" && during.Mounted == "tmpfs" && during.Marker == lateMarker && after.Mounted == "nothing",
		"the mount that holds the directory is %s on the host and %s in the worker, after MS_REC|MS_SLAVE on /; at the directory the worker saw %s before the host mounted a tmpfs there, %s with a marker file that reads %q while it was mounted (expected tmpfs and %q), and %s after the host unmounted it",
		hostParent, before.Parent, before.Mounted, during.Mounted, during.Marker, lateMarker, after.Mounted)
}

// workerReadyFD is the descriptor on which a timed worker says it is ready.
const workerReadyFD = 3

// childWorkerStart does what a worker does first, says so with one byte and
// waits to be let go.
func childWorkerStart([]string) error {
	if err := privateMounts(); err != nil {
		return err
	}
	if _, err := unix.Write(workerReadyFD, []byte{1}); err != nil {
		return fmt.Errorf("report readiness: %w", err)
	}
	waitRelease()
	return nil
}

// workerStarts is how many workers are timed.
const workerStarts = 40

// percentile returns the smallest sample that at least p percent of the
// samples do not exceed.
func percentile(samples []time.Duration, p int) time.Duration {
	sorted := slices.Sorted(slices.Values(samples))
	rank := (p*len(sorted) + 99) / 100
	return sorted[max(rank, 1)-1]
}

// timeWorkerStart creates a cgroup, clones a worker into it in a new mount
// namespace, and returns the time until the worker said it was ready.
func timeWorkerStart(dir, group string) (elapsed time.Duration, err error) {
	ready, theirs, err := os.Pipe()
	if err != nil {
		return 0, err
	}
	defer ready.Close()

	start := time.Now()
	if err := os.Mkdir(group, 0o755); err != nil {
		theirs.Close()
		return 0, err
	}
	defer func() { err = errors.Join(err, cgRemove(group)) }()
	c, err := startChild(dir, spawn{name: "workerstart", clone: unix.CLONE_NEWNS, cgroup: group, files: []*os.File{theirs}})
	theirs.Close()
	if err != nil {
		return 0, err
	}
	defer c.stop()
	if err := ready.SetReadDeadline(time.Now().Add(readyTimeout)); err != nil {
		return 0, err
	}
	var b [1]byte
	if _, err := io.ReadFull(ready, b[:]); err != nil {
		return 0, fmt.Errorf("the worker did not say it was ready: %w; its stderr: %q", err, c.stderr())
	}
	return time.Since(start), nil
}

func TestWorkerStartTime(t *testing.T) {
	r := declare(t, "worker-start-time")
	r.needRoot()
	r.needCgroup2()

	parent, err := cgParent()
	if err != nil {
		r.skip("worker-start-time", "the parent cgroup of this run could not be created: %v", err)
		return
	}
	dir := t.TempDir()
	var samples []time.Duration
	for i := range workerStarts {
		d, err := timeWorkerStart(dir, filepath.Join(parent, fmt.Sprintf("start-%d", i)))
		if err != nil {
			r.skip("worker-start-time", "start %d of %d did not complete: %v", i+1, workerStarts, err)
			return
		}
		samples = append(samples, d)
	}
	size := "unknown"
	if fi, err := os.Stat("/proc/self/exe"); err == nil {
		size = fmt.Sprintf("%.1f MiB", float64(fi.Size())/(1<<20))
	}
	p95 := percentile(samples, 95)
	r.judge("worker-start-time", p95 < 100*time.Millisecond,
		"%d starts, each one a new cgroup, clone3 with CLONE_NEWNS and CLONE_INTO_CGROUP, the exec of this test binary (%s), MS_REC|MS_SLAVE on / and one byte back: median %s, 95th percentile %s (the limit is 100 ms), slowest %s",
		workerStarts, size, millis(percentile(samples, 50)), millis(p95), millis(slices.Max(samples)))
}

// The percentile of the fact, on samples whose answer is known.
func TestSelfPercentile(t *testing.T) {
	var samples []time.Duration
	for i := 40; i >= 1; i-- { // 1 ms to 40 ms, out of order
		samples = append(samples, time.Duration(i)*time.Millisecond)
	}
	for p, want := range map[int]time.Duration{50: 20 * time.Millisecond, 95: 38 * time.Millisecond, 100: 40 * time.Millisecond, 1: time.Millisecond} {
		if got := percentile(samples, p); got != want {
			t.Errorf("percentile %d of 1..40 ms = %v, want %v", p, got, want)
		}
	}
	if got := percentile([]time.Duration{7 * time.Millisecond}, 95); got != 7*time.Millisecond {
		t.Errorf("percentile 95 of one sample = %v", got)
	}
	// The mount that holds a path, in the mount table of this process.
	if got := propagationOf("/"); got == "unknown" {
		t.Errorf("propagationOf(/) = %q: no mount holds / in the mount table of this process", got)
	}
}
