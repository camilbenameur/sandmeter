//go:build integration && linux

package kernelfacts

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// What the options of the overlay cost a command.
//
// redirect_dir=nofollow is what lets a lower tree change between two
// mounts, and it has a price the documentation of the product must state:
// rename(2) of a directory that comes from a lower layer answers EXDEV, as
// if the directory were moved to another filesystem. mv copies and carries
// on; a program that renames a directory and has no fallback fails.
//
// And when the upper directory is on another filesystem than the lower
// layers, as it is under the tmpfs quota, the device a file reports
// depends on xino. With it every file reports the device of the overlay.
// Without it an unmodified file reports a device of its own, and find
// -xdev, du -x or tar --one-file-system leave it out.
//
// Both are recorded, on both placements of the upper directory. They
// decide wording, not design.

// The entries a rename is tried on, and what the kernel documents for each.
var renameKinds = []struct{ kind, want string }{
	{"lower directory", "EXDEV"},
	{"merged directory", "EXDEV"},
	{"created directory", "ok"},
	{"lower file", "ok"},
}

// The entries whose device number is read.
var deviceKinds = []string{"lower file", "copied-up file", "created file", "lower directory"}

// limitsReport is what the helper found on one placement.
type limitsReport struct {
	Lower   string            `json:"lower"`   // filesystem of the lower layers
	Upper   string            `json:"upper"`   // filesystem of the upper directory
	Options string            `json:"options"` // overlay options as the kernel reports them
	Inodes  string            `json:"inodes"`  // how the overlay numbers a lower file: whether xino is in use
	Renames map[string]string `json:"renames"` // what rename(2) answered, by kind of entry
	Devices map[string]string `json:"devices"` // "overlay" when the entry reports the device of the mount point, else which
}

// deviceOf says whether a path reports the device of the overlay.
func deviceOf(path string, overlayDev uint64) string {
	dev, _, err := devIno(path)
	switch {
	case err != nil:
		return errnoName(err)
	case dev == overlayDev:
		return "overlay"
	default:
		return fmt.Sprintf("another (%#x)", dev)
	}
}

// childOverlayLimits runs in a private mount namespace. args: directory,
// and where the upper directory lives: "disk" or "tmpfs".
func childOverlayLimits(args []string) error {
	if len(args) != 2 || (args[1] != "disk" && args[1] != "tmpfs") {
		return errors.New("usage: overlaylimits DIR disk|tmpfs")
	}
	dir := args[0]
	if err := privateMounts(); err != nil {
		return err
	}
	upperDir := dir
	if args[1] == "tmpfs" {
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
	if err := writeTree(s.workspace(), tree{
		"lowdir": "d", "lowdir/a.txt": "f:a",
		"merged": "d", "merged/b.txt": "f:b",
		"file.txt": "f:file", "copied.txt": "f:copied",
	}); err != nil {
		return err
	}
	rep := limitsReport{Lower: fsTypeOf(s.project), Upper: fsTypeOf(s.upper), Renames: map[string]string{}, Devices: map[string]string{}}
	if err := s.mount(overlayOpts); err != nil {
		return err
	}
	rep.Options = s.reportedOptions()
	rep.Inodes = s.inodeNumbering("etc/issue")

	// What a command does: it writes into a directory of the project, makes
	// a directory of its own, changes a file and creates one.
	ws := filepath.Join(s.merged, "workspace")
	if err := errors.Join(
		os.WriteFile(filepath.Join(ws, "merged/new.txt"), []byte("new"), 0o644),
		os.Mkdir(filepath.Join(ws, "made"), 0o755),
		os.WriteFile(filepath.Join(ws, "made/x.txt"), []byte("x"), 0o644),
		os.WriteFile(filepath.Join(ws, "copied.txt"), []byte("changed"), 0o644),
		os.WriteFile(filepath.Join(ws, "created.txt"), []byte("created"), 0o644),
	); err != nil {
		return fmt.Errorf("writes through the overlay: %w", err)
	}

	overlayDev, _, err := devIno(s.merged)
	if err != nil {
		return fmt.Errorf("the mount point: %w", err)
	}
	for kind, rel := range map[string]string{
		"lower file": "file.txt", "copied-up file": "copied.txt", "created file": "created.txt", "lower directory": "lowdir",
	} {
		rep.Devices[kind] = deviceOf(filepath.Join(ws, rel), overlayDev)
	}
	for kind, rel := range map[string]string{
		"lower directory": "lowdir", "merged directory": "merged", "created directory": "made", "lower file": "file.txt",
	} {
		rep.Renames[kind] = errnoName(os.Rename(filepath.Join(ws, rel), filepath.Join(ws, rel+".moved")))
	}

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

// renamesAsDocumented reports whether every rename answered what the kernel
// documents for these options, and prints what each answered.
func renamesAsDocumented(renames map[string]string) (bool, string) {
	ok := true
	var out []string
	for _, k := range renameKinds {
		got, found := renames[k.kind]
		if !found {
			got = "not tried"
		}
		ok = ok && got == k.want
		out = append(out, fmt.Sprintf("%s: %s (expected %s)", k.kind, got, k.want))
	}
	return ok, strings.Join(out, ", ")
}

// devicesOfOverlay reports whether every entry reports the device of the
// overlay, and prints what each reports.
func devicesOfOverlay(devices map[string]string) (bool, string) {
	ok := true
	var out []string
	for _, kind := range deviceKinds {
		got, found := devices[kind]
		if !found {
			got = "not read"
		}
		ok = ok && got == "overlay"
		out = append(out, fmt.Sprintf("%s: %s", kind, got))
	}
	return ok, strings.Join(out, ", ")
}

func TestOverlayLimits(t *testing.T) {
	r := declare(t, "overlay-dir-rename", "overlay-device-numbers")
	r.needRoot()

	reps := map[string]limitsReport{}
	for _, upper := range []string{"disk", "tmpfs"} {
		dir := scratch(t, "limits-"+upper)
		var rep limitsReport
		if err := runChild(t, spawn{name: "overlaylimits", args: []string{dir, upper}, clone: unix.CLONE_NEWNS}, &rep); err != nil {
			r.skipRest("the measurement did not complete with the upper directory on %s (lower layers on %s): %v", upper, fsTypeOf(dir), err)
			return
		}
		reps[upper] = rep
	}
	disk, tmpfs := reps["disk"], reps["tmpfs"]

	diskRenames, diskSaid := renamesAsDocumented(disk.Renames)
	tmpfsRenames, tmpfsSaid := renamesAsDocumented(tmpfs.Renames)
	r.judge("overlay-dir-rename", diskRenames && tmpfsRenames,
		"mounted with %s; rename(2) in the project, upper directory on %s: %s; upper directory on %s: %s",
		overlayOpts, disk.Upper, diskSaid, tmpfs.Upper, tmpfsSaid)

	diskDevices, diskDev := devicesOfOverlay(disk.Devices)
	tmpfsDevices, tmpfsDev := devicesOfOverlay(tmpfs.Devices)
	r.judge("overlay-device-numbers", diskDevices && tmpfsDevices,
		"mounted with %s; lower layers on %s and upper directory on %s (the kernel reports %s; %s): %s; lower layers on %s and upper directory on %s (the kernel reports %s; %s): %s",
		overlayOpts, tmpfs.Lower, tmpfs.Upper, tmpfs.Options, tmpfs.Inodes, tmpfsDev,
		disk.Lower, disk.Upper, disk.Options, disk.Inodes, diskDev)
}

// The two verdicts, on answers written by hand.
func TestSelfOverlayLimitVerdicts(t *testing.T) {
	documented := map[string]string{"lower directory": "EXDEV", "merged directory": "EXDEV", "created directory": "ok", "lower file": "ok"}
	if ok, said := renamesAsDocumented(documented); !ok || !strings.Contains(said, "merged directory: EXDEV (expected EXDEV)") {
		t.Errorf("the documented answers are not accepted: %v, %s", ok, said)
	}
	redirected := map[string]string{"lower directory": "ok", "merged directory": "EXDEV", "created directory": "ok", "lower file": "ok"}
	if ok, said := renamesAsDocumented(redirected); ok || !strings.Contains(said, "lower directory: ok (expected EXDEV)") {
		t.Errorf("a lower directory that renames is not reported: %v, %s", ok, said)
	}
	if ok, said := renamesAsDocumented(nil); ok || !strings.Contains(said, "not tried") {
		t.Errorf("no answer at all is accepted: %v, %s", ok, said)
	}

	uniform := map[string]string{"lower file": "overlay", "copied-up file": "overlay", "created file": "overlay", "lower directory": "overlay"}
	if ok, _ := devicesOfOverlay(uniform); !ok {
		t.Errorf("four entries on the device of the overlay are not accepted")
	}
	mixed := map[string]string{"lower file": "another (0x2f)", "copied-up file": "overlay", "created file": "overlay", "lower directory": "overlay"}
	if ok, said := devicesOfOverlay(mixed); ok || !strings.Contains(said, "lower file: another (0x2f)") {
		t.Errorf("a lower file with a device of its own is not reported: %v, %s", ok, said)
	}

	// A file reports the device of the directory it is in, and not another.
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	dev, _, err := devIno(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := deviceOf(file, dev); got != "overlay" {
		t.Errorf("deviceOf a file against the device of its directory = %q", got)
	}
	if got := deviceOf(file, dev+1); !strings.HasPrefix(got, "another (") {
		t.Errorf("deviceOf a file against another device = %q", got)
	}
	if got := deviceOf(filepath.Join(dir, "absent"), dev); got != "ENOENT" {
		t.Errorf("deviceOf a missing file = %q, want ENOENT", got)
	}
}
