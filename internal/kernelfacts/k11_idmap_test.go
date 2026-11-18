//go:build integration && linux

package kernelfacts

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// K11: the ID-mapped lower layer, which v0.1.0 leaves out.
//
// Nothing of v0.1.0 depends on it: the project comes in as a copy. This
// test only records, per filesystem and kernel, what the live variant would
// find, so that the next design starts from measurements:
//
//   - a detached clone of the project directory gets an ID map whose line
//     is "owner shifted 1": the kernel looks the on-disk owner up in the
//     first column and takes the second (Documentation/filesystems/
//     idmappings.rst);
//   - the clone is attached in the worker's mount namespace and becomes the
//     lower layer of an overlay whose upper directory belongs to the
//     shifted uid;
//   - a process in the sandbox's user namespace then sees the owner's files
//     as uid 0, and what it modifies is copied up owned by the shifted uid,
//     the project itself staying as it was.

// Group ids of the test files. They need no entry in any group database.
const (
	k11TeamGID  = 4242 // a second group of the owner, mapped
	k11StrayGID = 4343 // a group left out of the map
)

// k11Files are the files of the project, in the order they are reported.
var k11Files = []string{"own.txt", "team.txt", "stray.txt", "foreign.txt", "open.txt", "private.txt"}

// k11Entry is how one file looks from the sandbox's user namespace.
type k11Entry struct {
	Owner string `json:"owner"` // uid:gid
	Read  string `json:"read"`  // "ok" or an errno
	Write string `json:"write"` // "ok" or an errno, for an append
}

// k11ViewReport is what the process in the sandbox's user namespace saw.
type k11ViewReport struct {
	Entries map[string]k11Entry `json:"entries"`
	Create  string              `json:"create"` // creating a new file
}

// appendTo opens a file for appending and writes one byte.
func appendTo(path string) string {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return errnoName(err)
	}
	defer f.Close()
	_, err = f.Write([]byte("+"))
	return errnoName(err)
}

// childK11View runs in a user namespace that maps 0 to the shifted uid.
// args: the merged directory.
func childK11View(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: k11view DIR")
	}
	rep := k11ViewReport{Entries: map[string]k11Entry{}}
	for _, name := range k11Files {
		p := filepath.Join(args[0], name)
		_, err := os.ReadFile(p)
		rep.Entries[name] = k11Entry{Owner: ownerOf(p), Read: errnoName(err), Write: appendTo(p)}
	}
	rep.Create = errnoName(os.WriteFile(filepath.Join(args[0], "new.txt"), []byte("new"), 0o644))
	return sayResult(rep)
}

// k11Report is what the stand-in for the worker measured.
type k11Report struct {
	FS         string         `json:"fs"`          // filesystem of the project directory
	Map        string         `json:"map"`         // uid map of the mount
	Mount      string         `json:"mount"`       // "ok", or the call that failed and its errno
	MappedOwn  string         `json:"mapped_own"`  // owner of own.txt through the mapped mount, for host root
	MappedTeam string         `json:"mapped_team"` // owner of team.txt there
	MappedRoot string         `json:"mapped_root"` // owner of foreign.txt there
	Overlay    string         `json:"overlay"`     // mounting an overlay over the mapped clone
	View       *k11ViewReport `json:"view"`        // nil when the view did not run
	ViewErr    string         `json:"view_err"`
	UpperOwn   string         `json:"upper_own"`   // owner of the copy of own.txt in the upper directory
	UpperNew   string         `json:"upper_new"`   // owner of the new file there
	ProjectOwn string         `json:"project_own"` // owner and content of the project's own.txt at the end
}

// mappingNamespace returns a descriptor of a user namespace that carries
// the given maps and nothing else: the process that created it is gone when
// the function returns, and the descriptor keeps the namespace alive.
func mappingNamespace(uids, gids []syscall.SysProcIDMap) (int, error) {
	cmd := exec.Command("/proc/self/exe", childArg, "idle")
	hold, err := cmd.StdinPipe()
	if err != nil {
		return -1, err
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWUSER, UidMappings: uids, GidMappings: gids}
	if err := cmd.Start(); err != nil {
		return -1, fmt.Errorf("start a process in a new user namespace: %w", err)
	}
	defer func() {
		hold.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	fd, err := unix.Open(fmt.Sprintf("/proc/%d/ns/user", cmd.Process.Pid), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open its user namespace: %w", err)
	}
	return fd, nil
}

// idmapMount attaches at dst a clone of src whose ownership goes through
// the maps of the user namespace (mount_setattr(2)).
func idmapMount(src, dst string, userns int) string {
	clone, err := unix.OpenTree(unix.AT_FDCWD, src, unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC)
	if err != nil {
		return "open_tree: " + errnoName(err)
	}
	defer unix.Close(clone)
	attr := unix.MountAttr{Attr_set: unix.MOUNT_ATTR_IDMAP, Userns_fd: uint64(userns)}
	if err := unix.MountSetattr(clone, "", unix.AT_EMPTY_PATH, &attr); err != nil {
		return "mount_setattr: " + errnoName(err)
	}
	// The clone must be attached in the mount namespace of whoever mounts
	// the overlay: a detached mount cannot be a layer.
	if err := unix.MoveMount(clone, "", unix.AT_FDCWD, dst, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		return "move_mount: " + errnoName(err)
	}
	return "ok"
}

// childK11 runs as root in a private mount namespace.
// args: directory, uid and gid of the project's owner.
func childK11(args []string) error {
	if len(args) != 3 {
		return errors.New("usage: k11idmap DIR UID GID")
	}
	dir := args[0]
	uid, err := strconv.Atoi(args[1])
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(args[2])
	if err != nil {
		return err
	}
	if err := privateMounts(); err != nil {
		return err
	}

	proj := filepath.Join(dir, "proj")
	o := overlay{
		lower:  filepath.Join(dir, "mapped"),
		upper:  filepath.Join(dir, "upper"),
		work:   filepath.Join(dir, "work"),
		merged: filepath.Join(dir, "merged"),
	}
	for _, d := range []string{proj, o.lower, o.upper, o.work, o.merged} {
		if err := os.Mkdir(d, 0o755); err != nil {
			return err
		}
	}
	// The project of a developer: their own files, a file of a second
	// group of theirs, a file of a group the map does not know, and files
	// that belong to root.
	for _, f := range []struct {
		name     string
		uid, gid int
		mode     os.FileMode
	}{
		{"own.txt", uid, gid, 0o644},
		{"team.txt", uid, k11TeamGID, 0o640},
		{"stray.txt", uid, k11StrayGID, 0o640},
		{"foreign.txt", 0, 0, 0o644},
		{"open.txt", 0, 0, 0o666},
		{"private.txt", 0, 0, 0o600},
	} {
		p := filepath.Join(proj, f.name)
		if err := errors.Join(
			os.WriteFile(p, []byte(strings.TrimSuffix(f.name, ".txt")), 0o600),
			os.Chown(p, f.uid, f.gid),
			os.Chmod(p, f.mode),
		); err != nil {
			return err
		}
	}
	if err := errors.Join(os.Chown(proj, uid, gid), os.Chown(o.upper, idShift, idShift)); err != nil {
		return err
	}

	rep := k11Report{FS: fsTypeOf(proj), Map: fmt.Sprintf("%d %d 1", uid, idShift)}
	// uid: "owner shifted 1". gid: the owner's group to the shifted gid,
	// the second group to its own place in the sandbox's range.
	ns, err := mappingNamespace(
		[]syscall.SysProcIDMap{{ContainerID: uid, HostID: idShift, Size: 1}},
		[]syscall.SysProcIDMap{{ContainerID: gid, HostID: idShift, Size: 1}, {ContainerID: k11TeamGID, HostID: idShift + k11TeamGID, Size: 1}},
	)
	if err != nil {
		return err
	}
	defer unix.Close(ns)

	rep.Mount = idmapMount(proj, o.lower, ns)
	if rep.Mount != "ok" {
		return sayResult(rep)
	}
	defer func() { _ = unix.Unmount(o.lower, unix.MNT_DETACH) }()
	rep.MappedOwn = ownerOf(filepath.Join(o.lower, "own.txt"))
	rep.MappedTeam = ownerOf(filepath.Join(o.lower, "team.txt"))
	rep.MappedRoot = ownerOf(filepath.Join(o.lower, "foreign.txt"))

	if err := o.mount(overlayOpts); err != nil {
		rep.Overlay = errnoName(err)
		return sayResult(rep)
	}
	rep.Overlay = "ok"

	// The sandbox's side: a process in a user namespace where 0 is the
	// shifted uid, in this mount namespace.
	view := exec.Command("/proc/self/exe", childArg, "k11view", o.merged)
	attr := &syscall.SysProcAttr{}
	usernsAttr(attr)
	view.SysProcAttr = attr
	out, err := view.Output()
	if p, ok := findLine(out, "result "); ok && err == nil {
		rep.View = &k11ViewReport{}
		if err := json.Unmarshal(p, rep.View); err != nil {
			rep.View, rep.ViewErr = nil, err.Error()
		}
	} else {
		rep.ViewErr = fmt.Sprintf("the process in the sandbox's user namespace reported nothing: %v", err)
	}

	rep.UpperOwn = ownerOf(filepath.Join(o.upper, "own.txt"))
	rep.UpperNew = ownerOf(filepath.Join(o.upper, "new.txt"))
	if err := o.unmount(); err != nil {
		return err
	}
	rep.ProjectOwn = ownerOf(filepath.Join(proj, "own.txt")) + " " + strconv.Quote(contentOf(filepath.Join(proj, "own.txt")))
	return sayResult(rep)
}

// projectOwner picks the uid and gid that own the test project: the user
// who ran sudo, or 1000 when there is none.
func projectOwner() (uid, gid int) {
	uid, gid = 1000, 1000
	if n, err := strconv.Atoi(os.Getenv("SUDO_UID")); err == nil && n > 0 {
		uid = n
	}
	if n, err := strconv.Atoi(os.Getenv("SUDO_GID")); err == nil && n > 0 {
		gid = n
	}
	if gid == k11TeamGID || gid == k11StrayGID {
		gid += 1000 // keep the three groups distinct
	}
	return uid, gid
}

func TestK11IDMappedLower(t *testing.T) {
	r := declare(t, "K11-idmap", "K11-overlay", "K11-owners")
	r.needRoot()

	dir := scratch(t, "k11")
	uid, gid := projectOwner()
	var rep k11Report
	if err := runChild(t, spawn{name: "k11idmap", args: []string{dir, strconv.Itoa(uid), strconv.Itoa(gid)}, clone: unix.CLONE_NEWNS}, &rep); err != nil {
		r.skipRest("the experiment did not complete: %v", err)
		return
	}

	shifted := fmt.Sprintf("%d:%d", idShift, idShift)
	r.judge("K11-idmap", rep.Mount == "ok" && rep.MappedOwn == shifted,
		"project on %s, owned by %d:%d, uid map %q; open_tree, mount_setattr(MOUNT_ATTR_IDMAP), move_mount: %s; through the mapped mount host root sees own.txt as %s (expected %s), team.txt as %s, the root-owned file as %s",
		rep.FS, uid, gid, rep.Map, rep.Mount, rep.MappedOwn, shifted, rep.MappedTeam, rep.MappedRoot)
	if rep.Mount != "ok" {
		r.skipRest("no ID-mapped mount on %s: %s", rep.FS, rep.Mount)
		return
	}
	if rep.Overlay != "ok" || rep.View == nil {
		r.no("K11-overlay", "overlay over the ID-mapped clone on %s: %s; view from the sandbox's user namespace: %s", rep.FS, rep.Overlay, rep.ViewErr)
		r.skipRest("no view through an overlay over the ID-mapped clone")
		return
	}

	e := rep.View.Entries
	unchanged := fmt.Sprintf("%d:%d %q", uid, gid, "own")
	r.judge("K11-overlay", e["own.txt"].Owner == "0:0" && e["own.txt"].Read == "ok" && e["own.txt"].Write == "ok" &&
		rep.View.Create == "ok" && rep.UpperOwn == shifted && rep.UpperNew == shifted && rep.ProjectOwn == unchanged,
		"on %s with %s; in the sandbox's user namespace own.txt is owned by %s (expected 0:0), read: %s, append: %s, create a file: %s; in the upper directory the copy belongs to %s and the new file to %s (expected %s); the project's own.txt is %s (expected %s)",
		rep.FS, overlayOpts, e["own.txt"].Owner, e["own.txt"].Read, e["own.txt"].Write, rep.View.Create, rep.UpperOwn, rep.UpperNew, shifted, rep.ProjectOwn, unchanged)

	var all []string
	for _, name := range k11Files {
		all = append(all, fmt.Sprintf("%s owner %s read %s append %s", name, e[name].Owner, e[name].Read, e[name].Write))
	}
	r.judge("K11-owners",
		e["team.txt"].Read == "ok" && e["team.txt"].Write == "ok" &&
			e["foreign.txt"].Read == "ok" && e["foreign.txt"].Write != "ok" &&
			e["private.txt"].Read != "ok",
		"seen from the sandbox's user namespace (team.txt: owner's file in a mapped second group, 0640; stray.txt: in a group the map leaves out, 0640; foreign.txt: root 0644; open.txt: root 0666; private.txt: root 0600): %s",
		strings.Join(all, "; "))
}

// The probes of the view, on files that need no privilege.
func TestSelfK11Probes(t *testing.T) {
	file := filepath.Join(t.TempDir(), "own.txt")
	if err := os.WriteFile(file, []byte("own"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := appendTo(file); got != "ok" || contentOf(file) != "own+" {
		t.Errorf("appendTo = %q and the file reads %q; want ok and \"own+\"", got, contentOf(file))
	}
	if err := os.Chmod(file, 0o444); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if got := appendTo(file); got != "EACCES" {
			t.Errorf("appendTo on a read-only file = %q, want EACCES", got)
		}
	}
	if uid, gid := projectOwner(); uid <= 0 || gid <= 0 || gid == k11TeamGID || gid == k11StrayGID {
		t.Errorf("projectOwner = %d:%d: the owner must not be root and its group must differ from the two test groups", uid, gid)
	}
}
