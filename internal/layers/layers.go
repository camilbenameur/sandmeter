//go:build linux

// Package layers manages the overlayfs stack of one sandbox: read-only image
// layers, a small base layer with mount points, frozen snapshot layers, and
// one writable upper layer.
//
// A snapshot freezes the current upper directory by renaming it into a
// read-only layer and starting a new empty upper on top. Restoring a snapshot
// rebuilds the lower stack from that snapshot down to the image. Both are
// O(1) in the amount of data written: nothing is copied. The cost is one more
// lower layer per snapshot, so the number of snapshots is capped.
package layers

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// MaxSnapshots bounds the chain length; overlayfs accepts up to 500 lower
// layers and the mount option string is limited to one page.
const MaxSnapshots = 64

// MountPoints are directories every sandbox root needs, created in the base
// layer so that creating them never shows up in the diff.
var MountPoints = []string{"dev", "proc", "sys", "tmp", "workspace", "etc"}

// Stack is the overlay of one sandbox. It is safe for concurrent use.
type Stack struct {
	mu      sync.Mutex
	dir     string
	image   []string // bottom first
	shift   uint32
	snaps   map[string]snapshot
	nextID  int
	parent  string // "" means the image itself
	mounted bool
}

type snapshot struct {
	dir    string
	parent string
}

// New creates the directories under dir (which must not exist) and mounts
// the overlay at Merged(). shift is the host uid/gid that root inside the
// sandbox maps to: the writable layer and the base layer belong to it.
func New(dir string, image []string, shift uint32, hosts []byte) (*Stack, error) {
	if len(image) == 0 {
		return nil, errors.New("layers: no image layers")
	}
	// 0711: the sandbox user must traverse it to reach merged/, but not list it.
	if err := os.Mkdir(dir, 0o711); err != nil {
		return nil, fmt.Errorf("layers: %w", err)
	}
	if err := os.Chmod(dir, 0o711); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("layers: %w", err)
	}
	s := &Stack{dir: dir, image: image, shift: shift, snaps: map[string]snapshot{}}
	if err := s.makeBase(hosts); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	for _, d := range []string{s.path("snap"), s.path("merged")} {
		if err := os.Mkdir(d, 0o700); err != nil {
			os.RemoveAll(dir)
			return nil, fmt.Errorf("layers: %w", err)
		}
	}
	// The merged root takes its owner and mode from the upper directory;
	// the sandbox's root user must be able to traverse it.
	if err := os.Chmod(s.path("merged"), 0o755); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("layers: %w", err)
	}
	if err := s.freshUpper(); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	if err := s.mount(); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	return s, nil
}

func (s *Stack) path(elem ...string) string {
	return filepath.Join(append([]string{s.dir}, elem...)...)
}

// makeBase writes the base layer: mount point directories and the files the
// host provides (/etc/hosts, /etc/hostname, an empty /etc/resolv.conf).
func (s *Stack) makeBase(hosts []byte) error {
	base := s.path("base")
	if err := os.Mkdir(base, 0o755); err != nil {
		return fmt.Errorf("layers: base: %w", err)
	}
	for _, d := range MountPoints {
		mode := os.FileMode(0o755)
		if d == "tmp" {
			mode = 0o1777 | os.ModeSticky
		}
		p := filepath.Join(base, d)
		if err := os.Mkdir(p, mode.Perm()); err != nil {
			return fmt.Errorf("layers: base: %w", err)
		}
		if d == "tmp" {
			if err := os.Chmod(p, os.ModeSticky|0o777); err != nil {
				return fmt.Errorf("layers: base: %w", err)
			}
		}
	}
	files := map[string][]byte{
		"etc/hosts":       append([]byte("127.0.0.1 localhost\n::1 localhost\n"), hosts...),
		"etc/hostname":    []byte("sandbox\n"),
		"etc/resolv.conf": nil,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(base, name), data, 0o644); err != nil {
			return fmt.Errorf("layers: base: %w", err)
		}
	}
	return s.chownTree(base)
}

// chownTree gives a directory tree we created ourselves to the sandbox root.
// It never runs on content the sandbox wrote.
func (s *Stack) chownTree(root string) error {
	if s.shift == 0 {
		return nil
	}
	return filepath.Walk(root, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, int(s.shift), int(s.shift))
	})
}

func (s *Stack) freshUpper() error {
	for _, d := range []string{"upper", "work"} {
		p := s.path(d)
		if err := os.RemoveAll(p); err != nil {
			return fmt.Errorf("layers: %w", err)
		}
		if err := os.Mkdir(p, 0o755); err != nil {
			return fmt.Errorf("layers: %w", err)
		}
	}
	if s.shift != 0 {
		if err := os.Lchown(s.path("upper"), int(s.shift), int(s.shift)); err != nil {
			return fmt.Errorf("layers: %w", err)
		}
	}
	return nil
}

// lowers returns the read-only layers, top first, as overlayfs wants them.
func (s *Stack) lowers() []string {
	var out []string
	for id := s.parent; id != ""; id = s.snaps[id].parent {
		out = append(out, s.snaps[id].dir)
	}
	out = append(out, s.path("base"))
	for i := len(s.image) - 1; i >= 0; i-- {
		out = append(out, s.image[i])
	}
	return out
}

func (s *Stack) mount() error {
	for _, l := range s.lowers() {
		if strings.ContainsAny(l, ",:") {
			return fmt.Errorf("layers: path %q contains ',' or ':'", l)
		}
	}
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s",
		strings.Join(s.lowers(), ":"), s.path("upper"), s.path("work"))
	if len(opts) >= unix.Getpagesize() {
		return fmt.Errorf("layers: overlay options too long (%d bytes): too many layers", len(opts))
	}
	if err := unix.Mount("overlay", s.path("merged"), "overlay", unix.MS_NODEV, opts); err != nil {
		return fmt.Errorf("layers: mount overlay: %w", err)
	}
	s.mounted = true
	return nil
}

func (s *Stack) unmount() error {
	if !s.mounted {
		return nil
	}
	if err := unix.Unmount(s.path("merged"), 0); err != nil {
		return fmt.Errorf("layers: unmount overlay: %w", err)
	}
	s.mounted = false
	return nil
}

// Merged is the mounted root filesystem.
func (s *Stack) Merged() string { return s.path("merged") }

// Layers returns the upper directory and every lower directory.
func (s *Stack) Layers() (string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.path("upper"), s.lowers()
}

// DiffBase names the layer the upper is relative to.
func (s *Stack) DiffBase() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.parent == "" {
		return "image"
	}
	return s.parent
}

// Snapshot freezes the upper layer. No command may run during the call.
func (s *Stack) Snapshot() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.snaps) >= MaxSnapshots {
		return "", fmt.Errorf("layers: at most %d snapshots", MaxSnapshots)
	}
	if err := s.unmount(); err != nil {
		return "", err
	}
	s.nextID++
	id := "s" + strconv.Itoa(s.nextID)
	dir := s.path("snap", id)
	if err := os.Rename(s.path("upper"), dir); err != nil {
		return "", errors.Join(fmt.Errorf("layers: snapshot: %w", err), s.mount())
	}
	s.snaps[id] = snapshot{dir: dir, parent: s.parent}
	s.parent = id
	if err := s.freshUpper(); err != nil {
		return "", err
	}
	return id, s.mount()
}

// Restore discards the upper layer and continues from snapshot id ("image"
// restores the original image). No command may run during the call.
func (s *Stack) Restore(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == "image" {
		id = ""
	}
	if _, ok := s.snaps[id]; id != "" && !ok {
		return fmt.Errorf("layers: unknown snapshot %q", id)
	}
	if err := s.unmount(); err != nil {
		return err
	}
	s.parent = id
	if err := s.freshUpper(); err != nil {
		return err
	}
	return s.mount()
}

// Close unmounts the overlay and deletes every layer this stack created.
// Image layers are left alone. os.RemoveAll does not follow symlinks, so
// links planted by the sandbox cannot redirect the deletion.
func (s *Stack) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.unmount(); err != nil {
		// Detach so a process still using the mount cannot block cleanup.
		if err2 := unix.Unmount(s.path("merged"), unix.MNT_DETACH); err2 != nil {
			return errors.Join(err, err2)
		}
		s.mounted = false
	}
	return os.RemoveAll(s.dir)
}
