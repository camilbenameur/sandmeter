package main

import (
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// runUsernsMount creates a nested user namespace and mount namespace,
// writes identity uid/gid maps (mapping its own uid/gid to 0 inside), and
// tries to mount a tmpfs under that fake root. It imitates a process
// regaining "root" through CLONE_NEWUSER and then using that root to do
// something privileged, rather than anything that touches the outer
// sandbox's own mounts.
func runUsernsMount() error {
	uid := os.Getuid()
	gid := os.Getgid()

	if err := unix.Unshare(unix.CLONE_NEWUSER | unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("unshare(CLONE_NEWUSER|CLONE_NEWNS): %w", err)
	}

	if err := writeIDMap("/proc/self/uid_map", uid); err != nil {
		return fmt.Errorf("write uid_map: %w", err)
	}
	// An unprivileged process must give up CAP_SETGID in the new
	// namespace (by denying setgroups) before the kernel allows it to
	// write gid_map at all.
	if err := os.WriteFile("/proc/self/setgroups", []byte("deny"), 0); err != nil {
		return fmt.Errorf("write setgroups=deny: %w", err)
	}
	if err := writeIDMap("/proc/self/gid_map", gid); err != nil {
		return fmt.Errorf("write gid_map: %w", err)
	}

	dir, err := os.MkdirTemp("", "rfprobe-userns-*")
	if err != nil {
		return fmt.Errorf("make mount point: %w", err)
	}
	defer os.RemoveAll(dir)

	if err := unix.Mount("none", dir, "tmpfs", 0, ""); err != nil {
		return fmt.Errorf("mount tmpfs in nested userns: %w", err)
	}
	unix.Unmount(dir, 0)

	fmt.Println("mounted tmpfs after unshare(CLONE_NEWUSER|CLONE_NEWNS)")
	return nil
}

// writeIDMap maps a single id to itself: "0 <id> 1" inside the file means
// uid/gid 0 inside the namespace is id outside it.
func writeIDMap(path string, id int) error {
	line := "0 " + strconv.Itoa(id) + " 1\n"
	return os.WriteFile(path, []byte(line), 0)
}
