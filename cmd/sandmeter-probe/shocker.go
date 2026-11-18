package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// runShocker checks whether the open_by_handle_at primitive used by the
// 2014 "Shocker" Docker breakout is reachable at all: get a file handle
// for "/" with name_to_handle_at, then try to resolve it back with
// open_by_handle_at. It does not brute-force other inodes; that part of
// the original technique needed only the same two syscalls, repeated.
func runShocker() error {
	handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, "/", 0)
	if err != nil {
		return fmt.Errorf("name_to_handle_at(/): %w", err)
	}

	// open_by_handle_at needs any open fd on the mount the handle belongs
	// to, not necessarily the fd the handle came from.
	mountFD, err := unix.Open("/", unix.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("open mount fd: %w", err)
	}
	defer unix.Close(mountFD)

	fd, err := unix.OpenByHandleAt(mountFD, handle, unix.O_RDONLY)
	if err != nil {
		return fmt.Errorf("open_by_handle_at(/): %w", err)
	}
	defer unix.Close(fd)

	fmt.Println("open_by_handle_at on a handle of / succeeded")
	return nil
}
