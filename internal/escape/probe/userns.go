package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Hidden subcommands the re-exec'd child runs inside the new namespaces.
const (
	usernsChildArg = "__userns-child"
	noopArg        = "__noop"
)

// usernsCommand re-execs self in a new user and mount namespace, mapping
// uid/gid 0 inside to our own ids outside. The namespace must come from
// clone flags: unshare(CLONE_NEWUSER) returns EINVAL once a process has
// more than one thread, and the Go runtime always starts several.
func usernsCommand(arg string) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("find own path: %w", err)
	}
	cmd := exec.Command(self, arg)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	return cmd, nil
}

// startErrno extracts the errno from a failed cmd.Run, which wraps it in
// an *exec.Error or *os.PathError, or returns EIO.
func startErrno(err error) unix.Errno {
	for err != nil {
		if errno, ok := err.(unix.Errno); ok {
			return errno
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			break
		}
		err = u.Unwrap()
	}
	return unix.EIO
}

// runUsernsMount starts a child in a nested user and mount namespace and
// has it mount a tmpfs. It imitates a process regaining "root" through
// CLONE_NEWUSER and then using that root for something privileged, without
// touching the outer sandbox's own mounts.
func runUsernsMount() error {
	cmd, err := usernsCommand(usernsChildArg)
	if err != nil {
		return fmt.Errorf("rfprobe: userns-mount: %w", err)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("start or run child in new user namespace: %w: %s", err, strings.TrimSpace(string(out)))
	}
	fmt.Print(string(out))
	return nil
}

// runUsernsChild runs inside the new namespaces, where it holds a full
// capability set by kernel definition.
func runUsernsChild() error {
	dir, err := os.MkdirTemp("", "rfprobe-userns-*")
	if err != nil {
		return fmt.Errorf("make mount point: %w", err)
	}
	defer os.RemoveAll(dir)

	if err := unix.Mount("none", dir, "tmpfs", 0, ""); err != nil {
		return fmt.Errorf("mount tmpfs in nested userns: %w", err)
	}
	unix.Unmount(dir, 0)

	fmt.Println("mounted tmpfs inside a new user and mount namespace")
	return nil
}
