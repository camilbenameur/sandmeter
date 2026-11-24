//go:build integration && linux

package kernelfacts

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// T-host: what this runner is.
//
// Every other fact is a fact about one kernel on one image. These lines say
// which, so that a result can be read months later, and so that the
// documentation claims "tested" for exactly what ran. They need no
// privilege and decide nothing.

// osRelease reads one key of /etc/os-release.
func osRelease(key string) (string, error) {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			return strings.Trim(v, `"'`), nil
		}
	}
	return "", fmt.Errorf("no %s in /etc/os-release", key)
}

func TestHostFacts(t *testing.T) {
	r := declare(t,
		"K10", "T-host-kernel", "T-host-arch", "T-host-distro",
		"T-host-cgroup", "T-host-controllers",
		"T-host-lsm", "T-host-apparmor-userns", "T-host-max-userns", "T-host-inotify", "T-host-core-pattern",
		"T-host-fs-var-lib", "T-host-fs-tmp",
		"T-host-loop-control", "T-host-mkfs-ext4", "T-host-nft", "T-host-runsc", "T-host-systemd",
	)

	var u unix.Utsname
	machine := "unknown"
	if err := unix.Uname(&u); err == nil {
		machine = unix.ByteSliceToString(u.Machine[:])
	}
	// The hosted images name themselves in the environment.
	image := strings.TrimSpace(os.Getenv("ImageOS") + " " + os.Getenv("ImageVersion"))
	if image == "" {
		image = "not a hosted runner image, or its variables were not passed on"
	}
	r.yes("K10", "%s/%s, kernel %s, as uid %d; runner image: %s", runtime.GOOS, runtime.GOARCH, kernelRelease(), os.Geteuid(), image)
	r.yes("T-host-kernel", "%s", kernelRelease())
	r.yes("T-host-arch", "%s (GOARCH %s)", machine, runtime.GOARCH)

	distro, err := osRelease("PRETTY_NAME")
	r.judge("T-host-distro", err == nil, "%s", valueOr(distro, err))

	cgroupFS := "nothing is mounted there"
	if e, ok := mountAt(parseMountinfo(mountinfoText()), cgroupRoot); ok {
		cgroupFS = e.fstype
	}
	r.judge("T-host-cgroup", haveCgroup2(), "%s is %s", cgroupRoot, cgroupFS)
	r.judge("T-host-controllers", haveCgroup2() && len(missingControllers(cgroupRoot)) == 0,
		"cgroup.controllers of the root: %v; its cgroup.subtree_control: %v",
		cgFields(cgroupRoot, "cgroup.controllers"), cgFields(cgroupRoot, "cgroup.subtree_control"))

	lsm, err := readTrim("/sys/kernel/security/lsm")
	r.judge("T-host-lsm", err == nil, "%s", valueOr(lsm, err))
	restrict, err := readTrim("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
	r.judge("T-host-apparmor-userns", err == nil && restrict == "1", "kernel.apparmor_restrict_unprivileged_userns: %s", valueOr(restrict, err))
	maxUserns, err := readTrim("/proc/sys/user/max_user_namespaces")
	r.judge("T-host-max-userns", err == nil, "%s", valueOr(maxUserns, err))
	inotify, err := readTrim("/proc/sys/fs/inotify/max_user_instances")
	r.judge("T-host-inotify", err == nil, "%s", valueOr(inotify, err))
	pattern, err := readTrim(corePattern)
	r.judge("T-host-core-pattern", err == nil && strings.HasPrefix(pattern, "|"), "kernel.core_pattern: %q", valueOr(pattern, err))

	r.yes("T-host-fs-var-lib", "%s", fsTypeOf("/var/lib"))
	r.yes("T-host-fs-tmp", "%s", fsTypeOf("/tmp"))

	r.judge("T-host-loop-control", exists("/dev/loop-control"), "/dev/loop-control; loop devices now: %d, of which %d attached", len(loopNames()), len(boundLoops()))

	// Tools are looked up in the PATH of the process, which under sudo is
	// the PATH a root service would get.
	tool := func(id, name string, versionArgs ...string) {
		path, err := exec.LookPath(name)
		if err != nil {
			r.no(id, "%s is not in PATH (%s)", name, os.Getenv("PATH"))
			return
		}
		r.yes(id, "%s: %s", path, firstLine(path, versionArgs...))
	}
	tool("T-host-mkfs-ext4", "mkfs.ext4", "-V")
	tool("T-host-nft", "nft", "--version")
	tool("T-host-runsc", "runsc", "--version")

	systemd := "systemctl is not in PATH"
	if path, err := exec.LookPath("systemctl"); err == nil {
		systemd = firstLine(path, "--version")
	}
	r.judge("T-host-systemd", exists("/run/systemd/system"), "%s; /run/systemd/system exists: %v; PID 1 is %s",
		systemd, exists("/run/systemd/system"), readOr(filepath.Join("/proc", "1", "comm")))
}
