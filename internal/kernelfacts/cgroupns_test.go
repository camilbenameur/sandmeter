//go:build integration && linux

package kernelfacts

import (
	"errors"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// The cgroup namespace of the init.
//
// A cgroup namespace is rooted at the cgroup of the process that creates
// it. The supervisor clones the init straight into the leaf with
// CLONE_INTO_CGROUP; a CLONE_NEWCGROUP in that same clone would be rooted
// at the supervisor's group, and the sandbox would read a path that walks
// up the host's hierarchy. So the init unshares the namespace itself, once
// it is inside the leaf, on every thread.

// cgroupnsReport is what the helper read of its own cgroup.
type cgroupnsReport struct {
	Before  string `json:"before"`  // /proc/self/cgroup as it started
	Unshare string `json:"unshare"` // result of unshare(CLONE_NEWCGROUP), or "not tried"
	Variant string `json:"variant"` // "all-threads", "locked-thread" or "none"
	After   string `json:"after"`   // /proc/self/cgroup at the end
}

// childCgroupns reports its cgroup, before and after it left the cgroup
// namespace it was born in. args[0] is "unshare" or "none".
func childCgroupns(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: cgroupns unshare|none")
	}
	rep := cgroupnsReport{Before: strings.TrimSpace(contentOf("/proc/self/cgroup")), Unshare: "not tried", Variant: "none"}
	if args[0] == "unshare" {
		// A namespace is a property of a thread. The init changes it on
		// all of them (syscall.AllThreadsSyscall), which a binary built
		// with cgo cannot do: such a build falls back to one locked thread
		// and reads the file from that thread.
		rep.Variant = "all-threads"
		_, _, e := syscall.AllThreadsSyscall(unix.SYS_UNSHARE, unix.CLONE_NEWCGROUP, 0, 0)
		switch e {
		case 0:
			rep.Unshare = "ok"
		case syscall.ENOTSUP:
			rep.Variant = "locked-thread"
			runtime.LockOSThread()
			rep.Unshare = errnoName(unix.Unshare(unix.CLONE_NEWCGROUP))
			rep.After = strings.TrimSpace(contentOf("/proc/thread-self/cgroup"))
			return sayResult(rep)
		default:
			rep.Unshare = errnoName(e)
		}
	}
	rep.After = strings.TrimSpace(contentOf("/proc/self/cgroup"))
	return sayResult(rep)
}

func TestCgroupNamespace(t *testing.T) {
	r := declare(t, "cgroupns-unshare", "cgroupns-clone-flag")
	r.needRoot()
	r.needCgroup2()

	tr, err := newCgTree(t, "cgroupns")
	if err != nil {
		r.no("cgroupns-unshare", "the cgroup layout could not be created: %v", err)
		return
	}
	// What a process of the leaf reads while it is still in the cgroup
	// namespace of the test.
	full := "0::" + strings.TrimPrefix(tr.leaf, cgroupRoot)

	var rep cgroupnsReport
	if err := runChild(t, spawn{name: "cgroupns", args: []string{"unshare"}, userns: true, cgroup: tr.leaf}, &rep); err != nil {
		r.no("cgroupns-unshare", "a helper cloned into the leaf, in a new user namespace, did not complete: %v", err)
	} else {
		r.judge("cgroupns-unshare", rep.Unshare == "ok" && rep.Before == full && rep.After == "0::/",
			"cloned into the leaf it reads %q (expected %q); unshare(CLONE_NEWCGROUP) on %s: %s; it then reads %q (expected \"0::/\")",
			rep.Before, full, rep.Variant, rep.Unshare, rep.After)
	}

	var flag cgroupnsReport
	if err := runChild(t, spawn{name: "cgroupns", args: []string{"none"}, userns: true, clone: unix.CLONE_NEWCGROUP, cgroup: tr.leaf}, &flag); err != nil {
		r.skip("cgroupns-clone-flag", "a helper cloned with CLONE_NEWCGROUP and CLONE_INTO_CGROUP did not complete: %v", err)
		return
	}
	r.judge("cgroupns-clone-flag", flag.Before == "0::/",
		"with CLONE_NEWCGROUP in the clone that enters the leaf, the process reads %q", flag.Before)
}
