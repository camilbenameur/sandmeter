//go:build integration && linux

package kernelfacts

// catalogue is every fact this package records. The name of a fact is a
// statement: the outcome "yes" means it holds on this host. The last field
// says whether the fact is required, that is, whether its "no" fails the
// run because a decision of the design rests on it.
//
// doc.go lists the same identifiers with the decision each one gates, and
// TestSelfDocListsEveryFact keeps the two in step.
var catalogue = []def{
	{"egress-listener", "a TCP listener created on 127.0.0.1 inside a loopback-only network namespace and passed out with SCM_RIGHTS accepts, in the host namespace, a connection made from inside", true},
	{"egress-no-route", "a direct connect from inside that namespace to a public address fails with ENETUNREACH", true},
	{"egress-host-untouched", "the host's links, addresses, routes, forwarding switches and nft ruleset are identical before, during and after", true},
	{"egress-loopback-only", "a fresh network namespace holds no interface but lo", false},
	{"egress-listener-setns", "a listener created by a locked thread of the parent after setns into the namespace accepts a connection made from inside", false},

	{"userns-nested-refused", "after 0 is written to user/max_user_namespaces through a procfs the init mounted itself, unshare(CLONE_NEWUSER) fails with ENOSPC, with and without capabilities", true},
	{"userns-nested-control", "with that write skipped, the same unshare(CLONE_NEWUSER) is not refused with ENOSPC", true},
	{"userns-limit-sealed", "a process without CAP_SYS_RESOURCE and CAP_SYS_ADMIN cannot raise the value back", true},
	{"userns-nested-unprivileged", "with the write skipped, a process without any capability can still create a nested user namespace", false},
	{"inotify-charge-default", "host root can still create an inotify instance while a sandbox user namespace holds as many as the kernel lets it create", false},
	{"inotify-charge-lowered", "host root can still create an inotify instance once the sandbox lowered user/max_inotify_instances in its own user namespace", false},

	{"refresh-disk-replace", "with the upper directory on the state filesystem, lower files replaced while the overlay was unmounted are seen at the next mount, and an upper copy wins until it is dropped", true},
	{"refresh-disk-delete-file", "with the upper directory on the state filesystem, lower files deleted while the overlay was unmounted are gone at the next mount, and an upper copy stays until it is dropped", true},
	{"refresh-disk-delete-dir", "with the upper directory on the state filesystem, a lower directory deleted while the overlay was unmounted leaves only its upper counterpart at the next mount", true},
	{"refresh-tmpfs-replace", "with the upper directory on a tmpfs, lower files replaced while the overlay was unmounted are seen at the next mount, and an upper copy wins until it is dropped", true},
	{"refresh-tmpfs-delete-file", "with the upper directory on a tmpfs, lower files deleted while the overlay was unmounted are gone at the next mount, and an upper copy stays until it is dropped", true},
	{"refresh-tmpfs-delete-dir", "with the upper directory on a tmpfs, a lower directory deleted while the overlay was unmounted leaves only its upper counterpart at the next mount", true},

	{"worker-mounts-private", "mounts made by a CLONE_NEWNS child after MS_REC|MS_SLAVE on / never appear in the host's /proc/self/mountinfo", true},
	{"worker-kill-unmounts", "after SIGKILL of that child nothing is left mounted: its mount namespace has no member and its upper directory can be mounted again", true},
	{"worker-sees-host-mounts", "a mount made on the host after a worker started, whose mount namespace is a slave of the host's, is visible to the worker, and gone for it when the host unmounts it", false},
	{"worker-start-time", "a worker in a cgroup and a mount namespace of its own is ready within 100 ms of its clone, at the 95th percentile of 40 starts", false},
	{"cgroup-session-leaf", "a cgroup subtree with cpu, memory and pids can be created under a parent group and a process cloned into its leaf with CLONE_INTO_CGROUP", true},
	{"cgroup-systemd-delegate", "a systemd-run scope with Delegate=yes gives a subtree where cpu, memory and pids can be enabled", false},

	{"init-kill-switch", "when the supervisor is killed, PID 1 reads end-of-file and exits, the kernel kills its pid namespace and the leaf cgroup.procs is empty within 2 s", true},
	{"init-fork-bomb", "a Go PID 1 with GOMAXPROCS=1 that shares its leaf with the workload stays within the 16 pids reserved for it and outlives a fork bomb that holds the leaf at pids.max: it then stops what is left, reaps it, and exits only when its supervisor lets go", true},
	{"init-signals", "a Go PID 1 that asked for every signal survives each of the 64 signals its workload sends it with kill(2), SIGKILL and SIGSTOP included", true},

	{"gvisor-file-owner", "under runsc with an OCI user namespace that maps 0 to the shifted uid, a file written on a bind-mounted directory is owned by the shifted uid on the host", true},
	{"gvisor-overlay-bind", "an rbind OCI mount of an overlay path works under runsc: the lower content is read and a write lands in the upper directory, owned by the shifted uid", true},
	{"gvisor-process-uids", "the Sentry and the gofer run as the shifted uid on the host", false},
	{"gvisor-root-submount", "a mount placed under the root path before runsc starts is visible inside the sandbox", false},

	{"core-limit-one", "with a piped core handler, a crash under RLIMIT_CORE=1 does not start the handler while RLIMIT_CORE=0 and unlimited do", true},
	{"core-kernel-log", "the kernel log names the dump it aborted because of RLIMIT_CORE=1", false},

	{"cgroupns-unshare", "unshare(CLONE_NEWCGROUP) from inside the target cgroup makes /proc/self/cgroup read 0::/", true},
	{"cgroupns-clone-flag", "CLONE_NEWCGROUP given to the clone that uses CLONE_INTO_CGROUP also makes /proc/self/cgroup read 0::/", false},

	{"tmpfs-upper-whiteouts", "an overlay whose upper and work directories are on a size-capped tmpfs handles whiteouts and opaque directories, across a remount", true},
	{"tmpfs-upper-size", "that overlay returns ENOSPC when the tmpfs reaches size=", true},
	{"tmpfs-upper-inodes", "that overlay returns ENOSPC when the tmpfs reaches nr_inodes=", true},
	{"tmpfs-upper-memory", "the pages written to the tmpfs upper layer are charged to the cgroup of the writer", false},

	{"host-runner", "this runner ran the kernel-facts tests", false},

	{"idmap-mount", "mount_setattr(MOUNT_ATTR_IDMAP) with the map line \"owner shifted 1\" shows the owner's files as the shifted uid", false},
	{"idmap-overlay", "an overlay over the ID-mapped lower shows the owner's files as uid 0 in the sandbox namespace and copies them up owned by the shifted uid", false},
	{"idmap-owners", "through that overlay a file of a mapped group can be modified, a foreign file can be read and not modified, and a foreign 0600 file cannot be read", false},

	{"overlay-dir-rename", "with redirect_dir=nofollow, rename(2) of a directory that comes from a lower layer answers EXDEV, while files and the directories a command created rename", false},
	{"overlay-device-numbers", "every file of the overlay reports the device of the overlay, with the upper directory on the filesystem of the lower layers and on another one", false},
	{"overlay-unmount-time", "unmounting an overlay stays under one second after 50 MiB and after 5,000 small files were written", false},
	{"pids-events-leaf", "with pids.max on the session group and on the leaf, a fork refused by the leaf limit is counted in the leaf's pids.events", true},
	{"pids-events-session", "a fork refused by the session limit is also counted in the leaf's pids.events", false},
	{"mount-by-descriptor", "inside a user namespace, a mount target opened with openat2(RESOLVE_IN_ROOT|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS) and mounted through /proc/self/fd/N lands on that directory", true},
	{"mount-link-refused", "a symbolic link planted at or above the target makes that open fail with ELOOP and nothing is mounted", true},
	{"loop-image", "a sparse 2 GiB ext4 image on a loop device configured with autoclear carries an overlay, and the device is released after the unmount", false},
	{"loop-kill-release", "the loop device is released within 2 s when the process whose mount namespace holds it is killed", false},

	{"host-kernel", "kernel release", false},
	{"host-arch", "architecture", false},
	{"host-distro", "distribution", false},
	{"host-cgroup2", "/sys/fs/cgroup is a cgroup v2 mount", false},
	{"host-controllers", "the root cgroup offers cpu, memory and pids", false},
	{"host-lsm", "LSMs in force", false},
	{"host-apparmor-userns", "kernel.apparmor_restrict_unprivileged_userns is set", false},
	{"host-max-userns", "user.max_user_namespaces", false},
	{"host-inotify", "fs.inotify.max_user_instances", false},
	{"host-core-pattern", "kernel.core_pattern is a pipe handler", false},
	{"host-fs-var-lib", "filesystem type of /var/lib", false},
	{"host-fs-tmp", "filesystem type of /tmp", false},
	{"host-loop-control", "/dev/loop-control exists", false},
	{"host-mkfs-ext4", "mkfs.ext4 is installed", false},
	{"host-nft", "nft is installed", false},
	{"host-runsc", "runsc is installed", false},
	{"host-systemd", "systemd runs this host", false},

	{"clean-mounts", "the tests left the mount table of the host as they found it", true},
	{"clean-cgroups", "the tests left no cgroup behind", true},
	{"clean-loops", "the tests left no loop device attached", true},
	{"clean-processes", "the tests left no helper process running, and no thread of their own in a namespace of a test", true},
	{"clean-sysctls", "the tests left the sysctls they touch as they found them", true},
}
