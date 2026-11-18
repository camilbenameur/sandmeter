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
	{"K1", "a TCP listener created on 127.0.0.1 inside a loopback-only network namespace and passed out with SCM_RIGHTS accepts, in the host namespace, a connection made from inside", true},
	{"K1-unreach", "a direct connect from inside that namespace to a public address fails with ENETUNREACH", true},
	{"K1-host", "the host's links, addresses, routes, forwarding switches and nft ruleset are identical before, during and after", true},
	{"K1-links", "a fresh network namespace holds no interface but lo", false},
	{"K1-setns", "a listener created by a locked thread of the parent after setns into the namespace accepts a connection made from inside", false},

	{"K2", "after 0 is written to user/max_user_namespaces through a procfs the init mounted itself, unshare(CLONE_NEWUSER) fails with ENOSPC, with and without capabilities", true},
	{"K2-control", "with that write skipped, the same unshare(CLONE_NEWUSER) is not refused with ENOSPC", true},
	{"K2-raise", "a process without CAP_SYS_RESOURCE and CAP_SYS_ADMIN cannot raise the value back", true},
	{"K2-lsm", "with the write skipped, a process without any capability can still create a nested user namespace", false},
	{"K2b-unbounded", "host root can still create an inotify instance while a sandbox user namespace holds as many as the kernel lets it create", false},
	{"K2b-lowered", "host root can still create an inotify instance once the sandbox lowered user/max_inotify_instances in its own user namespace", false},

	{"K3-replace", "lower files replaced while the overlay was unmounted are seen at the next mount, and an upper copy wins until it is dropped", true},
	{"K3-delete-file", "lower files deleted while the overlay was unmounted are gone at the next mount, and an upper copy stays until it is dropped", true},
	{"K3-delete-dir", "a lower directory deleted while the overlay was unmounted leaves only its upper counterpart at the next mount", true},

	{"K4-mounts", "mounts made by a CLONE_NEWNS child after MS_REC|MS_SLAVE on / never appear in the host's /proc/self/mountinfo", true},
	{"K4-kill", "after SIGKILL of that child nothing is left mounted: its mount namespace has no member and its upper directory can be mounted again", true},
	{"K4-cgroup", "a cgroup subtree with cpu, memory and pids can be created under a parent group and a process cloned into its leaf with CLONE_INTO_CGROUP", true},
	{"K4-scope", "a systemd-run scope with Delegate=yes gives a subtree where cpu, memory and pids can be enabled", false},

	{"K5", "when the supervisor is killed, PID 1 reads end-of-file and exits, the kernel kills its pid namespace and the leaf cgroup.procs is empty within 2 s", true},

	{"K6-owner", "under runsc with an OCI user namespace that maps 0 to the shifted uid, a file written on a bind-mounted directory is owned by the shifted uid on the host", true},
	{"K6-bind", "an rbind OCI mount of an overlay path works under runsc: the lower content is read and a write lands in the upper directory, owned by the shifted uid", true},
	{"K6-uids", "the Sentry and the gofer run as the shifted uid on the host", false},
	{"K6-submount", "a mount placed under the root path before runsc starts is visible inside the sandbox", false},

	{"K7", "with a piped core handler, a crash under RLIMIT_CORE=1 does not start the handler while RLIMIT_CORE=0 and unlimited do", true},
	{"K7-klog", "the kernel log names the dump it aborted because of RLIMIT_CORE=1", false},

	{"K8", "unshare(CLONE_NEWCGROUP) from inside the target cgroup makes /proc/self/cgroup read 0::/", true},
	{"K8-cloneflag", "CLONE_NEWCGROUP given to the clone that uses CLONE_INTO_CGROUP also makes /proc/self/cgroup read 0::/", false},

	{"K9-whiteouts", "an overlay whose upper and work directories are on a size-capped tmpfs handles whiteouts and opaque directories, across a remount", true},
	{"K9-size", "that overlay returns ENOSPC when the tmpfs reaches size=", true},
	{"K9-inodes", "that overlay returns ENOSPC when the tmpfs reaches nr_inodes=", true},
	{"K9-memcg", "the pages written to the tmpfs upper layer are charged to the cgroup of the writer", false},

	{"K10", "this runner ran the kernel-facts tests", false},

	{"K11-idmap", "mount_setattr(MOUNT_ATTR_IDMAP) with the map line \"owner shifted 1\" shows the owner's files as the shifted uid", false},
	{"K11-overlay", "an overlay over the ID-mapped lower shows the owner's files as uid 0 in the sandbox namespace and copies them up owned by the shifted uid", false},
	{"K11-owners", "through that overlay a file of a mapped group can be modified, a foreign file can be read and not modified, and a foreign 0600 file cannot be read", false},

	{"T-syncfs", "unmounting an overlay stays under one second after 50 MiB and after 5,000 small files were written", false},
	{"T-pids-leaf", "with pids.max on the session group and on the leaf, a fork refused by the leaf limit is counted in the leaf's pids.events", true},
	{"T-pids-session", "a fork refused by the session limit is also counted in the leaf's pids.events", false},
	{"T-mnt", "inside a user namespace, a mount target opened with openat2(RESOLVE_IN_ROOT|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS) and mounted through /proc/self/fd/N lands on that directory", true},
	{"T-mnt-symlink", "a symbolic link planted at or above the target makes that open fail with ELOOP and nothing is mounted", true},
	{"T-loop", "a sparse 2 GiB ext4 image on a loop device configured with autoclear carries an overlay, and the device is released after the unmount", false},
	{"T-loop-kill", "the loop device is released within 2 s when the process whose mount namespace holds it is killed", false},

	{"T-host-kernel", "kernel release", false},
	{"T-host-arch", "architecture", false},
	{"T-host-distro", "distribution", false},
	{"T-host-cgroup", "/sys/fs/cgroup is a cgroup v2 mount", false},
	{"T-host-controllers", "the root cgroup offers cpu, memory and pids", false},
	{"T-host-lsm", "LSMs in force", false},
	{"T-host-apparmor-userns", "kernel.apparmor_restrict_unprivileged_userns is set", false},
	{"T-host-max-userns", "user.max_user_namespaces", false},
	{"T-host-inotify", "fs.inotify.max_user_instances", false},
	{"T-host-core-pattern", "kernel.core_pattern is a pipe handler", false},
	{"T-host-fs-var-lib", "filesystem type of /var/lib", false},
	{"T-host-fs-tmp", "filesystem type of /tmp", false},
	{"T-host-loop-control", "/dev/loop-control exists", false},
	{"T-host-mkfs-ext4", "mkfs.ext4 is installed", false},
	{"T-host-nft", "nft is installed", false},
	{"T-host-runsc", "runsc is installed", false},
	{"T-host-systemd", "systemd runs this host", false},

	{"Z-mounts", "the tests left the mount table of the host as they found it", true},
	{"Z-cgroups", "the tests left no cgroup behind", true},
	{"Z-loops", "the tests left no loop device attached", true},
	{"Z-processes", "the tests left no helper process running", true},
	{"Z-sysctls", "the tests left the sysctls they touch as they found them", true},
}
