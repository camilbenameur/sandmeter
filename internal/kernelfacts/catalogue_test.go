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
	{"K10", "this runner ran the kernel-facts tests", false},

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
