// Package kernelfacts records what the kernel of a host does for each
// assumption the v0.1.0 design rests on.
//
// The design was written on a machine where nothing may run as root, so the
// root-only mechanisms it chose had never been executed. This package is the
// measuring instrument that settles them. Each test runs one mechanism in
// the smallest setting that shows it and records facts: an identifier, a
// statement, an outcome and a detail that says what was expected and what
// was found. The package imports no other package of this module: it must
// keep working while the rest is being moved.
//
// # Running
//
// The tests carry the build tag "integration" and need root:
//
//	go test -exec "sudo -E" -tags integration -count=1 -v ./internal/kernelfacts/
//
// They create namespaces, mounts, cgroups and a loop device, and two of them
// change a host-wide setting for a moment. Every test puts back what it
// changed, and the last one compares the host with a snapshot taken before
// the first; all the same, run them on a throwaway machine. Without root the
// tests that create something are skipped, and the ones that only read (the
// facts about the host, the final comparison, the self-tests) still run.
//
// Environment:
//
//	SANDMETER_FACTS_OUT       file that receives one JSON line per fact
//	SANDMETER_REQUIRE         comma-separated prerequisites (root, cgroup2, runsc,
//	                          throwaway) whose absence fails a test instead of
//	                          skipping it
//	SANDMETER_THROWAWAY_HOST  set to 1, with CI=true, to allow the tests that
//	                          change a host-wide setting for a moment
//	SANDMETER_FACTS_DIR       where the scratch directory goes (default /var/lib,
//	                          the filesystem that will hold the service's state)
//
// # The record
//
// A fact is printed as a line that starts with "FACT " and carries a JSON
// object, and the same object is appended to SANDMETER_FACTS_OUT:
//
//	{"id":"init-kill-switch","name":"...","required":true,"outcome":"yes","detail":"...","kernel":"6.8.0-1070-azure"}
//
// The name is a statement and the outcome says whether it holds on this
// host: "yes", "no", or "skipped" with the reason in the detail. A required
// fact gates a decision of the design: its "no" fails the test, and the job
// (.github/workflows/kernel-facts.yml) with it. A recorded fact is a
// measurement and never fails; several are expected to be "no". A required
// fact that was skipped decided nothing, and fails the job too. Every fact
// of the catalogue (catalogue_test.go) is recorded on every run, so the
// absence of a line is itself an error.
//
// # The facts
//
// Each group names a decision of the design, lists its facts, and says what
// a "no" to a required one switches.
//
// The egress listener. In proxy mode the sandbox's network namespace has
// loopback only; the init creates the proxy's listener inside it and passes
// it to the supervisor with SCM_RIGHTS. Nothing is created in the host's
// network namespace.
//
//	egress-listener        required  the passed listener accepts, in the host
//	                                 namespace, a connection made from inside
//	egress-no-route        required  a direct connect from inside gets ENETUNREACH
//	egress-host-untouched  required  links, addresses, routes, forwarding and nft
//	                                 ruleset of the host do not move
//	egress-loopback-only   recorded  a fresh network namespace holds lo and
//	                                 nothing else
//	egress-listener-setns  recorded  a supervisor thread can create the listener
//	                                 itself after setns
//
// A "no" to egress-listener moves the creation of the listener to a
// supervisor thread (egress-listener-setns); if that is "no" as well, proxy
// mode does not ship. A "no" to egress-no-route or egress-host-untouched
// withdraws the claim it states.
//
// Nested user namespaces without the syscall filter. The init writes 0 to
// user/max_user_namespaces through a procfs it mounted itself, and lowers
// the inotify maxima of the sandbox's user namespace at the same time.
//
//	userns-nested-refused       required  unshare(CLONE_NEWUSER) then fails with
//	                                      ENOSPC
//	userns-nested-control       required  without the write it does not: the
//	                                      write is the cause
//	userns-limit-sealed         required  the workload cannot write the value back
//	userns-nested-unprivileged  recorded  what the host's LSM does to a nested
//	                                      user namespace when the init wrote
//	                                      nothing: a second barrier or none
//	inotify-charge-default      recorded  host root can still create an inotify
//	                                      instance while a sandbox takes all it
//	                                      can; "no" is the flaw, as read in the
//	                                      kernel source
//	inotify-charge-lowered      recorded  it can once the init lowered the
//	                                      sandbox's maximum
//
// A "no" to one of the three required facts leaves the syscall filter as the
// only barrier, and the profile "off" is documented as removing it. A "no"
// to inotify-charge-lowered publishes the limit as not enforced, in the
// threat model too.
//
// The overlay of a sandbox. One overlay holds everything: the layers of the
// image, above them a layer with the copy of the project, and the upper
// directory of the session. It is mounted for one command at a time, with
// index, metacopy and redirect_dir off and xino left to the kernel. Between
// two commands the project layer is refreshed from the host while nothing
// is mounted, and the upper entries of the changed paths are dropped. The
// opt-in disk quota puts the upper directory on a tmpfs: the layers are
// then on two filesystems, the kernel turns xino on, and its documentation
// no longer covers a lower tree that changes between two mounts. So the
// refresh is measured on both placements.
//
//	refresh-disk-replace       required  upper directory on the state
//	                                     filesystem: a lower file replaced
//	                                     between two mounts
//	refresh-disk-delete-file   required  a lower file deleted
//	refresh-disk-delete-dir    required  a lower directory deleted that has an
//	                                     upper counterpart
//	refresh-tmpfs-replace      required  upper directory on a tmpfs: a lower
//	                                     file replaced between two mounts
//	refresh-tmpfs-delete-file  required  a lower file deleted
//	refresh-tmpfs-delete-dir   required  a lower directory deleted that has an
//	                                     upper counterpart
//	tmpfs-upper-whiteouts      required  overlayfs works with its upper layer on
//	                                     a tmpfs
//	tmpfs-upper-size           required  size= answers ENOSPC through the overlay
//	tmpfs-upper-inodes         required  nr_inodes= answers ENOSPC through the
//	                                     overlay
//	tmpfs-upper-memory         recorded  the quota is charged to the memory of
//	                                     the writer's cgroup, as the
//	                                     documentation is about to say
//	overlay-dir-rename         recorded  the price of redirect_dir=nofollow: a
//	                                     directory of the project cannot be
//	                                     renamed, only copied
//	overlay-device-numbers     recorded  whether find -xdev and its like see
//	                                     every file when the layers are on two
//	                                     filesystems
//	overlay-unmount-time       recorded  what an unmount per command costs: a
//	                                     benchmark row
//
// A "no" to a refresh fact replaces the refresh in place by a new lower
// directory per refresh, built as a hard-link farm of the previous one. A
// "no" to a required tmpfs-upper fact cuts the tmpfs quota: a disk limit is
// refused and the free-space floor is the only guard.
//
// The worker and its commands. A worker serves one connection in its own
// mount namespace and cgroup subtree. A command runs in a leaf group of its
// session, under an init that is PID 1 of a new pid namespace and exits
// when its supervisor is gone.
//
//	worker-mounts-private    required  what a worker mounts never shows in the
//	                                   host's mount table
//	worker-kill-unmounts     required  after SIGKILL nothing of it is left mounted
//	worker-sees-host-mounts  recorded  what the host mounts later still reaches
//	                                   the worker: why its namespace is a slave
//	                                   and not a private copy
//	worker-start-time        recorded  what a worker per connection costs before
//	                                   it can serve
//	cgroup-session-leaf      required  the session and leaf groups can be built
//	                                   and a command cloned into the leaf
//	cgroup-systemd-delegate  recorded  what a systemd unit with Delegate=yes
//	                                   gives, for the unit file of the service
//	init-kill-switch         required  the supervisor dies, PID 1 reads
//	                                   end-of-file and exits, the kernel kills
//	                                   the pid namespace
//	init-fork-bomb           required  a Go PID 1 that shares the leaf with a
//	                                   fork bomb is not ended by its own
//	                                   runtime when the leaf is at pids.max
//	init-signals             required  nor by a signal of the workload
//	cgroupns-unshare         required  unshare(CLONE_NEWCGROUP) from inside the
//	                                   leaf hides the host's cgroup path
//	cgroupns-clone-flag      recorded  what CLONE_NEWCGROUP in the clone itself
//	                                   shows
//	pids-events-leaf         required  a fork refused by the leaf's own pids.max
//	                                   is counted on the leaf
//	pids-events-session      recorded  where a fork refused by the session's
//	                                   limit is counted; the two hosted kernels
//	                                   are expected to differ
//
// A "no" to worker-mounts-private or worker-kill-unmounts means mounts have
// to be swept after a crash, and that between two commands a session is more
// than a directory. A "no" to cgroup-session-leaf or pids-events-leaf means
// the cgroup layout has to change: the receipt and the fork-bomb case read
// the leaf. A "no" to init-kill-switch leaves cgroup.kill from the sweep as
// the only backstop. A "no" to init-fork-bomb takes the init out of the
// leaf of its workload, into a group of its own, before the cgroup layer is
// built on the shared leaf; a "no" to init-signals means that asking for
// every signal does not protect the init, and the sandbox with it. A "no"
// to cgroupns-unshare keeps the clone flag, and the leak of the host's
// cgroup path is documented.
//
// Hardening of the init. It sets RLIMIT_CORE to 1, and it opens every mount
// target beneath the root without following links, then mounts on the
// descriptor.
//
//	core-limit-one       required  RLIMIT_CORE=1 keeps a piped core handler from
//	                               starting
//	core-kernel-log      recorded  the kernel log lines of an aborted dump: a
//	                               crash loop in a sandbox is a log flood on the
//	                               host
//	mount-by-descriptor  required  a mount through /proc/self/fd/N lands on the
//	                               directory that was opened
//	mount-link-refused   required  a planted link fails closed
//
// A "no" to core-limit-one turns the control into a warning of doctor, and
// the escape case is published as it comes out. A "no" to
// mount-by-descriptor or mount-link-refused keeps path-based targets in the
// init, and a writable root cannot be granted.
//
// gVisor. The backend gives runsc an OCI user namespace that maps 0 to the
// shifted uid, and the workspace overlay as an OCI bind mount.
//
//	gvisor-file-owner     required  what the workload writes belongs to the
//	                                shifted uid on the host
//	gvisor-overlay-bind   required  the workspace overlay works as an rbind OCI
//	                                mount
//	gvisor-process-uids   recorded  the host uids of the Sentry and the gofer,
//	                                for the sentence of the threat model about
//	                                their privilege
//	gvisor-root-submount  recorded  runsc shows a mount under the root path; the
//	                                design does not rely on it
//
// A "no" to gvisor-file-owner or gvisor-overlay-bind makes gVisor a preview
// backend with network none and no project, outside the claims.
//
// Left for a later release, and measured now so that the next design starts
// from facts: the project as a live, ID-mapped lower layer, and a disk quota
// made of an ext4 image on a loop device.
//
//	idmap-mount        recorded  mount_setattr(MOUNT_ATTR_IDMAP) with the map
//	                             line "owner shifted 1", per filesystem
//	idmap-overlay      recorded  an overlay over the ID-mapped lower: uid 0
//	                             inside, copy-up owned by the shifted uid
//	idmap-owners       recorded  what the sandbox can do with files of other
//	                             owners and groups
//	loop-image         recorded  what the loop image costs, and whether the
//	                             kernel takes the device back after the unmount
//	loop-kill-release  recorded  and after the death of the process that held it
//
// The runner. Every fact is a fact about one kernel on one image; these say
// which, so that "tested" is claimed for exactly what ran.
//
//	host-runner           recorded  the runner exists and ran the tests
//	host-kernel           recorded  kernel release
//	host-arch             recorded  architecture
//	host-distro           recorded  distribution
//	host-cgroup2          recorded  cgroup v2 at /sys/fs/cgroup
//	host-controllers      recorded  cpu, memory and pids in the root group
//	host-lsm              recorded  LSMs in force
//	host-apparmor-userns  recorded  kernel.apparmor_restrict_unprivileged_userns
//	host-max-userns       recorded  user.max_user_namespaces
//	host-inotify          recorded  fs.inotify.max_user_instances
//	host-core-pattern     recorded  kernel.core_pattern is a pipe handler
//	host-fs-var-lib       recorded  filesystem of /var/lib
//	host-fs-tmp           recorded  filesystem of /tmp
//	host-loop-control     recorded  /dev/loop-control
//	host-mkfs-ext4        recorded  mkfs.ext4
//	host-nft              recorded  nft
//	host-runsc            recorded  runsc and its version
//	host-systemd          recorded  systemd and its version
//
// The tests themselves. A root test that leaves something behind is a
// defect of the test, and of whatever it shows to be leaking.
//
//	clean-mounts     required  the mount table of the host is as it was found
//	clean-cgroups    required  no cgroup is left
//	clean-loops      required  no loop device is left attached
//	clean-processes  required  no helper process is left, and no thread of the
//	                           test process in a namespace of a test: so no
//	                           namespace outlives the run
//	clean-sysctls    required  the sysctls the tests touch are as they were found
//
// # How a test is built
//
// A Go program cannot enter most namespaces once its threads exist, so a
// test starts a helper: the test binary itself, re-executed through
// /proc/self/exe with a hidden first argument and the clone flags the
// mechanism needs (child_test.go, children_test.go). A helper prints what
// it measured as one JSON line and the test turns that into facts. Helpers
// report errno names, not booleans, so a detail reads "expected ENOSPC,
// found EPERM".
//
// Three rules keep the host safe. A helper that mounts or configures a
// network first checks that it is not in the namespace of the test process,
// so a forgotten clone flag cannot touch the host; a self-test starts each
// of them without its flags, and without privilege, to see it refuse. A
// helper that waits does so on its standard input, whose other end only the
// test holds: when the test dies, the helper ends, and its namespaces with
// it. And the test process itself stays where it started: the one thread it
// sends into the namespace of a helper is kept apart until it is back, and
// is never the main thread (threads_test.go).
//
// Where half of a mechanism needs no privilege (the socket passing of the
// egress listener, the path resolution of a mount target, the crash under
// RLIMIT_CORE=1, the clone into a cgroup), a self-test next to the root test
// runs that half on any host, so that a "no" on a runner is a fact about the
// kernel and not a defect of the instrument.
//
// To add a fact: add it to the catalogue, give it a line here in the group
// of the decision it gates, declare it in the test that records it. The
// self-tests and the last test fail until the three agree.
package kernelfacts
