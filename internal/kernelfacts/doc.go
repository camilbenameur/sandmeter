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
//	SANDMETER_REQUIRE         comma-separated prerequisites (root, cgroup2, runsc)
//	                          whose absence fails a test instead of skipping it
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
//	{"id":"K5","name":"...","required":true,"outcome":"yes","detail":"...","kernel":"6.8.0-1070-azure"}
//
// The name is a statement and the outcome says whether it holds on this
// host: "yes", "no", or "skipped" with the reason in the detail. A required
// fact gates a decision of the design: its "no" fails the test, and the job
// (.github/workflows/kernel-facts.yml) with it. A recorded fact is a
// measurement and never fails; several are expected to be "no". Every fact
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
//	K1          required  the passed listener accepts, in the host namespace, a
//	                      connection made from inside
//	K1-unreach  required  a direct connect from inside gets ENETUNREACH
//	K1-host     required  links, addresses, routes, forwarding and nft ruleset
//	                      of the host do not move
//	K1-links    recorded  a fresh network namespace holds lo and nothing else
//	K1-setns    recorded  a supervisor thread can create the listener itself
//	                      after setns
//
// A "no" to K1 moves the creation of the listener to a supervisor thread
// (K1-setns); if that is "no" as well, proxy mode does not ship. A "no" to
// K1-unreach or K1-host withdraws the claim it states.
//
// Nested user namespaces without the syscall filter. The init writes 0 to
// user/max_user_namespaces through a procfs it mounted itself, and lowers
// the inotify maxima of the sandbox's user namespace at the same time.
//
//	K2             required  unshare(CLONE_NEWUSER) then fails with ENOSPC
//	K2-control     required  without the write it does not: the write is the cause
//	K2-raise       required  the workload cannot write the value back
//	K2-lsm         recorded  what the image's LSM does to a nested user namespace
//	                         when the init wrote nothing: a second barrier or none
//	K2b-unbounded  recorded  host root can still create an inotify instance while
//	                         a sandbox takes all it can; "no" is the flaw, as read
//	                         in the kernel source
//	K2b-lowered    recorded  it can once the init lowered the sandbox's maximum
//
// A "no" to K2, K2-control or K2-raise leaves the syscall filter as the only
// barrier, and the profile "off" is documented as removing it. A "no" to
// K2b-lowered publishes the limit as not enforced, in the threat model too.
//
// The workspace overlay. It is mounted for one command at a time; between
// two commands the lower tree is refreshed from the host while nothing is
// mounted, and the upper entries of the changed paths are dropped. The
// opt-in disk quota puts the upper layer on a tmpfs.
//
//	K3-replace      required  a lower file replaced between two mounts
//	K3-delete-file  required  a lower file deleted between two mounts
//	K3-delete-dir   required  a lower directory deleted that has an upper
//	                          counterpart
//	K9-whiteouts    required  overlayfs works with its upper layer on a tmpfs
//	K9-size         required  size= answers ENOSPC through the overlay
//	K9-inodes       required  nr_inodes= answers ENOSPC through the overlay
//	K9-memcg        recorded  the quota is charged to the memory of the writer's
//	                          cgroup, as the documentation is about to say
//	T-syncfs        recorded  what an unmount per command costs: a benchmark row
//
// A "no" to a K3 fact replaces the refresh in place by a new lower directory
// per refresh, built as a hard-link farm of the previous one. A "no" to a
// required K9 fact cuts the tmpfs quota: a disk limit is refused and the
// free-space floor is the only guard.
//
// The worker and its commands. A worker serves one connection in its own
// mount namespace and cgroup subtree. A command runs in a leaf group of its
// session, under an init that is PID 1 of a new pid namespace and exits
// when its supervisor is gone.
//
//	K4-mounts       required  what a worker mounts never shows in the host's
//	                          mount table
//	K4-kill         required  after SIGKILL nothing of it is left mounted
//	K4-cgroup       required  the session and leaf groups can be built and a
//	                          command cloned into the leaf
//	K4-scope        recorded  what a systemd unit with Delegate=yes gives, for
//	                          the unit file of the service
//	K5              required  the supervisor dies, PID 1 reads end-of-file and
//	                          exits, the kernel kills the pid namespace
//	K8              required  unshare(CLONE_NEWCGROUP) from inside the leaf
//	                          hides the host's cgroup path
//	K8-cloneflag    recorded  what CLONE_NEWCGROUP in the clone itself shows
//	T-pids-leaf     required  a fork refused by the leaf's own pids.max is
//	                          counted on the leaf
//	T-pids-session  recorded  where a fork refused by the session's limit is
//	                          counted; the two hosted kernels are expected to
//	                          differ
//
// A "no" to K4-mounts or K4-kill means mounts have to be swept after a
// crash, and that between two commands a session is more than a directory.
// A "no" to K4-cgroup or T-pids-leaf means the cgroup layout has to change:
// the receipt and the fork-bomb case read the leaf. A "no" to K5 leaves
// cgroup.kill from the sweep as the only backstop. A "no" to K8 keeps the
// clone flag, and the leak of the host's cgroup path is documented.
//
// The runner. Every fact is a fact about one kernel on one image; these say
// which, so that "tested" is claimed for exactly what ran.
//
//	K10                     recorded  the runner exists and ran the tests
//	T-host-kernel           recorded  kernel release
//	T-host-arch             recorded  architecture
//	T-host-distro           recorded  distribution
//	T-host-cgroup           recorded  cgroup v2 at /sys/fs/cgroup
//	T-host-controllers      recorded  cpu, memory and pids in the root group
//	T-host-lsm              recorded  LSMs in force
//	T-host-apparmor-userns  recorded  kernel.apparmor_restrict_unprivileged_userns
//	T-host-max-userns       recorded  user.max_user_namespaces
//	T-host-inotify          recorded  fs.inotify.max_user_instances
//	T-host-core-pattern     recorded  kernel.core_pattern is a pipe handler
//	T-host-fs-var-lib       recorded  filesystem of /var/lib
//	T-host-fs-tmp           recorded  filesystem of /tmp
//	T-host-loop-control     recorded  /dev/loop-control
//	T-host-mkfs-ext4        recorded  mkfs.ext4
//	T-host-nft              recorded  nft
//	T-host-runsc            recorded  runsc and its version
//	T-host-systemd          recorded  systemd and its version
//
// The tests themselves. A root test that leaves something behind is a
// defect of the test, and of whatever it shows to be leaking.
//
//	Z-mounts     required  the mount table of the host is as it was found
//	Z-cgroups    required  no cgroup is left
//	Z-loops      required  no loop device is left attached
//	Z-processes  required  no helper process is left, and so no namespace
//	Z-sysctls    required  the sysctls the tests touch are as they were found
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
// Two rules keep the host safe. A helper that mounts or configures a
// network first checks that it is not in the namespace of the test process,
// so a forgotten clone flag cannot touch the host. And a helper that waits
// does so on its standard input, whose other end only the test holds: when
// the test dies, the helper ends, and its namespaces with it.
//
// Where half of a mechanism needs no privilege (the socket passing of K1,
// the path resolution of T-mnt, the crash of K7), a self-test next to the
// root test runs that half on any host, so that a "no" on a runner is a
// fact about the kernel and not a defect of the instrument.
//
// To add a fact: add it to the catalogue, give it a line here in the group
// of the decision it gates, declare it in the test that records it. The
// self-tests and the last test fail until the three agree.
package kernelfacts
