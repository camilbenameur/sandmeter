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
