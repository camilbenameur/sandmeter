//go:build integration && linux

package kernelfacts

import (
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// scratchEnv chooses the directory under which the tests work. The default
// is /var/lib, the filesystem that will hold the state of the service: the
// facts about overlays are facts about that filesystem.
const scratchEnv = "SANDMETER_FACTS_DIR"

var (
	// scratchRoot is the directory of this run; "" when the tests do not
	// run as root and therefore create nothing.
	scratchRoot string
	// baseline is the state of the host before the first test.
	baseline hostState
	// hostMntNS, hostNetNS and hostPidNS are the mount, network and pid
	// namespaces of the test process, read once before the first test.
	// Helpers are told them so that they can refuse to work there
	// (outsideHost); read at each start of a helper, they would follow
	// whatever a test did to the thread that /proc/self names.
	hostMntNS, hostNetNS, hostPidNS string
)

// The main goroutine stays on the main thread, in the test process and in
// every helper. In the test process this keeps the goroutines of the tests
// off that thread: one of them enters the network namespace of a sandbox,
// and a thread that cannot be brought back must be one the runtime is able
// to end, which the main thread is not (threads_test.go). In a helper it
// makes /proc/self/ns describe the very thread that goes on to mount.
func init() { runtime.LockOSThread() }

// plainPath is what a scratch path may look like: it ends up in overlay
// option strings and in a shell script, where a comma, a colon or a quote
// would change the meaning.
var plainPath = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)+$`)

// TestMain is both the entry point of the tests and of their helper
// processes (see childArg).
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == childArg {
		os.Exit(childMain(os.Args[2:]))
	}
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	// Helpers that run as the shifted uid reach the files of a test through
	// their "other" permission bits: the modes the tests ask for must be
	// the modes they get, whatever umask root has here.
	unix.Umask(0o022)
	hostMntNS, hostNetNS, hostPidNS = nsLink("mnt"), nsLink("net"), nsLink("pid")
	baseline = snapshotHost()
	if os.Geteuid() != 0 {
		// Every test that creates something skips itself, or fails when
		// SANDMETER_REQUIRE lists root; the ones that only read still run.
		return m.Run()
	}
	dir, err := makeScratchRoot()
	if err != nil {
		fmt.Fprintf(os.Stderr, "kernelfacts: %v\n", err)
		return 1
	}
	scratchRoot = dir

	code := m.Run()

	// The last test compared the host with the baseline; it does not run
	// under -run or -shuffle, and it cannot see what the teardown below
	// leaves. So the comparison is made once more here, and decides the
	// exit status.
	var left []string
	if err := os.RemoveAll(scratchRoot); err != nil {
		left = append(left, "scratch directory: "+err.Error())
	}
	if err := removeCgParent(); err != nil {
		left = append(left, "cgroups: "+err.Error())
	}
	for _, c := range []struct{ what, diff string }{
		{"mount table", baseline.mountsDiff()},
		{"cgroups", baseline.cgroupsDiff(true)},
		{"loop devices", baseline.loopsDiff()},
		{"helper processes", strayHelpers()},
		{"threads of the test process", settled(strayThreads)},
		{"sysctls", baseline.sysctlsDiff()},
	} {
		if c.diff != "" {
			left = append(left, c.what+": "+c.diff)
		}
	}
	if len(left) > 0 {
		fmt.Fprintf(os.Stderr, "kernelfacts: the host is not as the tests found it:\n  %s\n", strings.Join(left, "\n  "))
		if code == 0 {
			code = 1
		}
	}
	return code
}

// makeScratchRoot creates the directory of this run. Anyone may search it
// and only root may list it: helpers that run as the shifted uid reach what
// a test prepares for them, and nothing else does by accident.
func makeScratchRoot() (string, error) {
	base := os.Getenv(scratchEnv)
	if base == "" {
		base = "/var/lib"
	}
	if !plainPath.MatchString(base) {
		return "", fmt.Errorf("%s=%q: want an absolute path made of letters, digits, '.', '_', '-' and '/'", scratchEnv, base)
	}
	dir, err := os.MkdirTemp(base, "sandmeter-facts-")
	if err != nil {
		return "", fmt.Errorf("scratch directory: %w", err)
	}
	if err := os.Chmod(dir, 0o711); err != nil {
		os.Remove(dir)
		return "", fmt.Errorf("scratch directory: %w", err)
	}
	return dir, nil
}
