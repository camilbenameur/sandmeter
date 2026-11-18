//go:build integration && linux

package kernelfacts

import (
	"flag"
	"slices"
	"strings"
	"testing"
)

// The last test of the package, by the name of its file: go test runs the
// tests of a package in the order of their files, then of their
// declarations. It compares the host with the snapshot TestMain took before
// the first test. TestMain makes the same comparison again after its own
// teardown, so a run narrowed with -run or shuffled is covered too.

// wholeSuite reports whether go test was asked for every test, in order.
func wholeSuite() bool {
	for name, want := range map[string]string{"test.run": "", "test.skip": "", "test.shuffle": "off"} {
		if f := flag.Lookup(name); f != nil && f.Value.String() != want {
			return false
		}
	}
	return true
}

func TestZZHostLeftClean(t *testing.T) {
	r := declare(t, "Z-mounts", "Z-cgroups", "Z-loops", "Z-processes", "Z-sysctls")

	d := baseline.mountsDiff()
	r.judge("Z-mounts", d == "", "lines of /proc/self/mountinfo that differ from the snapshot taken before the first test: %s", orNothing(d))

	d = baseline.cgroupsDiff(false)
	r.judge("Z-cgroups", d == "", "under %s, against the snapshot: %s; controllers the root hands down, which the service manager changes on its own: %s",
		cgroupRoot, orNothing(d), baseline.subtreeNote())

	d = baseline.loopsDiff()
	r.judge("Z-loops", d == "", "loop devices with a backing file, against the snapshot (%d then): %s", len(baseline.loops), orNothing(d))

	d = strayHelpers()
	r.judge("Z-processes", d == "", "processes that still run the test binary, and with them any namespace a test created: %s", orNothing(d))

	d = baseline.sysctlsDiff()
	r.judge("Z-sysctls", d == "", "of %s: %s", strings.Join(watchedSysctls, ", "), orNothing(d))

	// The record has no hole: when the whole suite ran, every fact of the
	// catalogue was recorded, whatever its outcome.
	if !wholeSuite() {
		return
	}
	recordMu.Lock()
	defer recordMu.Unlock()
	var missing []string
	for _, entry := range catalogue {
		if _, ok := recorded[entry.id]; !ok {
			missing = append(missing, entry.id)
		}
	}
	slices.Sort(missing)
	if len(missing) > 0 {
		t.Errorf("facts of the catalogue that no test recorded: %v", missing)
	}
}
