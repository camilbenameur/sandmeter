//go:build integration && linux

package kernelfacts

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
)

// Environment variables read by this package.
const (
	// factsOutEnv names a file that receives one JSON line per fact.
	factsOutEnv = "SANDMETER_FACTS_OUT"
	// requireEnv lists prerequisites (root, cgroup2, runsc) whose absence
	// fails a test instead of skipping it.
	requireEnv = "SANDMETER_REQUIRE"
	// throwawayEnv, together with CI=true, allows the tests that change a
	// host-wide setting for a moment (K7, the first half of K2b).
	throwawayEnv = "SANDMETER_THROWAWAY_HOST"
)

// Outcomes of a fact.
const (
	yes     = "yes"
	no      = "no"
	skipped = "skipped"
)

// fact is one line of the record: what this kernel did for one assumption.
type fact struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Required bool   `json:"required"`
	Outcome  string `json:"outcome"`
	Detail   string `json:"detail"`
	Kernel   string `json:"kernel"`
}

// def declares a fact. name is a statement: the outcome "yes" means it holds
// on this host. A required fact gates a design decision of v0.1.0, so its
// "no" fails the test; the others are measurements and never fail.
type def struct {
	id       string
	name     string
	required bool
}

// catalogued finds a fact by identifier.
func catalogued(id string) (def, bool) {
	for _, d := range catalogue {
		if d.id == id {
			return d, true
		}
	}
	return def{}, false
}

var (
	recordMu sync.Mutex
	// recorded holds the facts of this run by identifier, for the final
	// check that none is missing.
	recorded = map[string]fact{}
)

// maxDetail bounds the detail of a fact. What is cut is said in the text.
const maxDetail = 1500

// cleanDetail puts a detail on one line and bounds its length.
func cleanDetail(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxDetail {
		cut := maxDetail
		for cut > 0 && s[cut]&0xC0 == 0x80 { // do not split a UTF-8 sequence
			cut--
		}
		s = fmt.Sprintf("%s ... (%d more bytes cut)", s[:cut], len(s)-cut)
	}
	return s
}

// emit writes a fact as a "FACT " line on standard output and, when
// SANDMETER_FACTS_OUT is set, as one JSON line appended to that file.
func emit(f fact) error { return emitTo(os.Stdout, f) }

// emitTo is emit with the log line going to log.
func emitTo(log io.Writer, f fact) error {
	line, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("encode fact %s: %w", f.ID, err)
	}
	recordMu.Lock()
	defer recordMu.Unlock()
	recorded[f.ID] = f
	// Straight to the descriptor, in one write: the line must start at
	// column zero, which t.Log would not do.
	if _, err := log.Write(append(append([]byte("FACT "), line...), '\n')); err != nil {
		return fmt.Errorf("print fact %s: %w", f.ID, err)
	}
	path := os.Getenv(factsOutEnv)
	if path == "" {
		return nil
	}
	out, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("%s: %w", factsOutEnv, err)
	}
	if _, err := out.Write(append(line, '\n')); err != nil {
		out.Close()
		return fmt.Errorf("%s: %w", factsOutEnv, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("%s: %w", factsOutEnv, err)
	}
	return nil
}

// recorder records the facts of one test. Every fact a test declares is
// recorded exactly once: what is still open when the test ends is closed by
// the cleanup, so the record never has a hole.
type recorder struct {
	t    *testing.T
	open []def
}

// declare names the facts a test is going to record.
func declare(t *testing.T, ids ...string) *recorder {
	t.Helper()
	r := &recorder{t: t}
	for _, id := range ids {
		d, ok := catalogued(id)
		if !ok {
			t.Fatalf("fact %q is not in the catalogue (catalogue_test.go)", id)
		}
		r.open = append(r.open, d)
	}
	t.Cleanup(r.close)
	return r
}

// record writes one fact. A required fact whose outcome is "no" fails the
// test, without stopping it: the facts that follow are still measured.
func (r *recorder) record(id, outcome, detail string) {
	r.t.Helper()
	i := slices.IndexFunc(r.open, func(d def) bool { return d.id == id })
	if i < 0 {
		r.t.Fatalf("fact %q is recorded twice, or was not declared by this test", id)
	}
	d := r.open[i]
	r.open = slices.Delete(r.open, i, i+1)
	f := fact{ID: d.id, Name: d.name, Required: d.required, Outcome: outcome, Detail: cleanDetail(detail), Kernel: kernelRelease()}
	if err := emit(f); err != nil {
		r.t.Errorf("the record is incomplete: %v", err)
	}
	if outcome == no && d.required {
		r.t.Errorf("%s is a required fact and this host says no.\n  expected: %s\n  found:    %s", d.id, d.name, f.Detail)
	}
}

func (r *recorder) yes(id, format string, args ...any) {
	r.t.Helper()
	r.record(id, yes, fmt.Sprintf(format, args...))
}

func (r *recorder) no(id, format string, args ...any) {
	r.t.Helper()
	r.record(id, no, fmt.Sprintf(format, args...))
}

func (r *recorder) skip(id, format string, args ...any) {
	r.t.Helper()
	r.record(id, skipped, fmt.Sprintf(format, args...))
}

// judge records yes or no with the same detail.
func (r *recorder) judge(id string, ok bool, format string, args ...any) {
	r.t.Helper()
	if ok {
		r.yes(id, format, args...)
		return
	}
	r.no(id, format, args...)
}

// skipRest records every fact still open as skipped, with the reason.
func (r *recorder) skipRest(format string, args ...any) {
	r.t.Helper()
	reason := fmt.Sprintf(format, args...)
	for len(r.open) > 0 {
		r.record(r.open[0].id, skipped, reason)
	}
}

// need stops the test when a prerequisite is missing. The facts still open
// are recorded as skipped with the reason. When SANDMETER_REQUIRE lists the
// prerequisite the test fails instead: on CI a missing prerequisite is a
// broken job, not a result.
func (r *recorder) need(prerequisite string, ok bool, reason string) {
	r.t.Helper()
	if ok {
		return
	}
	if requireLists(prerequisite) {
		r.skipRest("%s (%s lists %s, so this is a failure)", reason, requireEnv, prerequisite)
		r.t.Fatalf("%s lists %q but %s", requireEnv, prerequisite, reason)
	}
	r.skipRest("%s", reason)
	r.t.Skip(reason)
}

// needRoot is the first line of every test that creates anything.
func (r *recorder) needRoot() {
	r.t.Helper()
	r.need("root", os.Geteuid() == 0, `these tests need root: run them with go test -exec "sudo -E" -tags integration`)
}

// needCgroup2 stops a test that needs the unified cgroup hierarchy.
func (r *recorder) needCgroup2() {
	r.t.Helper()
	r.need("cgroup2", haveCgroup2(), "cgroup v2 is not mounted at "+cgroupRoot)
}

// close records what the test left open. Such a fact was not measured, so
// its outcome is "skipped" whatever stopped the test: a "no" is only ever
// something the kernel answered. The failure is carried by the test.
func (r *recorder) close() {
	for len(r.open) > 0 {
		d := r.open[0]
		switch {
		case r.t.Skipped():
			r.record(d.id, skipped, "not measured: the test was skipped before it reached this fact")
		case r.t.Failed():
			r.record(d.id, skipped, "not measured: the test failed before it reached this fact")
		default:
			r.record(d.id, skipped, "not measured: the test ended without recording this fact")
			r.t.Errorf("fact %s was declared and never recorded: the test has a path that forgets it", d.id)
		}
	}
}

// requireLists reports whether SANDMETER_REQUIRE names the prerequisite.
func requireLists(name string) bool {
	for _, f := range strings.Split(os.Getenv(requireEnv), ",") {
		if strings.TrimSpace(f) == name {
			return true
		}
	}
	return false
}

// throwawayHost reports whether this machine may have a host-wide setting
// changed for the length of a test.
func throwawayHost() bool {
	return os.Getenv("CI") == "true" && os.Getenv(throwawayEnv) == "1"
}
