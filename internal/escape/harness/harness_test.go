//go:build linux

package harness

import (
	"regexp"
	"strings"
	"testing"

	"github.com/camilbenameur/sandmeter/internal/escape"
)

// The harness itself needs root and real backends. These tests check, without
// either, the two contracts between the harness and the case scripts that
// nothing else would catch before a full run: the names of the environment
// variables and the name of the probe.

func harnessEnvNames(t *testing.T) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	for _, kv := range caseEnv("/canary", "/marker", "192.0.2.1", "1", "2", 3, 4) {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || value == "" {
			t.Errorf("%q is not NAME=value", kv)
		}
		if !strings.HasPrefix(name, "SANDMETER_ESCAPE_") {
			t.Errorf("%s: every variable the harness sets starts with SANDMETER_ESCAPE_", name)
		}
		if names[name] {
			t.Errorf("%s is set twice", name)
		}
		names[name] = true
	}
	return names
}

func TestCasesOnlyReadWhatTheHarnessSets(t *testing.T) {
	set := harnessEnvNames(t)
	// A case may read these without the harness setting them. Without the
	// sandbox root, case 06 stops at EXPOSED: see the package README.
	optional := map[string]bool{"SANDMETER_ESCAPE_SANDBOX_ROOT": true}

	cases, err := escape.Cases()
	if err != nil {
		t.Fatal(err)
	}
	variable := regexp.MustCompile(`\bSANDMETER_[A-Z0-9_]+`)
	read := map[string]bool{}
	for _, c := range cases {
		for _, name := range variable.FindAllString(c.Script, -1) {
			read[name] = true
			if !set[name] && !optional[name] {
				t.Errorf("case %s reads %s, which the harness does not set", c.ID, name)
			}
		}
	}
	// The other way round, as a check on this test: if no case read any of
	// the variables, the pattern above would have stopped matching.
	for _, name := range []string{"SANDMETER_ESCAPE_HOST_CANARY_PATH", "SANDMETER_ESCAPE_EGRESS_PORT"} {
		if !read[name] {
			t.Errorf("no case reads %s any more: is this test still looking at the scripts?", name)
		}
	}
}

func TestCasesCallTheProbeTheHarnessInstalls(t *testing.T) {
	cases, err := escape.Cases()
	if err != nil {
		t.Fatal(err)
	}
	// A case that needs the probe first checks for it with "command -v".
	check := regexp.MustCompile(`command -v ([A-Za-z0-9_.-]+)`)
	checked := 0
	for _, c := range cases {
		for _, m := range check.FindAllStringSubmatch(c.Script, -1) {
			checked++
			if m[1] != probeName {
				t.Errorf("case %s looks for %q, the harness installs %q", c.ID, m[1], probeName)
			}
			if !strings.Contains(c.Script, "$("+probeName+" ") {
				t.Errorf("case %s checks for %s and never runs it", c.ID, probeName)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no case checks for the probe: is this test still looking at the scripts?")
	}
}
