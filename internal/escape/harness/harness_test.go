//go:build linux

package harness

import (
	"regexp"
	"slices"
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

// The scripts keep their own variables in lower case, so an upper-case name
// is one they expect from their environment. Three patterns find those
// names, wherever they stand: in code, in a quoted string handed to another
// shell, or in a comment.
var (
	// $NAME, ${NAME}, ${NAME:-word} and the like, and ${#NAME}.
	expansion = regexp.MustCompile(`\$(?:\{#?)?([A-Z][A-Z0-9_]*)`)
	// $((...)), where a variable is read by its bare name.
	arithmetic = regexp.MustCompile(`\$\(\((.*?)\)\)`)
	bareName   = regexp.MustCompile(`\b[A-Z][A-Z0-9_]*\b`)
	// Any mention of a name with the harness prefix: an assignment or a
	// message that misspells one misleads as much as an expansion does.
	prefixed = regexp.MustCompile(`\bSANDMETER_[A-Z0-9_]+`)
)

// environmentNames lists the names a script expects from its environment,
// each once, in the order they first appear.
func environmentNames(script string) []string {
	var names []string
	add := func(name string) {
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	for _, m := range expansion.FindAllStringSubmatch(script, -1) {
		add(m[1])
	}
	for _, m := range arithmetic.FindAllStringSubmatch(script, -1) {
		for _, name := range bareName.FindAllString(m[1], -1) {
			add(name)
		}
	}
	for _, name := range prefixed.FindAllString(script, -1) {
		add(name)
	}
	return names
}

func TestEnvironmentNames(t *testing.T) {
	for script, want := range map[string][]string{
		`cat "$CANARY"`:                           {"CANARY"},
		`[ -n "${EGRESS_IP:-}" ] || exit 2`:       {"EGRESS_IP"},
		`echo "${#TOKEN} ${PORT%:*}"`:             {"TOKEN", "PORT"},
		`p="$pid/$leaf$CANARY_PATH"`:              {"CANARY_PATH"},
		`target=$((LIMIT_BYTES * 4 + total))`:     {"LIMIT_BYTES"},
		`sh -c "echo \$\$ >'$child/\$MARKER'"`:    {"MARKER"},
		`# reads SANDMETER_ESCAPE_X when set`:     {"SANDMETER_ESCAPE_X"},
		`SANDMETER_ESCAPE_Y=$(printf %d "0x$h")`:  {"SANDMETER_ESCAPE_Y"},
		`echo "RESULT: BLOCKED $out"; kill -KILL`: nil,
		`awk '$2 == "00000000" { print $3 }' $$`:  nil,
		`count=$((count + 1)); echo "$1" "$@"`:    nil,
		`echo "$A_1 ${A_1} $((A_1))"`:             {"A_1"},
	} {
		if got := environmentNames(script); !slices.Equal(got, want) {
			t.Errorf("environmentNames(%q) = %q, want %q", script, got, want)
		}
	}
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
	read := map[string]bool{}
	for _, c := range cases {
		for _, name := range environmentNames(c.Script) {
			read[name] = true
			if !set[name] && !optional[name] {
				t.Errorf("case %s expects %s from its environment, and the harness does not set it. "+
					"Correct the name (a variable of the script's own is written in lower case); "+
					"if the case may run without the variable, list it as optional in this test.", c.ID, name)
			}
		}
	}
	// The other way round, as a check on this test: if no case read any of
	// the variables, the patterns above would have stopped matching.
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
