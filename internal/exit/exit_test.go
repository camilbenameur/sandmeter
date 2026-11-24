package exit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/camilbenameur/sandmeter/receipt"
)

func ip(v int) *int { return &v }

// TestTableMatchesTheConstants reads this package's source: every constant
// of the status block is a row of the table, under its own name, once, with
// a doc comment, and the rows are in ascending order with no number used
// twice.
func TestTableMatchesTheConstants(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "exit.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	for _, d := range f.Decls {
		gen, ok := d.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs := spec.(*ast.ValueSpec)
			for _, name := range vs.Names {
				declared[name.Name] = true
				if vs.Doc == nil || !strings.HasPrefix(vs.Doc.Text(), name.Name+":") && !strings.HasPrefix(vs.Doc.Text(), name.Name+" ") {
					t.Errorf("constant %s needs a doc comment that starts with its name", name.Name)
				}
			}
		}
	}
	if len(declared) == 0 {
		t.Fatal("no constant found: the check below would pass on nothing")
	}
	seenName, seenCode := map[string]bool{}, map[int]bool{}
	last := -1
	for _, row := range Table {
		if !declared[row.Name] {
			t.Errorf("row %q of the table is not a constant of the package", row.Name)
		}
		if seenName[row.Name] || seenCode[row.Code] {
			t.Errorf("row %q (%d) repeats a name or a number", row.Name, row.Code)
		}
		seenName[row.Name], seenCode[row.Code] = true, true
		if row.Code <= last {
			t.Errorf("row %q (%d) is out of order", row.Name, row.Code)
		}
		last = row.Code
		if row.Meaning == "" || row.Code < 0 || row.Code > 128 {
			t.Errorf("row %+v: a meaning and a status between 0 and 128 are required", row)
		}
	}
	for name := range declared {
		if !seenName[name] {
			t.Errorf("constant %s is missing from the table", name)
		}
	}
}

func TestConventions(t *testing.T) {
	// The numbers people already know.
	if Usage != 2 || Timeout != 124 || Failure != 125 || NotExecutable != 126 || NotFound != 127 || SignalBase != 128 {
		t.Error("a conventional status moved")
	}
	// What sandmeter adds for a sandboxed command stays clear of the small
	// numbers programs use for their own failures.
	for _, code := range []int{PolicyRefused, HostCannotRun, Denied, TeardownFailed} {
		if code < 120 || code >= Timeout {
			t.Errorf("status %d is outside 120 to 123", code)
		}
	}
}

func TestForSignal(t *testing.T) {
	for n, want := range map[int]int{9: 137, 15: 143, 13: 141, 1: 129, 0: Failure, -3: Failure, 200: Failure} {
		if got := ForSignal(n); got != want {
			t.Errorf("ForSignal(%d) = %d, want %d", n, got, want)
		}
	}
}

func TestForOutcome(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		o                           receipt.OutcomeV2
		cleanupFailed, recordFailed bool
		want                        int
	}{
		{name: "success", o: receipt.OutcomeV2{Status: receipt.StatusExited, ExitCode: ip(0)}, want: 0},
		{name: "the command's own failure", o: receipt.OutcomeV2{Status: receipt.StatusExited, ExitCode: ip(3)}, want: 3},
		{name: "the command's own 125", o: receipt.OutcomeV2{Status: receipt.StatusExited, ExitCode: ip(125)}, want: 125},
		{name: "exited without a status", o: receipt.OutcomeV2{Status: receipt.StatusExited}, want: Failure},
		{name: "exited with an impossible status", o: receipt.OutcomeV2{Status: receipt.StatusExited, ExitCode: ip(256)}, want: Failure},
		{name: "not found", o: receipt.OutcomeV2{Status: receipt.StatusExecFailed, ExitCode: ip(127)}, want: NotFound},
		{name: "not executable", o: receipt.OutcomeV2{Status: receipt.StatusExecFailed, ExitCode: ip(126)}, want: NotExecutable},
		{name: "exec failure with another status", o: receipt.OutcomeV2{Status: receipt.StatusExecFailed, ExitCode: ip(1)}, want: Failure},
		{name: "abort", o: receipt.OutcomeV2{Status: receipt.StatusSignalled, Signal: ip(6)}, want: 134},
		{name: "signalled without a signal", o: receipt.OutcomeV2{Status: receipt.StatusSignalled}, want: Failure},
		{name: "time limit", o: receipt.OutcomeV2{Status: receipt.StatusKilled, KillReason: receipt.KillWallTimeout, Signal: ip(9)}, want: Timeout},
		{name: "memory limit", o: receipt.OutcomeV2{Status: receipt.StatusKilled, KillReason: receipt.KillOOM, Signal: ip(9)}, want: 137},
		{name: "cancelled", o: receipt.OutcomeV2{Status: receipt.StatusKilled, KillReason: receipt.KillCancelled, Signal: ip(9)}, want: Failure},
		{name: "stopped", o: receipt.OutcomeV2{Status: receipt.StatusKilled, KillReason: receipt.KillStopped}, want: Failure},
		{name: "free-space floor", o: receipt.OutcomeV2{Status: receipt.StatusKilled, KillReason: receipt.KillDiskFloor}, want: Failure},
		{name: "supervisor lost", o: receipt.OutcomeV2{Status: receipt.StatusKilled, KillReason: receipt.KillSupervisorLost}, want: Failure},
		{name: "init lost", o: receipt.OutcomeV2{Status: receipt.StatusKilled, KillReason: receipt.KillInitLost}, want: Failure},
		{name: "set-up failure", o: receipt.OutcomeV2{Status: receipt.StatusSetupFailed, Error: "no overlay"}, want: Failure},
		{name: "a status this build does not know", o: receipt.OutcomeV2{Status: "teleported", ExitCode: ip(0)}, want: Failure},
		{name: "zero value", o: receipt.OutcomeV2{}, want: Failure},
		// A leak is never silent, even behind a command that succeeded.
		{name: "success with a failed teardown", o: receipt.OutcomeV2{Status: receipt.StatusExited, ExitCode: ip(0)}, cleanupFailed: true, want: TeardownFailed},
		{name: "failure with a failed teardown", o: receipt.OutcomeV2{Status: receipt.StatusExited, ExitCode: ip(1)}, cleanupFailed: true, want: TeardownFailed},
		// A command without a record is a failure of sandmeter first.
		{name: "success without a record", o: receipt.OutcomeV2{Status: receipt.StatusExited, ExitCode: ip(0)}, recordFailed: true, want: Failure},
		{name: "no record and a failed teardown", o: receipt.OutcomeV2{Status: receipt.StatusExited, ExitCode: ip(0)}, cleanupFailed: true, recordFailed: true, want: Failure},
	} {
		if got := ForOutcome(tc.o, tc.cleanupFailed, tc.recordFailed); got != tc.want {
			t.Errorf("%s: ForOutcome = %d, want %d", tc.name, got, tc.want)
		}
	}
}
