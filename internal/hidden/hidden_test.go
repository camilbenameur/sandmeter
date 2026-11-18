package hidden

import (
	"strings"
	"testing"

	"github.com/camilbenameur/sandmeter/internal/backend/native"
)

func TestTable(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range entryPoints {
		if !strings.HasPrefix(e.Arg, "__") || len(e.Arg) < 3 {
			t.Errorf("entry point %q: the argument must start with \"__\", so that it cannot be taken for a command or a flag", e.Arg)
		}
		if seen[e.Arg] {
			t.Errorf("entry point %q is listed twice", e.Arg)
		}
		seen[e.Arg] = true
		if e.Doc == "" || e.Run == nil {
			t.Errorf("entry point %q needs a Doc and a Run", e.Arg)
		}
	}
	if !seen[native.InitArg] {
		t.Errorf("the native sandbox init (%q) is not in the table: the native backend could not start a command", native.InitArg)
	}
}

// TestDispatchReturnsOnOrdinaryCommandLines uses the real table. None of
// these command lines may select an entry point: the test would not survive
// it.
func TestDispatchReturnsOnOrdinaryCommandLines(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{},
		{"sandmeter"},
		{"sandmeter", ""},
		{"sandmeter", "run"},
		{"sandmeter", "run", "--", native.InitArg},
		{"sandmeter", "-test.run=^$", native.InitArg},
		{"sandmeter", native.InitArg + "x"},
		{"sandmeter", strings.TrimPrefix(native.InitArg, "_")},
		{"sandmeter", " " + native.InitArg},
		{"sandmeter", strings.ToUpper(native.InitArg)},
		{native.InitArg},
	} {
		Dispatch(args)
	}
}

func TestDispatchRunsTheSelectedEntryPointOnly(t *testing.T) {
	var ran []string
	table := []EntryPoint{
		{Arg: "__a", Run: func() { ran = append(ran, "a") }},
		{Arg: "__b", Run: func() { ran = append(ran, "b") }},
	}

	dispatch(table, []string{"bin", "visible", "__a"})
	if len(ran) != 0 {
		t.Fatalf("an argument after the first selected an entry point: ran %v", ran)
	}

	// The entry points of this table return, which a real one never does:
	// dispatch must then stop the process rather than fall through.
	msg := func() (msg string) {
		defer func() {
			if r := recover(); r != nil {
				msg, _ = r.(string)
			}
		}()
		dispatch(table, []string{"bin", "__b", "data"})
		return "dispatch returned"
	}()
	if len(ran) != 1 || ran[0] != "b" {
		t.Errorf("ran %v, want only b", ran)
	}
	if !strings.Contains(msg, "__b returned") {
		t.Errorf("after an entry point returned: %q, want a panic naming it", msg)
	}
}
