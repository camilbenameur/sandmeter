package hidden

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/camilbenameur/sandmeter/internal/backend/native"
	"github.com/camilbenameur/sandmeter/internal/exit"
	"github.com/camilbenameur/sandmeter/internal/hidden/entry"
)

// TestMain makes this test binary what every binary of the root side is: a
// program that hands control to a hidden entry point before anything else.
// The tests below start it again with such an argument.
func TestMain(m *testing.M) {
	Dispatch(os.Args)
	os.Exit(m.Run())
}

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
	// The table is exactly the entry points of package entry, plus the init
	// of the first native backend for as long as it runs today's sandboxes.
	for _, name := range entry.Names {
		if !seen[name] {
			t.Errorf("the entry point %q has a name and no row in the table", name)
		}
	}
	if !seen[native.InitArg] {
		t.Errorf("the native sandbox init (%q) is not in the table: the native backend could not start a command", native.InitArg)
	}
	if len(entryPoints) != len(entry.Names)+1 {
		t.Errorf("the table has %d rows, want the %d named entry points and the first init", len(entryPoints), len(entry.Names))
	}
}

// TestDispatchReturnsOnOrdinaryCommandLines uses the real table. None of
// these command lines may select an entry point: the test would not survive
// it.
func TestDispatchReturnsOnOrdinaryCommandLines(t *testing.T) {
	for _, name := range append([]string{native.InitArg}, entry.Names...) {
		for _, args := range [][]string{
			nil,
			{},
			{"sandmeterd"},
			{"sandmeterd", ""},
			{"sandmeterd", "serve"},
			{"sandmeterd", "serve", "--", name},
			{"sandmeterd", "-test.run=^$", name},
			{"sandmeterd", name + "x"},
			{"sandmeterd", strings.TrimPrefix(name, "_")},
			{"sandmeterd", " " + name},
			{"sandmeterd", strings.ToUpper(name)},
			{name},
		} {
			Dispatch(args)
		}
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

// enter starts this test binary as the named entry point, with control on
// descriptor 3 when it is not nil, and returns its exit status and what it
// wrote to standard error.
func enter(t *testing.T, name string, control *os.File) (int, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], name)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Env = []string{}
	if control != nil {
		cmd.ExtraFiles = []*os.File{control}
	}
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, stderr.String()
	case errors.As(err, &ee):
		return ee.ExitCode(), stderr.String()
	}
	t.Fatalf("start %s: %v", name, err)
	return 0, ""
}

// TestEntryPointsRefuseToRunByHand starts each named entry point the way a
// person would, with nothing on descriptor 3, and with a file there: it must
// exit at once, with the failure status and a message that says what it is.
func TestEntryPointsRefuseToRunByHand(t *testing.T) {
	file, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	for _, name := range entry.Names {
		code, stderr := enter(t, name, nil)
		if code != exit.Failure || !strings.Contains(stderr, "refused to run") || !strings.Contains(stderr, "internal entry point") || !strings.Contains(stderr, name) {
			t.Errorf("%s with no control channel: exit %d, stderr:\n%s", name, code, stderr)
		}
		code, stderr = enter(t, name, file)
		if code != exit.Failure || !strings.Contains(stderr, "not a pipe or a socket") {
			t.Errorf("%s with a file as control channel: exit %d, stderr:\n%s", name, code, stderr)
		}
	}
}

// TestEntryPointsThatAreNotBuiltSaySo completes the handshake as a parent
// would. An entry point whose body is not written yet then says so and
// fails; the test has nothing to say about one that is written.
func TestEntryPointsThatAreNotBuiltSaySo(t *testing.T) {
	for _, name := range entry.Names {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := entry.Offer(w, name); err != nil {
			t.Fatal(err)
		}
		w.Close()
		code, stderr := enter(t, name, r)
		r.Close()
		if !strings.Contains(stderr, "not built in this version") {
			t.Logf("%s is built: exit %d", name, code)
			continue
		}
		if code != exit.Failure || !strings.Contains(stderr, name) || strings.Contains(stderr, "refused to run") {
			t.Errorf("%s after a good handshake: exit %d, stderr:\n%s", name, code, stderr)
		}
	}
}
