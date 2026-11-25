package hidden

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/camilbenameur/sandmeter/internal/backend/native"
	"github.com/camilbenameur/sandmeter/internal/exit"
	"github.com/camilbenameur/sandmeter/internal/hidden/entry"
)

// TestMain makes this test binary what a binary that starts sandboxes is: a
// program that hands control to a hidden entry point before anything else.
// The tests below start it again with such an argument. It answers to the
// init of the first backend too, as the binaries that still run that backend
// do; the root service does not.
func TestMain(m *testing.M) {
	DispatchLegacy(os.Args)
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
	// The table is exactly the entry points of package entry: each of them
	// begins with the handshake, and nothing else is in it.
	for _, name := range entry.Names {
		if !seen[name] {
			t.Errorf("the entry point %q has a name and no row in the table", name)
		}
	}
	if len(entryPoints) != len(entry.Names) {
		t.Errorf("the table has %d rows, want the %d named entry points and nothing else", len(entryPoints), len(entry.Names))
	}
	// The init of the first backend has no handshake. It is kept out of the
	// table, in one of its own, for as long as it runs today's sandboxes.
	if seen[native.InitArg] {
		t.Errorf("the init of the first backend (%q) is in the table of the root service", native.InitArg)
	}
	if len(legacyEntryPoints) != 1 || legacyEntryPoints[0].Arg != native.InitArg || legacyEntryPoints[0].Run == nil || legacyEntryPoints[0].Doc == "" {
		t.Errorf("the legacy table is %+v: the first native backend could not start a command", legacyEntryPoints)
	}
}

// TestTheRootServiceDoesNotAnswerToTheFirstInit: that init reads a root
// filesystem and a command from a descriptor without any handshake. No
// command line makes the table of the root service run it. Dispatch returns
// here, which it would not do had it found an entry point.
func TestTheRootServiceDoesNotAnswerToTheFirstInit(t *testing.T) {
	Dispatch([]string{"sandmeterd", native.InitArg})
	Dispatch([]string{"sandmeterd", native.InitArg, "extra"})
	ran := false
	for _, e := range entryPoints {
		ran = ran || e.Arg == native.InitArg
	}
	if ran {
		t.Error("the table of the root service holds the first init")
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
			DispatchLegacy(args)
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
// descriptor 3 when it is not nil and the environment a parent writes for an
// entry point plus env, and returns its exit status and what it wrote to
// standard error.
func enter(t *testing.T, name string, control *os.File, env ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], name)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Env = append(entry.Environ(nil), env...)
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

// TestEntryPointsRefuseAnInheritedEnvironment completes the handshake as a
// parent would, and leaves in the environment a variable no parent of an
// entry point puts there: the entry point does not run.
func TestEntryPointsRefuseAnInheritedEnvironment(t *testing.T) {
	for _, name := range entry.Names {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := entry.Offer(w, name); err != nil {
			t.Fatal(err)
		}
		w.Close()
		code, stderr := enter(t, name, r, "SSL_CERT_FILE=/home/dev/ca.pem", "HOME=/root")
		r.Close()
		if code != exit.Failure || !strings.Contains(stderr, "refused to run") || !strings.Contains(stderr, "HOME, SSL_CERT_FILE") || strings.Contains(stderr, "ca.pem") {
			t.Errorf("%s with an inherited environment: exit %d, stderr:\n%s", name, code, stderr)
		}
	}
}

// TestTheFirstInitTakesItsConfigurationFromAPipeOnly: the init of the first
// backend has no handshake of its own. Started by hand, or with a file
// redirected onto its descriptor, it must not read a configuration and act
// on it.
func TestTheFirstInitTakesItsConfigurationFromAPipeOnly(t *testing.T) {
	// A file that holds a configuration the init would otherwise obey.
	config := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(config, []byte(`{"root":"/","hostname":"taken","argv":["/bin/true"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(config)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	code, stderr := enter(t, native.InitArg, file)
	if code != exit.Failure || !strings.Contains(stderr, "refused to run") || !strings.Contains(stderr, "not a pipe or a socket") || !strings.Contains(stderr, "internal entry point") {
		t.Errorf("with a file as configuration: exit %d, stderr:\n%s", code, stderr)
	}
	code, stderr = enter(t, native.InitArg, nil)
	if code != exit.Failure || !strings.Contains(stderr, "refused to run") || !strings.Contains(stderr, "no control channel") {
		t.Errorf("with nothing on the descriptor: exit %d, stderr:\n%s", code, stderr)
	}

	// A pipe is what its backend hands it: the check lets it through, and
	// the init itself then fails on the configuration that never comes.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	code, stderr = enter(t, native.InitArg, r)
	r.Close()
	if code == exit.Failure || strings.Contains(stderr, "refused to run") {
		t.Errorf("with an empty pipe: exit %d, stderr:\n%s; the check must let a pipe through", code, stderr)
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
