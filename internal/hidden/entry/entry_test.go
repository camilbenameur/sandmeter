package entry

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/camilbenameur/sandmeter/internal/layout"
)

// short is the wait used by the tests of a missing greeting.
const short = 50 * time.Millisecond

// given is an environment an entry point is started with.
var given = Environ(nil)

func pipe(t *testing.T) (r, w *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	return r, w
}

// handOver returns a descriptor of its own for what f is open on, as a child
// gets one from its parent. Accept takes that descriptor over: the file it
// returns owns it. Passing f.Fd() itself would leave two owners for one
// number, and the collector closing the second owner later would close
// whatever descriptor has that number by then.
func handOver(t *testing.T, f *os.File) uintptr {
	t.Helper()
	fd, err := unix.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	return uintptr(fd)
}

func TestNames(t *testing.T) {
	seen := map[string]bool{}
	for _, n := range Names {
		if !strings.HasPrefix(n, "__") || len(n) < 3 || seen[n] {
			t.Errorf("name %q: it must start with \"__\" and be listed once", n)
		}
		seen[n] = true
	}
	if len(Names) != 5 || !seen[Worker] || !seen[Init] || !seen[Exec] || !seen[Egress] || !seen[Fetch] {
		t.Errorf("Names = %v", Names)
	}
	if ControlFD != 3 {
		t.Error("the control channel is the first descriptor after the standard streams")
	}
}

func TestHandshakeOverAPipe(t *testing.T) {
	r, w := pipe(t)
	// The parent may write before the child exists.
	if err := Offer(w, Egress); err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString("what follows belongs to the entry point"); err != nil {
		t.Fatal(err)
	}
	w.Close()
	fd := handOver(t, r)
	f, err := accept(fd, Egress, Timeout, given)
	if err != nil {
		unix.Close(int(fd))
		t.Fatal(err)
	}
	defer f.Close()
	if f.Fd() != fd {
		t.Errorf("Accept returned descriptor %d for descriptor %d", f.Fd(), fd)
	}
	// Accept consumed the greeting and not one byte more.
	rest, err := io.ReadAll(f)
	if err != nil || string(rest) != "what follows belongs to the entry point" {
		t.Errorf("after the handshake the channel holds %q, %v", rest, err)
	}
	flags, err := unix.FcntlInt(fd, unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Errorf("the control descriptor is not close-on-exec: %#x, %v", flags, err)
	}
}

func TestHandshakeOverASocketInPieces(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	// The child's end goes to Accept as a bare descriptor: the file Accept
	// returns is its only owner.
	parent := os.NewFile(uintptr(fds[1]), "parent")
	defer parent.Close()
	var line bytes.Buffer
	if err := Offer(&line, Worker); err != nil {
		t.Fatal(err)
	}
	go func() {
		// A greeting that arrives a few bytes at a time is still one.
		for _, b := range line.Bytes() {
			parent.Write([]byte{b})
			time.Sleep(time.Millisecond)
		}
	}()
	f, err := accept(uintptr(fds[0]), Worker, Timeout, given)
	if err != nil {
		unix.Close(fds[0])
		t.Fatalf("a greeting sent byte by byte: %v", err)
	}
	f.Close()
}

func TestAcceptRefuses(t *testing.T) {
	// refused hands accept a descriptor of its own and closes it afterwards:
	// a refusal returns no file, so nothing else owns it.
	refused := func(name string, f *os.File, entryName, want string) {
		t.Helper()
		fd := handOver(t, f)
		defer unix.Close(int(fd))
		got, err := accept(fd, entryName, short, given)
		if got != nil || !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: accept = %v, %v; want a refusal that says %q", name, got, err, want)
		}
	}

	// No greeting at all: the wait is bounded.
	r, _ := pipe(t)
	began := time.Now()
	refused("a silent parent", r, Init, "no greeting within")
	if d := time.Since(began); d > 2*time.Second {
		t.Errorf("the wait for a greeting took %v", d)
	}

	// The greeting of another entry point.
	r, w := pipe(t)
	Offer(w, Fetch)
	refused("another entry point's greeting", r, Init, "does not carry the greeting")

	// Something that is not a greeting.
	r, w = pipe(t)
	w.WriteString("GET / HTTP/1.1\r\n\r\n")
	refused("other bytes", r, Init, "does not carry the greeting")

	// A greeting cut short by the end of the channel.
	r, w = pipe(t)
	w.WriteString("sandmeter-entry/1 __in")
	w.Close()
	refused("a truncated greeting", r, Init, "closed before the greeting")

	// A regular file that holds a perfect greeting: what a person would
	// redirect onto the descriptor.
	path := filepath.Join(t.TempDir(), "greeting")
	if err := os.WriteFile(path, greeting(Init), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	refused("a regular file", file, Init, "not a pipe or a socket")

	// A directory, and a character device.
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	refused("a directory", dir, Init, "not a pipe or a socket")
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	refused("a device", null, Init, "not a pipe or a socket")

	// A descriptor that is not open.
	r, _ = pipe(t)
	closed := handOver(t, r)
	unix.Close(int(closed))
	if got, err := accept(closed, Init, short, given); got != nil || !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "no control channel on descriptor") {
		t.Errorf("a closed descriptor: accept = %v, %v", got, err)
	}

	// A name that is not an entry point, whatever the channel says.
	r, w = pipe(t)
	w.WriteString("sandmeter-entry/1 __shell\n")
	refused("an unknown name", r, "__shell", "not a hidden entry point")
}

func TestOffer(t *testing.T) {
	var b bytes.Buffer
	if err := Offer(&b, Init); err != nil || b.String() != "sandmeter-entry/1 __init\n" {
		t.Errorf("Offer wrote %q, %v", b.String(), err)
	}
	if err := Offer(&b, "__shell"); err == nil {
		t.Error("Offer greeted a name that is not an entry point")
	}
	c1, c2 := net.Pipe()
	c1.Close()
	c2.Close()
	if err := Offer(c1, Init); err == nil {
		t.Error("Offer on a closed channel reported success")
	}
}

func TestCheckChannel(t *testing.T) {
	r, _ := pipe(t)
	if err := CheckChannel(r.Fd()); err != nil {
		t.Errorf("a pipe: %v", err)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	if err := CheckChannel(uintptr(fds[0])); err != nil {
		t.Errorf("a socket: %v", err)
	}
	file, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := CheckChannel(file.Fd()); err == nil || !strings.Contains(err.Error(), "not a pipe or a socket") {
		t.Errorf("a regular file: %v", err)
	}
	gone := handOver(t, r)
	unix.Close(int(gone))
	if err := CheckChannel(gone); err == nil || !strings.Contains(err.Error(), "no control channel") {
		t.Errorf("a closed descriptor: %v", err)
	}
}

// TestEnviron: what a parent gives an entry point is written out, and holds
// nothing of what the parent itself was started with except the log level.
func TestEnviron(t *testing.T) {
	inherited := []string{
		"PATH=/home/dev/bin:/usr/bin", "HOME=/root", "SUDO_USER=dev", "LANG=fr_FR.UTF-8",
		"GODEBUG=http2client=0", "GOCOVERDIR=/tmp/cover", "SSL_CERT_FILE=/home/dev/ca.pem", "SSL_CERT_DIR=/home/dev/certs",
		"HTTPS_PROXY=http://proxy.example:3128", "https_proxy=http://proxy.example:3128", "NO_PROXY=*", "LD_PRELOAD=/tmp/x.so",
		"SANDMETER_LOG=debug", "SANDMETER_SOCKET=/tmp/other.sock", "TMPDIR=/home/dev/tmp",
	}
	got := Environ(inherited)
	want := []string{"PATH=" + SearchPath, "SANDMETER_LOG=debug"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("Environ = %q, want %q", got, want)
	}
	// What it returns is what an entry point accepts.
	if err := CheckEnviron(got); err != nil {
		t.Errorf("the environment Environ wrote is refused: %v", err)
	}
	// A log level that is not one is dropped, not passed on.
	for _, level := range []string{"", "DEBUG", "trace", "debug\nGODEBUG=x", "debug "} {
		if env := Environ([]string{"SANDMETER_LOG=" + level}); len(env) != 1 {
			t.Errorf("the log level %q got through: %q", level, env)
		}
	}
	if env := Environ(nil); len(env) != 1 || env[0] != "PATH="+SearchPath {
		t.Errorf("Environ(nil) = %q", env)
	}
	// An entry point reduces its own environment to the same thing: the
	// function is a fixed point.
	if again := Environ(got); strings.Join(again, "\n") != strings.Join(got, "\n") {
		t.Errorf("Environ of its own result = %q", again)
	}
	for _, dir := range strings.Split(SearchPath, ":") {
		if !filepath.IsAbs(dir) || strings.HasPrefix(dir, "/home") || strings.HasPrefix(dir, "/tmp") || dir == "." {
			t.Errorf("the search path holds %q", dir)
		}
	}
	if envLog != layout.EnvLog {
		t.Errorf("the log level is passed as %s and read as %s", envLog, layout.EnvLog)
	}
}

func TestCheckEnviron(t *testing.T) {
	for _, env := range [][]string{
		nil,
		{},
		{"PATH=" + SearchPath},
		{"PATH=" + SearchPath, "SANDMETER_LOG=warn"},
		// The first process of a sandbox is given one more variable.
		{"GOMAXPROCS=1"},
		{"PATH=" + SearchPath, "GOMAXPROCS=16", "SANDMETER_LOG=error"},
	} {
		if err := CheckEnviron(env); err != nil {
			t.Errorf("%q: %v", env, err)
		}
	}
	for name, env := range map[string][]string{
		"a runtime switch":       {"GODEBUG=netdns=cgo"},
		"a certificate file":     {"PATH=" + SearchPath, "SSL_CERT_FILE=/tmp/ca.pem"},
		"a proxy":                {"HTTPS_PROXY=http://127.0.0.1:1"},
		"a coverage directory":   {"GOCOVERDIR=/tmp"},
		"another search path":    {"PATH=/home/dev/bin:/usr/bin"},
		"an empty search path":   {"PATH="},
		"an unknown log level":   {"SANDMETER_LOG=trace"},
		"threads: zero":          {"GOMAXPROCS=0"},
		"threads: not a number":  {"GOMAXPROCS=1,cpu"},
		"threads: a huge number": {"GOMAXPROCS=100000"},
		"a home directory":       {"HOME=/root"},
		"no name":                {"=value"},
		"no equals sign":         {"GODEBUG"},
		"an empty entry":         {""},
	} {
		if err := CheckEnviron(env); err == nil {
			t.Errorf("%s: %q was accepted", name, env)
		}
	}
	// The error names what is there and never what it holds.
	err := CheckEnviron([]string{"TOKEN=s3cret-value", "AWS_SECRET_ACCESS_KEY=abcd", "TOKEN=again"})
	if err == nil || !strings.Contains(err.Error(), "AWS_SECRET_ACCESS_KEY, TOKEN") || strings.Contains(err.Error(), "s3cret") || strings.Contains(err.Error(), "abcd") {
		t.Errorf("CheckEnviron = %v", err)
	}
	// A long list is cut, with a count.
	var many []string
	for c := 'A'; c <= 'Z'; c++ {
		many = append(many, "VAR_"+string(c)+"=1")
	}
	if err := CheckEnviron(many); err == nil || !strings.Contains(err.Error(), "and 18 more") || len(err.Error()) > 200 {
		t.Errorf("CheckEnviron of 26 variables = %v", err)
	}
}

// TestAcceptRefusesAnInheritedEnvironment: an entry point that was started
// with the environment of its parent, instead of the one written for it,
// does not run. The greeting is perfect; the variable is the reason.
func TestAcceptRefusesAnInheritedEnvironment(t *testing.T) {
	cases := [][]string{
		{"PATH=" + SearchPath, "GODEBUG=x509roots=0"},
		{"HTTPS_PROXY=http://proxy.example:3128"},
	}
	// The environment of this test process, which is what a child gets when
	// its parent sets none: a shell's, with a home directory at the least.
	if CheckEnviron(os.Environ()) != nil {
		cases = append(cases, os.Environ())
	}
	for _, env := range cases {
		r, w := pipe(t)
		if err := Offer(w, Worker); err != nil {
			t.Fatal(err)
		}
		fd := handOver(t, r)
		f, err := accept(fd, Worker, short, env)
		if f != nil || !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "environment") {
			t.Errorf("with %d variables: accept = %v, %v; want a refusal for the environment", len(env), f, err)
		}
		// Nothing was read: the refusal comes before the greeting.
		unix.Close(int(fd))
		w.Close()
		rest, _ := io.ReadAll(r)
		if !bytes.Equal(rest, greeting(Worker)) {
			t.Errorf("a refused entry point read %d bytes of its channel", len(greeting(Worker))-len(rest))
		}
	}
}
