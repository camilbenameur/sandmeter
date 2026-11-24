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
)

// short is the wait used by the tests of a missing greeting.
const short = 50 * time.Millisecond

func pipe(t *testing.T) (r, w *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close(); w.Close() })
	return r, w
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
	f, err := Accept(r.Fd(), Egress)
	if err != nil {
		t.Fatal(err)
	}
	// Accept consumed the greeting and not one byte more.
	rest, err := io.ReadAll(f)
	if err != nil || string(rest) != "what follows belongs to the entry point" {
		t.Errorf("after the handshake the channel holds %q, %v", rest, err)
	}
	flags, err := unix.FcntlInt(r.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Errorf("the control descriptor is not close-on-exec: %#x, %v", flags, err)
	}
}

func TestHandshakeOverASocketInPieces(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	child, parent := os.NewFile(uintptr(fds[0]), "child"), os.NewFile(uintptr(fds[1]), "parent")
	defer child.Close()
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
	if _, err := Accept(child.Fd(), Worker); err != nil {
		t.Errorf("a greeting sent byte by byte: %v", err)
	}
}

func TestAcceptRefuses(t *testing.T) {
	refused := func(name string, fd uintptr, entryName, want string) {
		t.Helper()
		f, err := accept(fd, entryName, short)
		if f != nil || !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: accept = %v, %v; want a refusal that says %q", name, f, err, want)
		}
	}

	// No greeting at all: the wait is bounded.
	r, _ := pipe(t)
	began := time.Now()
	refused("a silent parent", r.Fd(), Init, "no greeting within")
	if d := time.Since(began); d > 2*time.Second {
		t.Errorf("the wait for a greeting took %v", d)
	}

	// The greeting of another entry point.
	r, w := pipe(t)
	Offer(w, Fetch)
	refused("another entry point's greeting", r.Fd(), Init, "does not carry the greeting")

	// Something that is not a greeting.
	r, w = pipe(t)
	w.WriteString("GET / HTTP/1.1\r\n\r\n")
	refused("other bytes", r.Fd(), Init, "does not carry the greeting")

	// A greeting cut short by the end of the channel.
	r, w = pipe(t)
	w.WriteString("sandmeter-entry/1 __in")
	w.Close()
	refused("a truncated greeting", r.Fd(), Init, "closed before the greeting")

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
	refused("a regular file", file.Fd(), Init, "not a pipe or a socket")

	// A directory, and a character device.
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	refused("a directory", dir.Fd(), Init, "not a pipe or a socket")
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	refused("a device", null.Fd(), Init, "not a pipe or a socket")

	// A descriptor that is not open.
	r, w = pipe(t)
	closed := r.Fd()
	r.Close()
	w.Close()
	refused("a closed descriptor", closed, Init, "no control channel on descriptor")

	// A name that is not an entry point, whatever the channel says.
	r, w = pipe(t)
	w.WriteString("sandmeter-entry/1 __shell\n")
	refused("an unknown name", r.Fd(), "__shell", "not a hidden entry point")
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
