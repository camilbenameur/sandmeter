// Package entry holds what every hidden entry point of the root side shares:
// the names that select them, and the handshake each one must complete on
// its control descriptor before it does anything.
//
// A hidden entry point is a way into the sandmeterd binary that is not a
// command: the first process of a sandbox, the worker of a connection, the
// egress proxy, the image fetcher. Each is started by sandmeter itself, with
// descriptors and privileges prepared for that one job. The binary has to be
// executable by everybody (the first process of a sandbox runs it under the
// sandbox's ids), so anybody can type such a name on a command line. They
// gain nothing by it: the package installs no setuid bit and no file
// capability.
//
// The handshake is what keeps an entry point from running anywhere but under
// its parent. The parent writes one fixed line, the greeting, on the control
// channel it gives the child; the child refuses to go on unless its control
// descriptor is a pipe or a socket and the greeting for its own name arrives
// on it promptly. Typed by hand, started by a script, or given a file or a
// terminal as descriptor, an entry point exits at once with a message that
// says what it is.
//
// What the handshake does not do, and must not be taken for: it does not
// authenticate anybody. Whoever starts the binary chooses its descriptors
// and can write the greeting. In particular it is no protection for a host
// where a user was granted sudo on the bare binary: that grant is root, with
// or without a greeting.
//
// # Environment
//
// An entry point is started with an environment that sandmeter wrote out,
// never with the one its parent happened to have: the variables of a root
// shell, of "sudo -E" or of a unit's drop-in (a proxy, a certificate file, a
// debugging switch of the Go runtime) must not reach a worker, and from it
// the proxy and the fetcher. Environ is that environment and the one place
// that lists what it may hold. A parent sets it, whole, on every child it
// starts. The handshake checks it on the other side: an entry point that
// finds anything else in its environment refuses to run, so a parent that
// forgot is found by its first test and not by an operator.
//
// This package is a leaf, on purpose: the packages that own an entry point
// import it for the handshake, and the table of entry points (package
// hidden) imports those packages.
package entry

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/camilbenameur/sandmeter/internal/exit"
)

// The names of the hidden entry points: the first command-line argument that
// selects each one. They start with two underscores so that none can be
// taken for a command or a flag.
const (
	// Worker serves one connection of one client, as root, and at most one
	// session. The service starts one per accepted connection; root starts
	// one itself in direct mode.
	Worker = "__worker"
	// Init is the first stage of the native backend inside a new sandbox:
	// process 1 of its pid namespace for the life of a command.
	Init = "__init"
	// Exec is the second stage: it drops what is left of the privileges,
	// installs the syscall filter and executes the command.
	Exec = "__exec"
	// Egress is the egress proxy of one command. It runs without privilege,
	// under an id of its own.
	Egress = "__egress"
	// Fetch pulls an image from a registry. It runs without privilege, under
	// an id of its own, and refuses to run as root.
	Fetch = "__fetch"
)

// Names is the closed list of names.
var Names = []string{Worker, Init, Exec, Egress, Fetch}

// ControlFD is the descriptor on which an entry point finds its control
// channel unless its owner documents another: the first one after the three
// standard streams.
const ControlFD = 3

// Timeout is how long an entry point waits for its greeting. A parent writes
// it before or right after it starts the child, so the wait is short when
// everything is as it should be and bounded when nothing is.
const Timeout = 5 * time.Second

// protocol names the handshake itself. It changes if the greeting ever does.
const protocol = "sandmeter-entry/1"

// greeting returns the line a parent writes for the named entry point.
func greeting(name string) []byte { return []byte(protocol + " " + name + "\n") }

// ErrRefused is the error of Accept, wrapped with the reason.
var ErrRefused = errors.New("refused to run")

// SearchPath is the PATH of every entry point and of every process one
// starts: the directories of the system's own programs, in a fixed order.
// The directories under /usr/local are left out on purpose: on some
// distributions a group other than root can write to them. No entry point
// finds a program through PATH (each is started by an absolute path); the
// variable is there so that code which consults it anyway finds nothing
// surprising.
const SearchPath = "/usr/sbin:/usr/bin:/sbin:/bin"

// The variables an entry point may hold.
const (
	envPath = "PATH"
	// envLog is the log level (layout.EnvLog).
	envLog = "SANDMETER_LOG"
	// envThreads bounds the threads of the Go runtime. The first process of
	// a sandbox is given GOMAXPROCS=1, so that it stays within the few tasks
	// reserved for it.
	envThreads = "GOMAXPROCS"
)

// allowed reports whether an entry point may hold the variable name with
// this value. The list is closed: PATH with the fixed search path, the log
// level with one of its four values, and GOMAXPROCS with a small number.
func allowed(name, value string) bool {
	switch name {
	case envPath:
		return value == SearchPath
	case envLog:
		return value == "debug" || value == "info" || value == "warn" || value == "error"
	case envThreads:
		if len(value) == 0 || len(value) > 3 || value[0] == '0' {
			return false
		}
		for i := 0; i < len(value); i++ {
			if value[i] < '0' || value[i] > '9' {
				return false
			}
		}
		return true
	}
	return false
}

// Environ returns the whole environment of a hidden entry point: what a
// parent sets on the entry point it starts, and what an entry point sets on
// the children it starts in turn. It holds the fixed search path and, when
// from holds a valid one, the log level. Nothing else of from gets through.
//
// from is where the log level is taken from: os.Environ() in a process a
// person started, and in an entry point its own environment, which already
// went through here. A caller may append GOMAXPROCS and nothing else.
//
// Invariant: every process the root side starts for itself gets exactly
// this, set explicitly. An exec.Cmd whose Env is nil inherits the whole
// environment of its parent, which is how a variable of a root shell would
// reach the process that talks to a registry.
func Environ(from []string) []string {
	env := []string{envPath + "=" + SearchPath}
	for _, kv := range from {
		if name, value, ok := strings.Cut(kv, "="); ok && name == envLog && allowed(name, value) {
			env = append(env, kv)
			break
		}
	}
	return env
}

// CheckEnviron reports whether env is an environment an entry point may run
// with: nothing but the variables Environ sets, and GOMAXPROCS. The error
// names the variables that are not, and never their values.
func CheckEnviron(env []string) error {
	var bad []string
	seen := map[string]bool{}
	for _, kv := range env {
		name, value, _ := strings.Cut(kv, "=")
		if !allowed(name, value) && !seen[name] {
			seen[name] = true
			bad = append(bad, name)
		}
	}
	if len(bad) == 0 {
		return nil
	}
	sort.Strings(bad)
	const show = 8
	list := strings.Join(bad[:min(len(bad), show)], ", ")
	if len(bad) > show {
		list += fmt.Sprintf(" and %d more", len(bad)-show)
	}
	return fmt.Errorf("the environment holds what an entry point is never given (%s)", list)
}

// CheckChannel reports whether descriptor fd is open and is a pipe or a
// socket, which is what sandmeter hands a child as its control channel. A
// regular file, a directory, a terminal or a device is what a person or a
// script would put there.
func CheckChannel(fd uintptr) error {
	var st unix.Stat_t
	if err := unix.Fstat(int(fd), &st); err != nil {
		return fmt.Errorf("no control channel on descriptor %d (%v)", fd, err)
	}
	if kind := st.Mode & unix.S_IFMT; kind != unix.S_IFIFO && kind != unix.S_IFSOCK {
		return fmt.Errorf("descriptor %d is not a pipe or a socket", fd)
	}
	return nil
}

// Offer is the parent's half of the handshake: it writes the greeting for
// the named entry point on the control channel it hands to the child. The
// write does not wait for the child; on a pipe or a socket it may be done
// before the child is started.
func Offer(w io.Writer, name string) error {
	if !known(name) {
		return fmt.Errorf("offer a handshake to %q: not a hidden entry point", name)
	}
	if _, err := w.Write(greeting(name)); err != nil {
		return fmt.Errorf("offer the handshake to %s: %w", name, err)
	}
	return nil
}

func known(name string) bool {
	for _, n := range Names {
		if n == name {
			return true
		}
	}
	return false
}

// Accept is the child's half of the handshake, and the first thing an entry
// point does. It checks that descriptor fd is open and is a pipe or a
// socket, marks it close-on-exec, checks that the environment of the process
// is one an entry point is given (CheckEnviron), waits up to Timeout for the
// greeting of the named entry point and returns the descriptor as a file,
// positioned right after the greeting, for the rest of the conversation.
//
// Any other outcome is ErrRefused and the entry point must exit without
// having done anything: see MustAccept.
//
// The file returned owns the descriptor: closing it, or letting it be
// collected, closes descriptor fd.
func Accept(fd uintptr, name string) (*os.File, error) {
	return accept(fd, name, Timeout, os.Environ())
}

func accept(fd uintptr, name string, timeout time.Duration, env []string) (*os.File, error) {
	refuse := func(format string, args ...any) (*os.File, error) {
		return nil, fmt.Errorf("%s: %w: %s", name, ErrRefused, fmt.Sprintf(format, args...))
	}
	if !known(name) {
		return refuse("not a hidden entry point")
	}
	// Invariant: the control channel is a pipe or a socket. A regular file,
	// a directory, a terminal or a device is what a person or a script would
	// put there, never what sandmeter does.
	if err := CheckChannel(fd); err != nil {
		return refuse("%v", err)
	}
	unix.CloseOnExec(int(fd))
	// Invariant: an entry point runs with the environment sandmeter wrote
	// for it and no other. This is checked, not repaired: the Go runtime has
	// read its own variables before this line, so an environment that holds
	// one cannot be made safe after the fact.
	if err := CheckEnviron(env); err != nil {
		return refuse("%v", err)
	}

	want := greeting(name)
	got := make([]byte, 0, len(want))
	deadline := time.Now().Add(timeout)
	for len(got) < len(want) {
		left := time.Until(deadline)
		if left <= 0 {
			return refuse("no greeting within %v", timeout)
		}
		pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(pfd, int(left.Milliseconds())+1)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return refuse("waiting for the greeting: %v", err)
		}
		if n == 0 {
			continue
		}
		// Read no further than the greeting: what follows it belongs to the
		// owner of the entry point.
		buf := make([]byte, len(want)-len(got))
		m, err := unix.Read(int(fd), buf)
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		if err != nil {
			return refuse("reading the greeting: %v", err)
		}
		if m == 0 {
			return refuse("the control channel closed before the greeting")
		}
		got = append(got, buf[:m]...)
		if string(got) != string(want[:len(got)]) {
			return refuse("the control channel does not carry the greeting of this entry point")
		}
	}
	return os.NewFile(fd, "control"), nil
}

// MustAccept is Accept for an entry point's first line: when the handshake
// is refused it writes one message to standard error, saying what the
// program is and why it will not run, and exits with exit.Failure. It
// returns only with the control channel.
func MustAccept(fd uintptr, name string) *os.File {
	f, err := Accept(fd, name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sandmeter: %v\n%s is an internal entry point: sandmeter starts it itself, and it does nothing when it is started any other way.\n", err, name)
		os.Exit(exit.Failure)
	}
	return f
}

// NotBuilt ends an entry point whose body is not written yet: one message
// to standard error and exit.Failure. An entry point calls it after the
// handshake, so that even an unfinished one refuses to run by hand.
func NotBuilt(name string) {
	fmt.Fprintf(os.Stderr, "sandmeter: the entry point %s is not built in this version\n", name)
	os.Exit(exit.Failure)
}
