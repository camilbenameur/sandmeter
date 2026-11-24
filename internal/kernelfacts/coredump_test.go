//go:build integration && linux

package kernelfacts

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Piped core handlers.
//
// When kernel.core_pattern starts with a pipe, the kernel runs that program
// as root in the initial namespaces for every crash, sandboxed or not, and
// feeds it the memory of the crashed process. RLIMIT_CORE does not apply to
// a piped dump, with one exception in the kernel source: a soft limit of
// exactly 1 aborts the dump. The init sets that limit, and the filter keeps
// the workload from changing it.
//
// This test replaces kernel.core_pattern for a moment, which is why it only
// runs on a machine marked as throwaway.

const (
	corePipeLimit = "/proc/sys/kernel/core_pipe_limit"
	// The kernel keeps at most this many bytes of a pattern (core(5)).
	corePatternMax = 127
)

// childCrash sets RLIMIT_CORE and dies of SIGABRT with the default
// action, which makes the kernel consult core_pattern. args: the limit, a
// number of bytes or "unlimited".
func childCrash(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: crash LIMIT")
	}
	lim := unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}
	if args[0] != "unlimited" {
		n, err := strconv.ParseUint(args[0], 10, 64)
		if err != nil {
			return err
		}
		lim = unix.Rlimit{Cur: n, Max: n}
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &lim); err != nil {
		return fmt.Errorf("setrlimit(RLIMIT_CORE, %s): %w", args[0], err)
	}
	// With the "crash" level the runtime ends a panic by raising SIGABRT
	// with the default action instead of exiting with status 2.
	debug.SetTraceback("crash")
	panic("kernelfacts: deliberate crash, to make the kernel consult core_pattern")
}

// kernelLog reads the kernel's log buffer.
func kernelLog() (string, error) {
	size, err := unix.Klogctl(unix.SYSLOG_ACTION_SIZE_BUFFER, nil)
	if err != nil {
		return "", err
	}
	buf := make([]byte, size)
	n, err := unix.Klogctl(unix.SYSLOG_ACTION_READ_ALL, buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

// newLines returns the lines of after that are not in before and contain
// the word.
func newLines(before, after, word string) []string {
	seen := map[string]bool{}
	for _, l := range strings.Split(before, "\n") {
		seen[l] = true
	}
	var out []string
	for _, l := range strings.Split(after, "\n") {
		if !seen[l] && strings.Contains(l, word) {
			out = append(out, l)
		}
	}
	return out
}

// crashOutcome is one crash and what followed.
type crashOutcome struct {
	limit   string
	pid     int
	state   string // how the process ended
	aborted bool   // it died of SIGABRT
	handler bool   // the handler ran for it
}

func (c crashOutcome) String() string {
	return fmt.Sprintf("RLIMIT_CORE=%s: pid %d ended with %q, handler ran: %v", c.limit, c.pid, c.state, c.handler)
}

func TestPipedCoreHandler(t *testing.T) {
	r := declare(t, "core-limit-one", "core-kernel-log")
	r.needRoot()
	r.needThrowaway("this test replaces kernel.core_pattern for a moment")

	dir := scratch(t, "core")
	script, marker := filepath.Join(dir, "h"), filepath.Join(dir, "ran")
	// The kernel runs the handler as root, in the initial namespaces, with
	// the dump on its standard input. This one only notes that it ran:
	// %P is the pid of the crashed process in the initial namespace, %s the
	// signal. scratch paths are plain, so the quotes are safe.
	body := "#!/bin/sh\necho \"$1 $2\" >> '" + marker + "'\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatalf("write the handler: %v", err)
	}
	if err := os.Chmod(script, 0o755); err != nil {
		t.Fatalf("chmod the handler: %v", err)
	}
	pattern := "|" + script + " %P %s"
	if len(pattern) > corePatternMax {
		r.skipRest("the pattern %q is longer than the %d bytes the kernel keeps; choose a shorter %s", pattern, corePatternMax, scratchEnv)
		return
	}

	old, err := readTrim(corePattern)
	if err != nil {
		r.skipRest("kernel.core_pattern is not readable: %v", err)
		return
	}
	// Registered before the write: whatever happens next, the host gets its
	// pattern back, and the test says so loudly when it could not.
	t.Cleanup(func() {
		err := os.WriteFile(corePattern, []byte(old+"\n"), 0o644)
		if now := readOr(corePattern); err != nil || now != old {
			t.Errorf("kernel.core_pattern was NOT restored: it was %q, it is %q (write: %v). Restore it by hand.", old, now, err)
		}
	})
	if err := os.WriteFile(corePattern, []byte(pattern+"\n"), 0o644); err != nil {
		r.no("core-limit-one", "the handler could not be installed: write to kernel.core_pattern: %v", err)
		return
	}
	if now := readOr(corePattern); now != pattern {
		r.no("core-limit-one", "kernel.core_pattern reads %q after %q was written", now, pattern)
		return
	}

	// ranFor waits for the handler's note about a pid.
	ranFor := func(pid int, wait time.Duration) bool {
		return poll(wait, func() bool {
			b, _ := os.ReadFile(marker)
			return strings.Contains("\n"+string(b), fmt.Sprintf("\n%d ", pid))
		})
	}
	// The kernel starts the handler before the crashed process is reaped,
	// so a handler that is going to run has been started when wait returns.
	// The waits below are for its one line of shell.
	crash := func(limit string, wait time.Duration) crashOutcome {
		out := crashOutcome{limit: limit, state: "not started"}
		c, err := spawnChild(t, spawn{name: "crash", args: []string{limit}})
		if err != nil {
			out.state = err.Error()
			return out
		}
		_ = c.wait(30 * time.Second) // it dies of a signal: the error is expected
		out.pid = c.pid()
		out.state = c.cmd.ProcessState.String()
		out.aborted = c.diedOf(syscall.SIGABRT)
		out.handler = ranFor(out.pid, wait)
		return out
	}

	zero := crash("0", 5*time.Second)
	logBefore, logErr := kernelLog()
	one := crash("1", 1500*time.Millisecond)
	logAfter, logErr2 := kernelLog()
	unlimited := crash("unlimited", 5*time.Second)

	allAborted := zero.aborted && one.aborted && unlimited.aborted
	r.judge("core-limit-one", allAborted && zero.handler && unlimited.handler && !one.handler,
		"handler installed as %q (core_pipe_limit %s); %v; %v; %v (expected: each dies of SIGABRT, the handler runs for 0 and unlimited and not for 1)",
		pattern, readOr(corePipeLimit), zero, one, unlimited)

	if err := errors.Join(logErr, logErr2); err != nil {
		r.skip("core-kernel-log", "the kernel log is not readable: %v", err)
		return
	}
	lines := newLines(logBefore, logAfter, "RLIMIT_CORE")
	r.judge("core-kernel-log", len(lines) > 0,
		"%d new kernel log lines mention RLIMIT_CORE after the crash under RLIMIT_CORE=1: %s", len(lines), strings.Join(lines, " / "))
}

// The crasher must die of SIGABRT with the default action, or the test
// above measures nothing. With RLIMIT_CORE=1 the kernel writes no core file,
// and where core-limit-one holds it starts no handler either, so this is
// checked on any host.
func TestSelfCrasher(t *testing.T) {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &lim); err != nil {
		t.Fatal(err)
	}
	if lim.Max < 1 && os.Geteuid() != 0 {
		t.Skip("the hard RLIMIT_CORE of this process is 0: the helper cannot set it to 1")
	}
	c, err := spawnChild(t, spawn{name: "crash", args: []string{"1"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.wait(30 * time.Second)
	if !c.diedOf(syscall.SIGABRT) {
		t.Errorf("the crasher ended with %q, want death by SIGABRT; its stderr: %s", c.cmd.ProcessState, c.stderr())
	}
}
