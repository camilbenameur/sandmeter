package seccomp

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const helperEnv = "RINGFENCE_SECCOMP_HELPER"

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "1" {
		os.Exit(helper())
	}
	os.Exit(m.Run())
}

// probe is one syscall tried before and after the filter is installed.
// distinguishes marks probes whose result differs without the filter, so
// passing proves the filter acted and not just that an unprivileged process
// was refused anyway.
type probe struct {
	name          string
	call          func() error
	distinguishes bool
}

func probes() []probe {
	pid := uintptr(os.Getpid())
	return []probe{
		// Without the filter: success. unshare(CLONE_FILES) is harmless.
		{"unshare", func() error { return unix.Unshare(unix.CLONE_FILES) }, true},
		// Without the filter: ESRCH, because the pid is not a tracee.
		{"ptrace", func() error {
			_, _, e := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_PEEKDATA, pid, 0, 0, 0, 0)
			return errnoOrNil(e)
		}, true},
		// Unprivileged mount is refused regardless, so this cannot detect a
		// missing deny entry; TestVerdicts is the real check for mount. This
		// only shows the filter does not change the errno.
		{"mount", func() error { return unix.Mount("none", "/", "tmpfs", 0, "") }, false},
		// Result without the filter depends on the keyring state: not a
		// reliable discriminator.
		{"keyctl", func() error {
			_, _, e := unix.Syscall6(unix.SYS_KEYCTL, 0 /* KEYCTL_GET_KEYRING_ID */, ^uintptr(1) /* KEY_SPEC_SESSION_KEYRING */, 0, 0, 0, 0)
			return errnoOrNil(e)
		}, false},
	}
}

func errnoOrNil(e syscall.Errno) error {
	if e == 0 {
		return nil
	}
	return e
}

func errnoOf(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	if e, ok := err.(syscall.Errno); ok {
		return e
	}
	return 255
}

// helper runs in the re-executed test binary. It prints one line per check:
// "<name> before=<errno> after=<errno>" or "ok <name>" / "FAIL <name> ...".
func helper() int {
	// The filter covers this thread only, so stay on it for everything below,
	// including the fork.
	runtime.LockOSThread()

	ps := probes()
	before := make([]syscall.Errno, len(ps))
	for i, p := range ps {
		before[i] = errnoOf(p.call())
	}

	prog, err := Default().Build()
	if err != nil {
		fmt.Println("FAIL build:", err)
		return 2
	}
	if err := Install(prog); err != nil {
		fmt.Println("FAIL install:", err)
		return 2
	}

	for i, p := range ps {
		fmt.Printf("probe %s before=%d after=%d distinguishes=%v\n", p.name, before[i], errnoOf(p.call()), p.distinguishes)
	}
	if pid := unix.Getpid(); pid != os.Getpid() {
		fmt.Println("FAIL getpid mismatch")
		return 2
	}
	fmt.Println("ok getpid")

	// fork+exec must still work: it is clone without namespace flags.
	if err := forkTrue(&syscall.SysProcAttr{}); err != nil {
		fmt.Println("FAIL fork true:", err)
		return 2
	}
	fmt.Println("ok fork")

	// A fork that asks for a new user namespace must be refused.
	err = forkTrue(&syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER})
	fmt.Printf("probe clone_newuser after=%d\n", errnoOf(err))
	return 0
}

func forkTrue(attr *syscall.SysProcAttr) error {
	pid, err := syscall.ForkExec("/bin/true", []string{"true"}, &syscall.ProcAttr{
		Files: []uintptr{0, 1, 2},
		Sys:   attr,
	})
	if err != nil {
		return err
	}
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		return err
	}
	if !ws.Exited() || ws.ExitStatus() != 0 {
		return fmt.Errorf("true exited with %v", ws)
	}
	return nil
}

func TestFilterInRealKernel(t *testing.T) {
	if _, err := os.Stat("/bin/true"); err != nil {
		t.Skip("/bin/true not available")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("helper output:\n%s", out)
	if err != nil {
		t.Fatalf("helper failed: %v", err)
	}

	eperm := fmt.Sprint(int(unix.EPERM))
	seen := map[string]bool{}
	var inconclusive []string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if f[0] == "ok" {
			seen[f[1]] = true
			continue
		}
		if f[0] != "probe" {
			continue
		}
		kv := map[string]string{}
		for _, s := range f[2:] {
			k, v, _ := strings.Cut(s, "=")
			kv[k] = v
		}
		seen[f[1]] = true
		if kv["after"] != eperm {
			t.Errorf("%s: errno after filter = %s, want EPERM (%s)", f[1], kv["after"], eperm)
		}
		// If the host already refused the call with EPERM (for example a
		// container with its own seccomp profile), the probe proves nothing.
		if kv["distinguishes"] == "true" && kv["before"] == eperm {
			inconclusive = append(inconclusive, f[1])
		}
	}
	for _, name := range []string{"unshare", "ptrace", "mount", "keyctl", "getpid", "fork", "clone_newuser"} {
		if !seen[name] {
			t.Errorf("helper did not report %s", name)
		}
	}
	// Reported as a skip, after the other assertions, so a host that already
	// refuses these calls does not look like a pass.
	if len(inconclusive) > 0 {
		t.Skipf("already EPERM before the filter, not conclusive here: %v", inconclusive)
	}
}
