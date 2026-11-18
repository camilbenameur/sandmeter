package main

import (
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestBuildsStatic checks that rfprobe builds with CGO_ENABLED=0, as
// required to copy a single static binary into the sandbox rootfs.
func TestBuildsStatic(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "rfprobe")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Env = append(cmd.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build CGO_ENABLED=0: %v\n%s", err, out)
	}

	out, err := exec.Command("file", bin).Output()
	if err != nil {
		t.Skip("no `file` binary to check static linkage")
	}
	if strings.Contains(string(out), "dynamically linked") {
		t.Errorf("rfprobe is dynamically linked: %s", out)
	}
}

func TestTrimNL(t *testing.T) {
	tests := []struct{ in, want string }{
		{"reachable\n", "reachable"},
		{"reachable\r\n", "reachable"},
		{"reachable", "reachable"},
		{"", ""},
		{"a\n\n", "a"},
	}
	for _, tt := range tests {
		if got := trimNL([]byte(tt.in)); got != tt.want {
			t.Errorf("trimNL(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestEffectiveCaps(t *testing.T) {
	status := "Name:\trfprobe\nCapEff:\t0000000000000000\nState:\tR\n"
	path := writeTempFile(t, status)

	caps, err := effectiveCaps(path)
	if err != nil {
		t.Fatalf("effectiveCaps: %v", err)
	}
	if caps != "0000000000000000" {
		t.Errorf("effectiveCaps = %q, want %q", caps, "0000000000000000")
	}
}

func TestEffectiveCapsMissingLine(t *testing.T) {
	path := writeTempFile(t, "Name:\trfprobe\nState:\tR\n")
	if _, err := effectiveCaps(path); err == nil {
		t.Error("effectiveCaps: want an error when CapEff is absent")
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "status")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestFormatCheckResult(t *testing.T) {
	// A real child that prints "blocked EPERM" and exits 1, as
	// runSyscallCheck does for a refused syscall.
	fail := exec.Command("sh", "-c", "echo 'blocked EPERM'; exit 1")
	out, err := fail.Output()
	if got, want := formatCheckResult("bpf", out, err), "bpf blocked EPERM"; got != want {
		t.Errorf("blocked line = %q, want %q", got, want)
	}

	ok := exec.Command("sh", "-c", "echo reachable")
	out, err = ok.Output()
	if got, want := formatCheckResult("bpf", out, err), "bpf reachable"; got != want {
		t.Errorf("reachable line = %q, want %q", got, want)
	}

	silent := exec.Command("sh", "-c", "exit 1")
	out, err = silent.Output()
	if got := formatCheckResult("bpf", out, err); !strings.HasPrefix(got, "bpf blocked exit:1") {
		t.Errorf("silent failure line = %q", got)
	}
}

func TestBlockedLine(t *testing.T) {
	if got := blockedLine(unix.EPERM); got != "blocked EPERM" {
		t.Errorf("blockedLine(EPERM) = %q", got)
	}
}

func TestKeyctlReachable(t *testing.T) {
	if !keyctlReachable(unix.ENOKEY) {
		t.Error("ENOKEY comes from the keyctl handler and must count as reachable")
	}
	for _, e := range []unix.Errno{unix.EPERM, unix.ENOSYS, unix.EACCES} {
		if keyctlReachable(e) {
			t.Errorf("%v must count as blocked", e)
		}
	}
}

func TestICMPChecksum(t *testing.T) {
	// A packet with its checksum filled in sums to zero.
	p := icmpEcho(7)
	if icmpChecksum(p) != 0 {
		t.Errorf("echo packet % x does not verify", p)
	}
}

func TestDNSQueryShape(t *testing.T) {
	q := dnsQuery()
	if len(q) != 12+1+7+1+3+1+4 {
		t.Errorf("query length = %d", len(q))
	}
	if q[2]&0x01 == 0 {
		t.Error("recursion-desired bit not set")
	}
}

// TestUnshareNewuserAgrees runs the built binary (the check re-execs
// itself, so it cannot run inside the test binary) and compares its answer
// with the host's own: if the shell's unshare can make a user namespace,
// so must rfprobe.
func TestUnshareNewuserAgrees(t *testing.T) {
	if exec.Command("unshare", "-U", "true").Run() != nil {
		t.Skip("host does not allow unprivileged user namespaces")
	}
	bin := filepath.Join(t.TempDir(), "rfprobe")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Env = append(build.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	out, err := exec.Command(bin, "syscalls").Output()
	if err != nil {
		t.Fatalf("rfprobe syscalls: %v", err)
	}
	if !strings.Contains(string(out), "unshare_newuser reachable") {
		t.Errorf("unshare_newuser not reachable on a host that allows it:\n%s", out)
	}
	if strings.Contains(string(out), "stderr:") {
		t.Errorf("a blocked line lost its errno:\n%s", out)
	}
}
