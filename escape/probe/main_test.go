package main

import (
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
