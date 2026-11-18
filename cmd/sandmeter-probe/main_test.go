package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The tests here need the built binary. Those of the probe's code are with
// it, in internal/escape/probe.

// TestBuildsStatic checks that sandmeter-probe builds with CGO_ENABLED=0, as
// required to copy a single static binary into the sandbox rootfs.
func TestBuildsStatic(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "sandmeter-probe")
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
		t.Errorf("sandmeter-probe is dynamically linked: %s", out)
	}
}

// TestUnshareNewuserAgrees runs the built binary (the check re-execs
// itself, so it cannot run inside the test binary) and compares its answer
// with the host's own: if the shell's unshare can make a user namespace,
// so must sandmeter-probe.
func TestUnshareNewuserAgrees(t *testing.T) {
	if exec.Command("unshare", "-U", "true").Run() != nil {
		t.Skip("host does not allow unprivileged user namespaces")
	}
	bin := filepath.Join(t.TempDir(), "sandmeter-probe")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Env = append(build.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	// The run is bounded. A check of the batch that got stuck would otherwise
	// hold this test until the timeout of the whole suite, and leave its
	// processes on the host after that. Killing the probe lets go of a child
	// it was waiting for.
	const limit = 30 * time.Second
	ctx, cancel := context.WithTimeout(t.Context(), limit)
	defer cancel()
	run := exec.CommandContext(ctx, bin, "syscalls")
	run.WaitDelay = 5 * time.Second
	out, err := run.Output()
	if ctx.Err() != nil {
		t.Fatalf("sandmeter-probe syscalls was still running after %s and was killed. Its output until then:\n%s", limit, out)
	}
	if err != nil {
		t.Fatalf("sandmeter-probe syscalls: %v", err)
	}
	if !strings.Contains(string(out), "unshare_newuser reachable") {
		t.Errorf("unshare_newuser not reachable on a host that allows it:\n%s", out)
	}
	if strings.Contains(string(out), "stderr:") {
		t.Errorf("a blocked line lost its errno:\n%s", out)
	}
}
