//go:build integration

package cgroup

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/camilbenameur/sandmeter/sandbox"
)

// testParent creates a throwaway parent under the cgroup v2 root and removes
// it at the end. The tests need root and a unified cgroup hierarchy.
func testParent(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		t.Skipf("cgroup v2 not mounted at /sys/fs/cgroup: %v", err)
	}
	parent := fmt.Sprintf("/sys/fs/cgroup/sandmeter-test-%d", os.Getpid())
	// Registered first: EnsureParent may create the directory and still fail.
	t.Cleanup(func() {
		// The groups are removed by their own tests; this only drops the parent.
		if err := unix.Rmdir(parent); err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Logf("remove parent: %v", err)
		}
	})
	if err := EnsureParent(parent); err != nil {
		t.Skipf("cannot prepare cgroup parent: %v", err)
	}
	return parent
}

// startIn starts cmd directly inside g with CLONE_INTO_CGROUP.
func startIn(t *testing.T, g *Group, cmd *exec.Cmd) {
	t.Helper()
	f, err := g.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(f.Fd())}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start in cgroup: %v", err)
	}
}

func newTestGroup(t *testing.T, parent, name string, l sandbox.Limits) *Group {
	t.Helper()
	g, err := New(parent, name, l)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := g.Remove(ctx); err != nil {
			t.Errorf("cleanup remove: %v", err)
		}
	})
	return g
}

func TestIntegrationLifecycle(t *testing.T) {
	parent := testParent(t)
	g := newTestGroup(t, parent, "life", sandbox.Limits{CPU: 0.5, MemoryBytes: 64 << 20, PIDs: 32})

	if got := mustRead(t, g.Path, "cpu.max"); strings.TrimSpace(got) != "50000 100000" {
		t.Errorf("cpu.max = %q", got)
	}
	if got := mustRead(t, g.Path, "pids.max"); strings.TrimSpace(got) != "32" {
		t.Errorf("pids.max = %q", got)
	}

	cmd := exec.Command("sleep", "30")
	startIn(t, g, cmd)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	procs := strings.Fields(mustRead(t, g.Path, "cgroup.procs"))
	if len(procs) != 1 || procs[0] != strconv.Itoa(cmd.Process.Pid) {
		t.Errorf("cgroup.procs = %v, want [%d]", procs, cmd.Process.Pid)
	}
	st, err := g.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.OOMKills != 0 || st.PIDsMaxHits != 0 {
		t.Errorf("fresh group has events: %+v", st)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := g.Kill(ctx); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, g.Path, "cgroup.procs"); strings.TrimSpace(got) != "" {
		t.Errorf("processes left after Kill: %q", got)
	}
	select {
	case err := <-done:
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Errorf("Wait = %v, want ExitError from SIGKILL", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("sleep did not exit after Kill")
	}

	if err := g.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(g.Path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("group directory still there: %v", err)
	}
	// Remove twice must be fine: Stop is documented as idempotent.
	if err := g.Remove(ctx); err != nil {
		t.Errorf("second Remove: %v", err)
	}
}

func TestIntegrationNewFailsIfExists(t *testing.T) {
	parent := testParent(t)
	newTestGroup(t, parent, "dup", sandbox.Limits{})
	if _, err := New(parent, "dup", sandbox.Limits{}); !errors.Is(err, fs.ErrExist) {
		t.Errorf("err = %v, want ErrExist", err)
	}
}

func TestIntegrationOOM(t *testing.T) {
	parent := testParent(t)
	g := newTestGroup(t, parent, "oom", sandbox.Limits{MemoryBytes: 32 << 20, PIDs: 16})

	// The shell doubles a string until the cgroup limit stops it.
	cmd := exec.Command("sh", "-c", `x=aaaaaaaaaaaaaaaa; while :; do x="$x$x"; done`)
	startIn(t, g, cmd)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("Wait = %v, want ExitError", err)
		}
		if ws, ok := ee.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
			t.Errorf("exit = %v, want death by SIGKILL from the OOM killer", ee)
		}
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		st, _ := g.Stats()
		t.Fatalf("memory hog was not stopped within 20s (stats %+v, memory.max %q, memory.swap.max %q)",
			st, mustRead(t, g.Path, "memory.max"), mustRead(t, g.Path, "memory.swap.max"))
	}

	st, err := g.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.OOMKills < 1 {
		t.Errorf("OOMKills = %d, want >= 1 (stats %+v)", st.OOMKills, st)
	}
}

func TestIntegrationPIDsMax(t *testing.T) {
	parent := testParent(t)
	g := newTestGroup(t, parent, "pids", sandbox.Limits{PIDs: 16})

	// Each background sleep needs a task; the shell keeps going when fork
	// fails, so the loop ends by itself. The sleeps are short as a second
	// bound, and the context is the hard one.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", `i=0; while [ $i -lt 100 ]; do sleep 5 & i=$((i+1)); done 2>/dev/null; wait`)
	startIn(t, g, cmd)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	// Poll instead of waiting for the shell: once the limit is hit the
	// counter is final, and the sleeps need not finish.
	deadline := time.Now().Add(10 * time.Second)
	var st sandbox.CgroupStats
	for time.Now().Before(deadline) {
		var err error
		if st, err = g.Stats(); err != nil {
			t.Fatal(err)
		}
		if st.PIDsMaxHits > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if st.PIDsMaxHits == 0 {
		t.Errorf("PIDsMaxHits = 0 after 10s, want > 0 (stats %+v)", st)
	}

	killCtx, killCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer killCancel()
	if err := g.Kill(killCtx); err != nil {
		t.Fatal(err)
	}
	<-done
}

// TestIntegrationStatsAfterWork checks the counters move for a command that ran.
func TestIntegrationStatsAfterWork(t *testing.T) {
	parent := testParent(t)
	g := newTestGroup(t, parent, "work", sandbox.Limits{})
	cmd := exec.Command("sh", "-c", "i=0; while [ $i -lt 20000 ]; do i=$((i+1)); done")
	startIn(t, g, cmd)
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	st, err := g.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.CPUUsageUsec <= 0 {
		t.Errorf("CPUUsageUsec = %d, want > 0", st.CPUUsageUsec)
	}
}
