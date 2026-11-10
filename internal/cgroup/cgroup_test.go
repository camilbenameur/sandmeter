package cgroup

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/camilbenameur/ringfence/sandbox"
)

// writeTree creates files under dir, standing in for what the kernel provides.
func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func mustRead(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// fakeMkdir makes the directory and the interface files a fresh cgroup has.
func fakeMkdir(skip ...string) func(string) error {
	return func(p string) error {
		if err := os.Mkdir(p, 0o755); err != nil {
			return err
		}
		for _, f := range []string{"cpu.max", "memory.max", "memory.swap.max", "memory.oom.group", "pids.max"} {
			skipped := false
			for _, s := range skip {
				skipped = skipped || s == f
			}
			if skipped {
				continue
			}
			if err := os.WriteFile(filepath.Join(p, f), nil, 0o644); err != nil {
				return err
			}
		}
		return nil
	}
}

func TestParseFlat(t *testing.T) {
	good, err := parseFlat("low 0\nhigh 0\nmax 12\noom 1\noom_kill 3\n\n")
	if err != nil {
		t.Fatal(err)
	}
	if good["oom_kill"] != 3 || good["max"] != 12 || len(good) != 5 {
		t.Errorf("parsed %v", good)
	}
	if m, err := parseFlat(""); err != nil || len(m) != 0 {
		t.Errorf("empty input: %v, %v", m, err)
	}
	for _, bad := range []string{"oom_kill\n", "oom_kill x\n", "a 1 2\n", "a 1\nb\n", "a 99999999999999999999\n"} {
		if _, err := parseFlat(bad); err == nil {
			t.Errorf("parseFlat(%q) succeeded, want error", bad)
		}
	}
}

func TestCPUMax(t *testing.T) {
	tests := []struct {
		cpu     float64
		want    string
		wantErr bool
	}{
		{0, "max 100000", false},
		{0.5, "50000 100000", false},
		{2, "200000 100000", false},
		{0.07, "7000 100000", false},
		{1.5, "150000 100000", false},
		{0.001, "", true},
	}
	for _, tc := range tests {
		got, err := cpuMax(tc.cpu)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("cpuMax(%v) = %q, %v; want %q (err %v)", tc.cpu, got, err, tc.want, tc.wantErr)
		}
	}
}

func TestNewWritesLimits(t *testing.T) {
	parent := t.TempDir()
	l := sandbox.Limits{CPU: 0.5, MemoryBytes: 256 << 20, PIDs: 64}
	g, err := newGroup(parent, "sb-1", l, fakeMkdir(), os.RemoveAll)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"cpu.max":          "50000 100000",
		"memory.max":       "268435456",
		"memory.swap.max":  "0",
		"memory.oom.group": "1",
		"pids.max":         "64",
	}
	for f, v := range want {
		if got := mustRead(t, g.Path, f); got != v {
			t.Errorf("%s = %q, want %q", f, got, v)
		}
	}
	if len(g.Notes) != 0 {
		t.Errorf("unexpected notes %v", g.Notes)
	}
}

func TestNewNoLimits(t *testing.T) {
	g, err := newGroup(t.TempDir(), "sb", sandbox.Limits{}, fakeMkdir(), os.RemoveAll)
	if err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, g.Path, "cpu.max"); got != "max 100000" {
		t.Errorf("cpu.max = %q", got)
	}
	if got := mustRead(t, g.Path, "memory.max"); got != "max" {
		t.Errorf("memory.max = %q", got)
	}
	if got := mustRead(t, g.Path, "pids.max"); got != "max" {
		t.Errorf("pids.max = %q", got)
	}
	// Swap is only capped alongside a memory limit.
	if got := mustRead(t, g.Path, "memory.swap.max"); got != "" {
		t.Errorf("memory.swap.max written without a memory limit: %q", got)
	}
}

func TestNewSwapAccountingOff(t *testing.T) {
	g, err := newGroup(t.TempDir(), "sb", sandbox.Limits{MemoryBytes: 1 << 20}, fakeMkdir("memory.swap.max"), os.RemoveAll)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Notes) != 1 || !strings.Contains(g.Notes[0], "swap") {
		t.Errorf("notes = %v, want one about swap", g.Notes)
	}
}

func TestNewCleansUpOnError(t *testing.T) {
	parent := t.TempDir()
	// No pids.max: the last write fails after the others succeeded.
	_, err := newGroup(parent, "sb", sandbox.Limits{PIDs: 8}, fakeMkdir("pids.max"), os.RemoveAll)
	if err == nil {
		t.Fatal("want error")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("error %v should wrap ErrNotExist", err)
	}
	if _, err := os.Stat(filepath.Join(parent, "sb")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("directory left behind: %v", err)
	}
}

func TestNewRejects(t *testing.T) {
	parent := t.TempDir()
	for _, name := range []string{"", ".", "..", "a/b", "a b", strings.Repeat("x", 65), "é"} {
		if _, err := newGroup(parent, name, sandbox.Limits{}, fakeMkdir(), os.RemoveAll); err == nil {
			t.Errorf("name %q accepted", name)
		}
	}
	for _, l := range []sandbox.Limits{{CPU: -1}, {MemoryBytes: -1}, {PIDs: -1}, {CPU: 0.0001}} {
		if _, err := newGroup(parent, "ok", l, fakeMkdir(), os.RemoveAll); err == nil {
			t.Errorf("limits %+v accepted", l)
		}
	}
	if _, err := newGroup(parent, "dup", sandbox.Limits{}, fakeMkdir(), os.RemoveAll); err != nil {
		t.Fatal(err)
	}
	if _, err := newGroup(parent, "dup", sandbox.Limits{}, fakeMkdir(), os.RemoveAll); !errors.Is(err, fs.ErrExist) {
		t.Errorf("duplicate: err = %v, want ErrExist", err)
	}
}

func TestStats(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"memory.peak":   "4096\n",
		"pids.peak":     "7\n",
		"memory.events": "low 0\nhigh 0\nmax 2\noom 1\noom_kill 1\noom_group_kill 1\n",
		"cpu.stat":      "usage_usec 1500\nuser_usec 1000\nsystem_usec 500\nnr_periods 0\n",
		"pids.events":   "max 5\n",
	})
	st, err := (&Group{Path: dir}).Stats()
	if err != nil {
		t.Fatal(err)
	}
	want := sandbox.CgroupStats{MemoryPeakBytes: 4096, OOMKills: 1, CPUUsageUsec: 1500, PIDsPeak: 7, PIDsMaxHits: 5}
	if st != want {
		t.Errorf("stats = %+v, want %+v", st, want)
	}
}

func TestStatsOptionalFilesMissing(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"memory.events": "oom_kill 0\n",
		"cpu.stat":      "usage_usec 10\n",
	})
	st, err := (&Group{Path: dir}).Stats()
	if err != nil {
		t.Fatal(err)
	}
	if st.MemoryPeakBytes != 0 || st.PIDsPeak != 0 || st.PIDsMaxHits != 0 || st.CPUUsageUsec != 10 {
		t.Errorf("stats = %+v", st)
	}
}

func TestStatsRequiredFilesAndMalformed(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"cpu.stat": "usage_usec 10\n"})
	if _, err := (&Group{Path: dir}).Stats(); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing memory.events: err = %v", err)
	}
	writeTree(t, dir, map[string]string{"memory.events": "oom_kill\n"})
	if _, err := (&Group{Path: dir}).Stats(); err == nil {
		t.Error("malformed memory.events accepted")
	}
	writeTree(t, dir, map[string]string{"memory.events": "oom_kill 0\n", "memory.peak": "abc\n"})
	if _, err := (&Group{Path: dir}).Stats(); err == nil {
		t.Error("malformed memory.peak accepted")
	}
}

func TestWaitUnpopulated(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"cgroup.events": "populated 0\nfrozen 0\n"})
	if err := waitUnpopulated(context.Background(), dir, time.Millisecond, false); err != nil {
		t.Errorf("already empty: %v", err)
	}

	writeTree(t, dir, map[string]string{"cgroup.events": "populated 1\nfrozen 0\n"})
	go func() {
		time.Sleep(20 * time.Millisecond)
		// Rename keeps the update atomic, like the kernel's single read.
		tmp := filepath.Join(t.TempDir(), "ev")
		_ = os.WriteFile(tmp, []byte("populated 0\nfrozen 0\n"), 0o644)
		_ = os.Rename(tmp, filepath.Join(dir, "cgroup.events"))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := waitUnpopulated(ctx, dir, time.Millisecond, false); err != nil {
		t.Errorf("became empty: %v", err)
	}
}

func TestWaitUnpopulatedContext(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"cgroup.events": "populated 1\n"})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err := waitUnpopulated(ctx, dir, time.Millisecond, false)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want deadline exceeded", err)
	}
}

func TestWaitUnpopulatedBadEvents(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"cgroup.events": "frozen 0\n"})
	if err := waitUnpopulated(context.Background(), dir, time.Millisecond, false); err == nil {
		t.Error("missing populated key accepted")
	}
	writeTree(t, dir, map[string]string{"cgroup.events": "garbage\n"})
	if err := waitUnpopulated(context.Background(), dir, time.Millisecond, false); err == nil {
		t.Error("malformed events accepted")
	}
}

func TestKillWritesAndWaits(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"cgroup.kill": "", "cgroup.events": "populated 0\n"})
	if err := (&Group{Path: dir}).Kill(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, dir, "cgroup.kill"); got != "1" {
		t.Errorf("cgroup.kill = %q, want 1", got)
	}
}

func TestKillMissingGroup(t *testing.T) {
	g := &Group{Path: filepath.Join(t.TempDir(), "gone")}
	if err := g.Kill(context.Background()); err != nil {
		t.Errorf("Kill on removed group: %v", err)
	}
}

func TestRetryRemove(t *testing.T) {
	var calls atomic.Int32
	busyTwice := func() error {
		if calls.Add(1) <= 2 {
			return unix.EBUSY
		}
		return nil
	}
	if err := retryRemove(context.Background(), busyTwice, 5, time.Millisecond); err != nil || calls.Load() != 3 {
		t.Errorf("err = %v after %d calls, want nil after 3", err, calls.Load())
	}

	calls.Store(0)
	always := func() error { calls.Add(1); return unix.EBUSY }
	if err := retryRemove(context.Background(), always, 4, time.Millisecond); !errors.Is(err, unix.EBUSY) || calls.Load() != 4 {
		t.Errorf("err = %v after %d calls, want EBUSY after 4", err, calls.Load())
	}

	calls.Store(0)
	other := func() error { calls.Add(1); return unix.EPERM }
	if err := retryRemove(context.Background(), other, 4, time.Millisecond); !errors.Is(err, unix.EPERM) || calls.Load() != 1 {
		t.Errorf("EPERM must not be retried: err = %v, calls = %d", err, calls.Load())
	}

	gone := func() error { return fs.ErrNotExist }
	if err := retryRemove(context.Background(), gone, 4, time.Millisecond); err != nil {
		t.Errorf("already removed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := retryRemove(ctx, always, 4, time.Hour); !errors.Is(err, unix.EBUSY) {
		t.Errorf("cancelled: %v", err)
	}
}

func TestRemoveUsesRmdir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "g")
	writeTree(t, dir, map[string]string{"cgroup.kill": "", "cgroup.events": "populated 0\n"})
	var removed string
	g := &Group{Path: dir, rmdir: func(p string) error { removed = p; return nil }}
	if err := g.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if removed != dir {
		t.Errorf("rmdir called on %q, want %q", removed, dir)
	}
}

func TestEnsureParent(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"cgroup.controllers":     "cpuset cpu io memory pids\n",
		"cgroup.subtree_control": "cpu\n",
	})
	path := filepath.Join(root, "ringfence")
	writeTree(t, path, map[string]string{
		"cgroup.controllers":     "cpu memory pids\n",
		"cgroup.subtree_control": "",
		"cgroup.procs":           "",
	})
	if err := EnsureParent(path); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, root, "cgroup.subtree_control"); got != "+memory +pids" {
		t.Errorf("root subtree_control write = %q", got)
	}
	if got := mustRead(t, path, "cgroup.subtree_control"); got != "+cpu +memory +pids" {
		t.Errorf("parent subtree_control write = %q", got)
	}
}

func TestEnsureParentAlreadyEnabled(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"cgroup.controllers":     "cpu memory pids\n",
		"cgroup.subtree_control": "cpu memory pids\n",
	})
	path := filepath.Join(root, "p")
	writeTree(t, path, map[string]string{
		"cgroup.controllers":     "cpu memory pids\n",
		"cgroup.subtree_control": "cpu memory pids\n",
		"cgroup.procs":           "",
	})
	if err := EnsureParent(path); err != nil {
		t.Fatal(err)
	}
	if got := mustRead(t, root, "cgroup.subtree_control"); got != "cpu memory pids\n" {
		t.Errorf("rewrote an already complete subtree_control: %q", got)
	}
}

func TestEnsureParentMissingController(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"cgroup.controllers":     "cpu memory\n",
		"cgroup.subtree_control": "",
	})
	err := EnsureParent(filepath.Join(root, "p"))
	if err == nil || !strings.Contains(err.Error(), "pids") {
		t.Errorf("err = %v, want one naming pids", err)
	}
}

func TestEnsureParentHasProcesses(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"cgroup.controllers":     "cpu memory pids\n",
		"cgroup.subtree_control": "cpu memory pids\n",
	})
	path := filepath.Join(root, "p")
	writeTree(t, path, map[string]string{"cgroup.procs": "123\n"})
	err := EnsureParent(path)
	if err == nil || !strings.Contains(err.Error(), "processes") {
		t.Errorf("err = %v, want a processes error", err)
	}
}
