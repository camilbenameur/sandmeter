// Package bench measures the cost of isolation: how long a sandboxed command
// takes to start, how long snapshots take, how much slower CPU and I/O work
// runs than the same binaries without isolation, and how many sandboxes run
// at once. Every number is printed with the machine and versions it came
// from; numbers from different machines are not comparable.
package bench

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/camilbenameur/sandmeter/engine"
	"github.com/camilbenameur/sandmeter/policy"
)

// Options select how much to measure.
type Options struct {
	Image       string
	Backends    []string
	StartRuns   int // runs of "true" for start latency
	SnapRuns    int // snapshot + restore cycles
	Concurrency int // sandboxes started at once for the density test
}

// Stat summarises durations in milliseconds.
type Stat struct {
	N              int
	P50, P90, P99  float64
	Min, Max, Mean float64
}

func summarise(ds []time.Duration) Stat {
	if len(ds) == 0 {
		return Stat{}
	}
	ms := make([]float64, len(ds))
	sum := 0.0
	for i, d := range ds {
		ms[i] = float64(d.Microseconds()) / 1000
		sum += ms[i]
	}
	sort.Float64s(ms)
	q := func(p float64) float64 {
		// Nearest-rank percentile: no interpolation, every value is a real sample.
		i := int(p*float64(len(ms))+0.999999) - 1
		if i < 0 {
			i = 0
		}
		if i >= len(ms) {
			i = len(ms) - 1
		}
		return ms[i]
	}
	return Stat{N: len(ms), P50: q(0.5), P90: q(0.9), P99: q(0.99), Min: ms[0], Max: ms[len(ms)-1], Mean: sum / float64(len(ms))}
}

// BackendResult holds the measures of one backend.
type BackendResult struct {
	Backend  string
	Version  string
	Start    Stat // Exec of "true", end to end on the host side
	Snapshot Stat
	Restore  Stat
	// CPU and IO compare the sandbox with a chroot into the same image
	// layers (same binaries, no namespaces, no cgroup limits, no seccomp).
	CPUSandbox, CPUBaseline Stat
	IOSandbox, IOBaseline   Stat
	// Density: Concurrency sandboxes running "sleep" at once.
	DensityOK     int
	DensityWallMS float64
	DensityErr    string
}

// Results is a full benchmark run.
type Results struct {
	Host     string
	Kernel   string
	CPUs     int
	MemoryMB int64
	Image    string
	Digest   string
	Date     time.Time
	Backends []BackendResult
}

// Workloads, run with busybox sh from the image.
const (
	cpuWork = `i=0; while [ $i -lt 300000 ]; do i=$((i+1)); done`
	ioWork  = `dd if=/dev/zero of=/workspace/bench.bin bs=1M count=128 conv=fsync 2>/dev/null && rm /workspace/bench.bin`
)

// Run measures every backend in opts.
func Run(ctx context.Context, e *engine.Engine, opts Options, now time.Time) (Results, error) {
	res := Results{CPUs: runtime.NumCPU(), Image: opts.Image, Date: now}
	res.Host, _ = os.Hostname()
	res.Kernel = kernel()
	res.MemoryMB = memTotalMB()
	for _, name := range opts.Backends {
		br, digest, err := runBackend(ctx, e, name, opts)
		if err != nil {
			return res, fmt.Errorf("%s: %w", name, err)
		}
		res.Digest = digest
		res.Backends = append(res.Backends, br)
	}
	return res, nil
}

func benchPolicy() policy.Policy {
	p := policy.Default()
	p.Limits.Memory = "1GiB"
	p.Limits.PIDs = 512
	p.Limits.CPU = 1
	p.Limits.Wall = "120s"
	return p
}

func runBackend(ctx context.Context, e *engine.Engine, name string, opts Options) (BackendResult, string, error) {
	br := BackendResult{Backend: name}
	if v, ok := e.Backends[name].(engine.Versioner); ok {
		br.Version = v.Version()
	}
	s, err := e.Start(ctx, name, opts.Image, benchPolicy())
	if err != nil {
		return br, "", err
	}
	defer s.Stop(context.Background())
	digest := s.Image.Digest

	timeRun := func(argv ...string) (time.Duration, error) {
		o, err := s.Run(ctx, argv)
		if err != nil {
			return 0, err
		}
		if o.Result.ExitCode != 0 {
			return 0, fmt.Errorf("%v: exit %d: %s", argv, o.Result.ExitCode, o.Result.Stderr)
		}
		return o.Result.Duration, nil
	}

	// Warm up caches (page cache of the image, runsc binary) once.
	if _, err := timeRun("true"); err != nil {
		return br, digest, err
	}
	var starts []time.Duration
	for i := 0; i < opts.StartRuns; i++ {
		d, err := timeRun("true")
		if err != nil {
			return br, digest, err
		}
		starts = append(starts, d)
	}
	br.Start = summarise(starts)

	var snaps, restores []time.Duration
	if _, err := timeRun("sh", "-c", "dd if=/dev/zero of=/workspace/blob bs=1M count=64 2>/dev/null"); err != nil {
		return br, digest, err
	}
	base, err := s.Snapshot(ctx)
	if err != nil {
		return br, digest, err
	}
	for i := 0; i < opts.SnapRuns; i++ {
		if _, err := timeRun("sh", "-c", fmt.Sprintf("echo %d > /workspace/n", i)); err != nil {
			return br, digest, err
		}
		t0 := time.Now()
		if _, err := s.Snapshot(ctx); err != nil {
			// The snapshot chain is capped; stop measuring rather than fail.
			break
		}
		snaps = append(snaps, time.Since(t0))
		t0 = time.Now()
		if err := s.Restore(ctx, base); err != nil {
			return br, digest, err
		}
		restores = append(restores, time.Since(t0))
	}
	br.Snapshot, br.Restore = summarise(snaps), summarise(restores)

	// Overhead against a chroot into the same layers.
	upperRoot := mergedRoot(s)
	var cpuS, cpuB, ioS, ioB []time.Duration
	for i := 0; i < 5; i++ {
		d, err := timeRun("sh", "-c", cpuWork)
		if err != nil {
			return br, digest, err
		}
		cpuS = append(cpuS, d)
		d, err = timeRun("sh", "-c", ioWork)
		if err != nil {
			return br, digest, err
		}
		ioS = append(ioS, d)
		if upperRoot != "" {
			if d, err := chrootRun(ctx, upperRoot, cpuWork); err == nil {
				cpuB = append(cpuB, d)
			}
			if d, err := chrootRun(ctx, upperRoot, ioWork); err == nil {
				ioB = append(ioB, d)
			}
		}
	}
	br.CPUSandbox, br.CPUBaseline = summarise(cpuS), summarise(cpuB)
	br.IOSandbox, br.IOBaseline = summarise(ioS), summarise(ioB)

	// Density.
	n := opts.Concurrency
	if n > 0 {
		var wg sync.WaitGroup
		var mu sync.Mutex
		ok := 0
		var firstErr error
		t0 := time.Now()
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ds, err := e.Start(ctx, name, opts.Image, benchPolicy())
				if err == nil {
					defer ds.Stop(context.Background())
					var o engine.Output
					o, err = ds.Run(ctx, []string{"sleep", "2"})
					if err == nil && o.Result.ExitCode != 0 {
						err = fmt.Errorf("exit %d", o.Result.ExitCode)
					}
				}
				mu.Lock()
				defer mu.Unlock()
				if err == nil {
					ok++
				} else if firstErr == nil {
					firstErr = err
				}
			}()
		}
		wg.Wait()
		br.DensityOK = ok
		br.DensityWallMS = float64(time.Since(t0).Milliseconds())
		if firstErr != nil {
			br.DensityErr = firstErr.Error()
		}
	}
	return br, digest, nil
}

// mergedRoot returns the mounted overlay of a session, for the baseline.
func mergedRoot(s *engine.Session) string {
	if m, ok := s.Sandbox().(interface{ Merged() string }); ok {
		return m.Merged()
	}
	return ""
}

// chrootRun runs a workload with the image's busybox in a plain chroot.
func chrootRun(ctx context.Context, root, script string) (time.Duration, error) {
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script)
	cmd.Path = "/bin/sh"
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: root}
	t0 := time.Now()
	if out, err := cmd.CombinedOutput(); err != nil {
		return 0, fmt.Errorf("chroot baseline: %w: %s", err, out)
	}
	return time.Since(t0), nil
}

func kernel() string {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return "unknown"
	}
	b := make([]byte, 0, len(u.Release))
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

func memTotalMB() int64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	var kb int64
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fmt.Sscanf(strings.TrimPrefix(line, "MemTotal:"), "%d", &kb)
		}
	}
	return kb / 1024
}

// Markdown renders the results as tables.
func (r Results) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Machine: %d vCPU, %d MB RAM, kernel %s. Image %s (%s). %s.\n\n",
		r.CPUs, r.MemoryMB, r.Kernel, r.Image, short(r.Digest), r.Date.UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "| Backend | Start p50 | Start p90 | Start p99 | Snapshot p50 | Restore p50 | CPU loop vs chroot | 128 MiB fsync write vs chroot | %s |\n", "Concurrent sandboxes")
	fmt.Fprintf(&b, "|---|---|---|---|---|---|---|---|---|\n")
	for _, x := range r.Backends {
		fmt.Fprintf(&b, "| %s | %.1f ms | %.1f ms | %.1f ms | %.1f ms | %.1f ms | %s | %s | %s |\n",
			name(x), x.Start.P50, x.Start.P90, x.Start.P99, x.Snapshot.P50, x.Restore.P50,
			ratio(x.CPUSandbox, x.CPUBaseline), ratio(x.IOSandbox, x.IOBaseline), density(x))
	}
	fmt.Fprintf(&b, "\nStart = host-side wall time of running `true` in a fresh sandbox (namespaces, cgroup, init, exec, teardown); n=%d per backend. Overhead ratios compare medians of 5 runs against a plain chroot into the same image layers, which still pays process start but no isolation.\n", firstN(r))
	return b.String()
}

func name(x BackendResult) string {
	if x.Version != "" {
		return fmt.Sprintf("%s (%s)", x.Backend, x.Version)
	}
	return x.Backend
}

func ratio(s, base Stat) string {
	if s.N == 0 || base.N == 0 || base.P50 == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.0f ms vs %.0f ms (x%.2f)", s.P50, base.P50, s.P50/base.P50)
}

func density(x BackendResult) string {
	if x.DensityErr != "" {
		return fmt.Sprintf("%d ok in %.0f ms (first error: %s)", x.DensityOK, x.DensityWallMS, x.DensityErr)
	}
	return fmt.Sprintf("%d ok in %.0f ms", x.DensityOK, x.DensityWallMS)
}

func firstN(r Results) int {
	if len(r.Backends) == 0 {
		return 0
	}
	return r.Backends[0].Start.N
}

func short(h string) string {
	if len(h) > 19 {
		return h[:19]
	}
	return h
}
