//go:build linux

// Package native is the backend written directly on Linux primitives:
// user, PID, mount, UTS, IPC, network and cgroup namespaces, pivot_root,
// overlayfs, cgroups v2, a seccomp filter, a reduced capability set, and a
// veth pair with nftables egress rules. It does not use runc or any
// container runtime.
//
// Each Exec starts a fresh set of namespaces whose PID 1 is the command
// itself; when it exits, the kernel kills everything left in the sandbox.
// What persists between Execs is the filesystem (the overlay's upper layer).
package native

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/camilbenameur/ringfence/internal/cgroup"
	"github.com/camilbenameur/ringfence/internal/iox"
	"github.com/camilbenameur/ringfence/internal/layers"
	"github.com/camilbenameur/ringfence/internal/vnet"
	"github.com/camilbenameur/ringfence/netpolicy"
	"github.com/camilbenameur/ringfence/sandbox"
)

// Options configure the backend. Zero values select the defaults.
type Options struct {
	// StateDir holds per-sandbox runtime state. Default /run/ringfence.
	StateDir string
	// CgroupParent is the cgroup under which every command gets its own group.
	CgroupParent string
	// IDShift is the host uid/gid that root inside the sandbox maps to; 65536
	// ids starting there are mapped. It must match the ownership of the image
	// layers. Default 100000.
	IDShift uint32
	// OutputLimit caps captured stdout and stderr, each. Default 1 MiB.
	OutputLimit int
}

func (o *Options) defaults() {
	if o.StateDir == "" {
		o.StateDir = "/run/ringfence"
	}
	if o.CgroupParent == "" {
		o.CgroupParent = cgroup.DefaultParent
	}
	if o.IDShift == 0 {
		o.IDShift = 100000
	}
	if o.OutputLimit == 0 {
		o.OutputLimit = 1 << 20
	}
}

// IDRange is the number of uids and gids mapped into the sandbox.
const IDRange = 65536

// Backend is the native backend. Create it with New.
type Backend struct {
	opts Options
	host Host
}

// New probes the host and returns a backend.
func New(opts Options) *Backend {
	opts.defaults()
	return &Backend{opts: opts, host: ProbeHost()}
}

// Name is the backend name used in policies, receipts and the CLI.
func (b *Backend) Name() string { return "native" }

// Capabilities reports what this backend enforces on this host.
func (b *Backend) Capabilities() sandbox.Capabilities {
	c := sandbox.Capabilities{
		Backend:      "native",
		Isolation:    "linux-namespaces",
		CPULimit:     true,
		MemoryLimit:  true,
		PIDsLimit:    true,
		WallTimeout:  true,
		Networks:     []sandbox.NetworkMode{sandbox.NetworkNone, sandbox.NetworkAllowlist},
		ReadOnlyRoot: true,
		Seccomp:      true,
		DropCaps:     true,
		Snapshot:     true,
		NeedsRoot:    true,
	}
	if !b.host.Root {
		c.Notes = append(c.Notes, "not running as root: the native backend cannot start")
	}
	if !b.host.Cgroup2 {
		c.Notes = append(c.Notes, "cgroup v2 is not mounted at /sys/fs/cgroup")
	}
	if b.host.AppArmorRestrictsUserns {
		c.Notes = append(c.Notes, "kernel.apparmor_restrict_unprivileged_userns=1: rootless mode is unavailable on this host")
	}
	return c
}

// Start mounts the sandbox filesystem. Commands run with Exec.
func (b *Backend) Start(ctx context.Context, spec sandbox.Spec) (sandbox.Sandbox, error) {
	if !b.host.Root {
		return nil, errors.New("native: must run as root")
	}
	if len(spec.Layers) == 0 {
		return nil, errors.New("native: spec has no image layers")
	}
	if err := os.MkdirAll(b.opts.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("native: %w", err)
	}
	if err := cgroup.EnsureParent(b.opts.CgroupParent); err != nil {
		return nil, fmt.Errorf("native: %w", err)
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	s := &Sandbox{b: b, id: id, spec: spec, dir: filepath.Join(b.opts.StateDir, id)}
	if spec.Network == sandbox.NetworkAllowlist {
		if err := netpolicy.CheckForwarding(); err != nil {
			return nil, fmt.Errorf("native: %w", err)
		}
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		s.dests, s.hosts, err = netpolicy.Resolve(rctx, spec.Allow, nil)
		if err != nil {
			return nil, fmt.Errorf("native: resolve allowlist: %w", err)
		}
	}
	var hosts []byte
	for _, h := range s.hosts {
		hosts = append(hosts, fmt.Sprintf("%s %s\n", h.IP, h.Name)...)
	}
	s.stack, err = layers.New(s.dir, spec.Layers, b.opts.IDShift, hosts)
	if err != nil {
		return nil, fmt.Errorf("native: %w", err)
	}
	return s, nil
}

func newID() (string, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("native: id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// Sandbox is one native sandbox.
type Sandbox struct {
	b     *Backend
	id    string
	spec  sandbox.Spec
	dir   string
	stack *layers.Stack
	dests []netpolicy.Dest
	hosts []netpolicy.HostEntry

	mu      sync.Mutex // serialises Exec, Snapshot, Restore, Stop
	execs   int
	stopped bool
}

// ID returns the sandbox ID.
func (s *Sandbox) ID() string { return s.id }

// Layers returns the overlay layers for the receipt diff.
func (s *Sandbox) Layers() (string, []string) { return s.stack.Layers() }

// Merged is the mounted root filesystem on the host.
func (s *Sandbox) Merged() string { return s.stack.Merged() }

// DiffBase names the layer the diff is relative to.
func (s *Sandbox) DiffBase() string { return s.stack.DiffBase() }

// Snapshot freezes the writable layer.
func (s *Sandbox) Snapshot(ctx context.Context) (sandbox.SnapshotID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return "", errors.New("native: sandbox stopped")
	}
	id, err := s.stack.Snapshot()
	return sandbox.SnapshotID(id), err
}

// Restore resets the writable layer to a snapshot, or to the image with "image".
func (s *Sandbox) Restore(ctx context.Context, id sandbox.SnapshotID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return errors.New("native: sandbox stopped")
	}
	return s.stack.Restore(string(id))
}

// Stop releases the filesystem. Nothing runs between Execs, so there is no
// process to kill.
func (s *Sandbox) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return nil
	}
	s.stopped = true
	return s.stack.Close()
}

// Exec runs argv in fresh namespaces on top of the sandbox filesystem.
func (s *Sandbox) Exec(ctx context.Context, argv []string) (sandbox.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return sandbox.Result{}, errors.New("native: sandbox stopped")
	}
	if len(argv) == 0 {
		return sandbox.Result{}, errors.New("native: empty argv")
	}
	s.execs++
	r := &run{s: s, name: fmt.Sprintf("%s-%d", s.id, s.execs)}
	defer r.cleanup()
	return r.exec(ctx, argv)
}

// run holds the host resources of one Exec.
type run struct {
	s       *Sandbox
	name    string
	cg      *cgroup.Group
	net     *vnet.Pair
	cleanup func()
}

func (r *run) exec(ctx context.Context, argv []string) (sandbox.Result, error) {
	var res sandbox.Result
	var cleanups []func()
	r.cleanup = func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}
	spec := r.s.spec
	opts := r.s.b.opts

	cg, err := cgroup.New(opts.CgroupParent, r.name, spec.Limits)
	if err != nil {
		return res, fmt.Errorf("native: %w", err)
	}
	r.cg = cg
	cleanups = append(cleanups, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cg.Remove(ctx)
	})
	cgDir, err := cg.Open()
	if err != nil {
		return res, fmt.Errorf("native: %w", err)
	}
	defer cgDir.Close()

	cfgR, cfgW, err := os.Pipe()
	if err != nil {
		return res, fmt.Errorf("native: %w", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		cfgR.Close()
		cfgW.Close()
		return res, fmt.Errorf("native: %w", err)
	}
	defer cfgW.Close()
	defer errR.Close()

	self, err := os.Executable()
	if err != nil {
		return res, fmt.Errorf("native: %w", err)
	}
	stdout := &iox.LimitedBuffer{Limit: opts.OutputLimit}
	stderr := &iox.LimitedBuffer{Limit: opts.OutputLimit}
	cmd := &exec.Cmd{
		Path:       self,
		Args:       []string{self, InitArg},
		Env:        []string{},
		Stdout:     stdout,
		Stderr:     stderr,
		ExtraFiles: []*os.File{cfgR, errW},
		SysProcAttr: &syscall.SysProcAttr{
			Cloneflags: unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWPID |
				unix.CLONE_NEWUTS | unix.CLONE_NEWIPC | unix.CLONE_NEWNET | unix.CLONE_NEWCGROUP,
			UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: int(opts.IDShift), Size: IDRange}},
			GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: int(opts.IDShift), Size: IDRange}},
			UseCgroupFD: true,
			CgroupFD:    int(cgDir.Fd()),
			Pdeathsig:   syscall.SIGKILL,
			Setsid:      true,
		},
	}
	start := time.Now()
	if err := cmd.Start(); err != nil {
		cfgR.Close()
		errW.Close()
		return res, fmt.Errorf("native: start init: %w", err)
	}
	cfgR.Close()
	errW.Close()
	waited := false
	cleanups = append(cleanups, func() {
		if !waited {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})

	// The timeout covers sandbox setup too, so a stuck init cannot hang the host side.
	var timedOut atomic.Bool
	killAll := func() {
		kctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cg.Kill(kctx)
	}
	var timer *time.Timer
	if spec.Limits.Wall > 0 {
		timer = time.AfterFunc(spec.Limits.Wall, func() {
			timedOut.Store(true)
			killAll()
		})
	}
	stopCtx := context.AfterFunc(ctx, killAll)
	defer stopCtx()

	if spec.Network == sandbox.NetworkAllowlist {
		ns, err := netns.GetFromPid(cmd.Process.Pid)
		if err != nil {
			return res, fmt.Errorf("native: open sandbox netns: %w", err)
		}
		vp, err := vnet.Setup(ctx, r.s.b.opts.StateDir, ns, r.s.dests)
		ns.Close()
		if err != nil {
			return res, fmt.Errorf("native: network: %w", err)
		}
		r.net = vp
		cleanups = append(cleanups, vp.Close)
	}

	workdir := spec.Workdir
	if workdir == "" {
		workdir = "/"
	}
	cfg := initConfig{
		Root:         r.s.stack.Merged(),
		ReadOnlyRoot: spec.ReadOnlyRoot,
		Hostname:     hostnameOr(spec.Hostname),
		Argv:         argv,
		Env:          envOr(spec.Env),
		Workdir:      workdir,
		Seccomp:      spec.Seccomp,
	}
	if err := json.NewEncoder(cfgW).Encode(cfg); err != nil {
		return res, fmt.Errorf("native: send config: %w", err)
	}
	cfgW.Close()

	// The error pipe closes on execve (success) or carries the setup error.
	setupErr, _ := io.ReadAll(io.LimitReader(errR, 4096))

	waitErr := cmd.Wait()
	waited = true
	if timer != nil {
		timer.Stop()
	}
	res.Duration = time.Since(start)
	if len(setupErr) > 0 {
		return res, fmt.Errorf("native: sandbox setup failed: %s", setupErr)
	}

	// Kill anything that escaped the PID 1 lifetime rule (should be nothing).
	kctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	cg.Kill(kctx)
	cancel()

	res.Stdout, res.StdoutTruncated = stdout.Bytes(), stdout.Truncated()
	res.Stderr, res.StderrTruncated = stderr.Bytes(), stderr.Truncated()
	res.ExitCode = exitCode(waitErr, cmd)
	if st, err := cg.Stats(); err == nil {
		res.Stats = st
	}
	switch {
	case timedOut.Load():
		res.Killed = "wall-timeout"
	case res.Stats.OOMKills > 0:
		res.Killed = "oom"
	case ctx.Err() != nil:
		res.Killed = "cancelled"
	}
	if r.net != nil {
		conns, err := netpolicy.Attempts(context.Background(), r.net.Table)
		if err != nil {
			return res, fmt.Errorf("native: read connection log: %w", err)
		}
		res.Connections = conns
	}
	return res, nil
}

func exitCode(err error, cmd *exec.Cmd) int {
	if err == nil {
		return 0
	}
	if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return cmd.ProcessState.ExitCode()
}

func hostnameOr(h string) string {
	if h == "" {
		return "sandbox"
	}
	return h
}

func envOr(env []string) []string {
	if len(env) == 0 {
		return []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root"}
	}
	return env
}
