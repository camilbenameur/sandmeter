//go:build linux

// Package gvisor runs commands under runsc, gVisor's OCI runtime, on the
// same host-side pieces as the native backend: the same overlay layers, the
// same cgroup counters, the same veth pair and nftables egress rules. Only
// the thing that executes the sandboxed program's system calls changes: a
// user-space kernel (the Sentry, systrap platform) instead of the host kernel.
//
// gVisor is not a virtual machine: the Sentry runs as a host process,
// itself sandboxed with seccomp and namespaces.
package gvisor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vishvananda/netns"

	"github.com/camilbenameur/ringfence/internal/cgroup"
	"github.com/camilbenameur/ringfence/internal/iox"
	"github.com/camilbenameur/ringfence/internal/layers"
	"github.com/camilbenameur/ringfence/internal/seccomp"
	"github.com/camilbenameur/ringfence/internal/vnet"
	"github.com/camilbenameur/ringfence/netpolicy"
	"github.com/camilbenameur/ringfence/sandbox"
)

// Options configure the backend.
type Options struct {
	// Runsc is the runsc binary. Default: "runsc" from PATH.
	Runsc string
	// Platform is the runsc platform. Default "systrap" (works without KVM).
	Platform string
	// StateDir holds per-sandbox state. Default /run/ringfence.
	StateDir string
	// CgroupParent is the cgroup v2 directory under which runsc creates
	// one group per command. Default cgroup.DefaultParent.
	CgroupParent string
	// IDShift is the owner of the image layers (see native.Options).
	IDShift uint32
	// OutputLimit caps captured stdout and stderr, each. Default 1 MiB.
	OutputLimit int
}

func (o *Options) defaults() {
	if o.Runsc == "" {
		o.Runsc = "runsc"
	}
	if o.Platform == "" {
		o.Platform = "systrap"
	}
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

// Backend runs sandboxes under runsc.
type Backend struct {
	opts    Options
	path    string
	version string
	err     error
}

// New locates runsc and reads its version. Errors are reported by
// Capabilities (as notes) and Start, so a missing runsc does not break the CLI.
func New(opts Options) *Backend {
	opts.defaults()
	b := &Backend{opts: opts}
	b.path, b.err = exec.LookPath(opts.Runsc)
	if b.err == nil {
		out, err := exec.Command(b.path, "--version").Output()
		if err != nil {
			b.err = fmt.Errorf("runsc --version: %w", err)
		} else {
			b.version = strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
		}
	}
	return b
}

// Version is the runsc version line.
func (b *Backend) Version() string { return b.version }

// Capabilities reports what this backend enforces.
func (b *Backend) Capabilities() sandbox.Capabilities {
	c := sandbox.Capabilities{
		Backend:      "gvisor",
		Isolation:    "user-space-kernel (gVisor " + b.opts.Platform + ")",
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
	if b.err != nil {
		c.Notes = append(c.Notes, "runsc unavailable: "+b.err.Error())
	}
	if os.Geteuid() != 0 {
		c.Notes = append(c.Notes, "not running as root: the gvisor backend cannot start")
	}
	return c
}

// Start mounts the sandbox filesystem. Commands run with Exec.
func (b *Backend) Start(ctx context.Context, spec sandbox.Spec) (sandbox.Sandbox, error) {
	if b.err != nil {
		return nil, fmt.Errorf("gvisor: %w", b.err)
	}
	if os.Geteuid() != 0 {
		return nil, errors.New("gvisor: must run as root")
	}
	if err := os.MkdirAll(b.opts.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("gvisor: %w", err)
	}
	if err := cgroup.EnsureParent(b.opts.CgroupParent); err != nil {
		return nil, fmt.Errorf("gvisor: %w", err)
	}
	var raw [6]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	id := "g" + hex.EncodeToString(raw[:])
	s := &Sandbox{b: b, id: id, spec: spec, dir: filepath.Join(b.opts.StateDir, id)}
	if spec.Network == sandbox.NetworkAllowlist {
		if err := netpolicy.CheckForwarding(); err != nil {
			return nil, fmt.Errorf("gvisor: %w", err)
		}
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		var err error
		s.dests, s.hosts, err = netpolicy.Resolve(rctx, spec.Allow, nil)
		if err != nil {
			return nil, fmt.Errorf("gvisor: resolve allowlist: %w", err)
		}
	}
	var hosts []byte
	for _, h := range s.hosts {
		hosts = append(hosts, fmt.Sprintf("%s %s\n", h.IP, h.Name)...)
	}
	var err error
	s.stack, err = layers.New(s.dir, spec.Layers, b.opts.IDShift, hosts)
	if err != nil {
		return nil, fmt.Errorf("gvisor: %w", err)
	}
	return s, nil
}

// Sandbox is one gVisor sandbox: a filesystem on which each Exec starts a
// fresh runsc sandbox.
type Sandbox struct {
	b     *Backend
	id    string
	spec  sandbox.Spec
	dir   string
	stack *layers.Stack
	dests []netpolicy.Dest
	hosts []netpolicy.HostEntry

	mu      sync.Mutex
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
		return "", errors.New("gvisor: sandbox stopped")
	}
	id, err := s.stack.Snapshot()
	return sandbox.SnapshotID(id), err
}

// Restore resets the writable layer.
func (s *Sandbox) Restore(ctx context.Context, id sandbox.SnapshotID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return errors.New("gvisor: sandbox stopped")
	}
	return s.stack.Restore(string(id))
}

// Stop releases the filesystem.
func (s *Sandbox) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return nil
	}
	s.stopped = true
	return s.stack.Close()
}

// Exec runs argv in a new runsc sandbox on top of the filesystem.
func (s *Sandbox) Exec(ctx context.Context, argv []string) (res sandbox.Result, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return res, errors.New("gvisor: sandbox stopped")
	}
	if len(argv) == 0 {
		return res, errors.New("gvisor: empty argv")
	}
	s.execs++
	name := fmt.Sprintf("%s-%d", s.id, s.execs)
	opts := s.b.opts
	var cleanups []func()
	defer func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}()

	bundle := filepath.Join(s.dir, "bundle-"+name)
	if err := os.Mkdir(bundle, 0o700); err != nil {
		return res, fmt.Errorf("gvisor: %w", err)
	}
	cleanups = append(cleanups, func() { os.RemoveAll(bundle) })

	networkMode := "none"
	var nsPath string
	var pair *vnet.Pair
	if s.spec.Network == sandbox.NetworkAllowlist {
		networkMode = "sandbox"
		nsName := "ringfence-" + name
		ns, err := newNamedNetns(nsName)
		if err != nil {
			return res, fmt.Errorf("gvisor: %w", err)
		}
		cleanups = append(cleanups, func() { netns.DeleteNamed(nsName) })
		pair, err = vnet.Setup(ctx, opts.StateDir, ns, s.dests)
		ns.Close()
		if err != nil {
			return res, fmt.Errorf("gvisor: network: %w", err)
		}
		cleanups = append(cleanups, pair.Close)
		nsPath = filepath.Join("/var/run/netns", nsName)
	}

	cgRel, err := filepath.Rel("/sys/fs/cgroup", filepath.Join(opts.CgroupParent, name))
	if err != nil || strings.HasPrefix(cgRel, "..") {
		return res, fmt.Errorf("gvisor: cgroup parent %q is not under /sys/fs/cgroup", opts.CgroupParent)
	}
	cg := &cgroup.Group{Path: filepath.Join(opts.CgroupParent, name)}
	cfg, err := ociConfig(s.spec, s.stack.Merged(), argv, "/"+cgRel, nsPath)
	if err != nil {
		return res, err
	}
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), cfg, 0o600); err != nil {
		return res, fmt.Errorf("gvisor: %w", err)
	}

	runscRoot := filepath.Join(opts.StateDir, "runsc")
	if err := os.MkdirAll(runscRoot, 0o700); err != nil {
		return res, fmt.Errorf("gvisor: %w", err)
	}
	global := []string{
		"--root", runscRoot,
		"--platform", opts.Platform,
		"--network", networkMode,
		"--overlay2", "none", // writes must reach our overlay so the diff sees them
		"--oci-seccomp",
	}
	stdout := &iox.LimitedBuffer{Limit: opts.OutputLimit}
	stderr := &iox.LimitedBuffer{Limit: opts.OutputLimit}
	cmd := exec.Command(s.b.path, append(global, "run", "--bundle", bundle, name)...)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setsid: true}
	cleanups = append(cleanups, func() {
		exec.Command(s.b.path, append(global, "delete", "--force", name)...).Run()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cg.Remove(ctx)
	})

	var timedOut atomic.Bool
	kill := func() {
		exec.Command(s.b.path, append(global, "kill", "--all", name, "KILL")...).Run()
	}
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return res, fmt.Errorf("gvisor: start runsc: %w", err)
	}
	var timer *time.Timer
	if s.spec.Limits.Wall > 0 {
		timer = time.AfterFunc(s.spec.Limits.Wall, func() { timedOut.Store(true); kill() })
	}
	stop := context.AfterFunc(ctx, kill)
	waitErr := cmd.Wait()
	stop()
	if timer != nil {
		timer.Stop()
	}
	res.Duration = time.Since(start)
	res.Stdout, res.StdoutTruncated = stdout.Bytes(), stdout.Truncated()
	res.Stderr, res.StderrTruncated = stderr.Bytes(), stderr.Truncated()
	res.ExitCode = 0
	if waitErr != nil {
		var ee *exec.ExitError
		if !errors.As(waitErr, &ee) {
			return res, fmt.Errorf("gvisor: runsc: %w", waitErr)
		}
		res.ExitCode = ee.ExitCode()
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			res.ExitCode = 128 + int(ws.Signal())
		}
	}
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
	if pair != nil {
		conns, err := netpolicy.Attempts(context.Background(), pair.Table)
		if err != nil {
			return res, fmt.Errorf("gvisor: read connection log: %w", err)
		}
		res.Connections = conns
	}
	return res, nil
}

// newNamedNetns creates a network namespace pinned at /var/run/netns/name
// without moving the calling goroutine's thread into it for good.
func newNamedNetns(name string) (netns.NsHandle, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		return 0, err
	}
	defer orig.Close()
	ns, err := netns.NewNamed(name)
	if err != nil {
		return 0, fmt.Errorf("create netns: %w", err)
	}
	if err := netns.Set(orig); err != nil {
		ns.Close()
		return 0, fmt.Errorf("restore netns: %w", err)
	}
	return ns, nil
}

// ociConfig builds the OCI runtime spec for one command.
func ociConfig(spec sandbox.Spec, rootfs string, argv []string, cgroupsPath, netnsPath string) ([]byte, error) {
	caps := []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL",
		"CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE", "CAP_SYS_CHROOT", "CAP_AUDIT_WRITE"}
	cwd := spec.Workdir
	if cwd == "" {
		cwd = "/"
	}
	env := spec.Env
	if len(env) == 0 {
		env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root"}
	}
	hostname := spec.Hostname
	if hostname == "" {
		hostname = "sandbox"
	}
	mounts := []map[string]any{
		{"destination": "/proc", "type": "proc", "source": "proc"},
		{"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
		{"destination": "/sys", "type": "sysfs", "source": "sysfs", "options": []string{"nosuid", "noexec", "nodev", "ro"}},
	}
	if spec.ReadOnlyRoot {
		for _, d := range []string{"tmp", "workspace"} {
			mounts = append(mounts, map[string]any{
				"destination": "/" + d, "type": "bind", "source": filepath.Join(rootfs, d),
				"options": []string{"rbind", "rw", "nodev"},
			})
		}
	}
	namespaces := []map[string]string{{"type": "pid"}, {"type": "ipc"}, {"type": "uts"}, {"type": "mount"}}
	if netnsPath != "" {
		namespaces = append(namespaces, map[string]string{"type": "network", "path": netnsPath})
	} else {
		namespaces = append(namespaces, map[string]string{"type": "network"})
	}
	resources := map[string]any{}
	if l := spec.Limits; l.MemoryBytes > 0 {
		resources["memory"] = map[string]int64{"limit": l.MemoryBytes, "swap": l.MemoryBytes}
	}
	if l := spec.Limits; l.CPU > 0 {
		resources["cpu"] = map[string]int64{"quota": int64(l.CPU*100000 + 0.5), "period": 100000}
	}
	if l := spec.Limits; l.PIDs > 0 {
		resources["pids"] = map[string]int64{"limit": l.PIDs}
	}
	linux := map[string]any{
		"namespaces":  namespaces,
		"cgroupsPath": cgroupsPath,
		"resources":   resources,
	}
	if spec.Seccomp {
		sc, err := ociSeccomp()
		if err != nil {
			return nil, err
		}
		linux["seccomp"] = sc
	}
	cfg := map[string]any{
		"ociVersion": "1.0.2",
		"process": map[string]any{
			"terminal": false,
			"user":     map[string]int{"uid": 0, "gid": 0},
			"args":     argv,
			"env":      env,
			"cwd":      cwd,
			"capabilities": map[string][]string{
				"bounding": caps, "effective": caps, "permitted": caps,
			},
			"rlimits": []map[string]any{
				{"type": "RLIMIT_NOFILE", "hard": 4096, "soft": 4096},
				{"type": "RLIMIT_CORE", "hard": 0, "soft": 0},
			},
			"noNewPrivileges": true,
		},
		"root":     map[string]any{"path": rootfs, "readonly": spec.ReadOnlyRoot},
		"hostname": hostname,
		"mounts":   mounts,
		"linux":    linux,
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// ociSeccomp translates the native seccomp profile into the OCI format, which
// gVisor enforces inside its own kernel when started with --oci-seccomp.
func ociSeccomp() (map[string]any, error) {
	p := seccomp.Default()
	arch := map[string]string{"amd64": "SCMP_ARCH_X86_64", "arm64": "SCMP_ARCH_AARCH64"}[runtime.GOARCH]
	if arch == "" {
		return nil, fmt.Errorf("gvisor: no seccomp arch for %s", runtime.GOARCH)
	}
	const eperm, enosys = 1, 38
	syscalls := []map[string]any{
		{"names": p.Names(), "action": "SCMP_ACT_ERRNO", "errnoRet": eperm},
		{"names": []string{"clone3"}, "action": "SCMP_ACT_ERRNO", "errnoRet": enosys},
	}
	if p.DenyNamespaceFlags {
		// One rule per flag: (flags & bit) == bit.
		for _, bit := range []uint64{0x00020000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x02000000, 0x00000080} {
			syscalls = append(syscalls, map[string]any{
				"names": []string{"clone"}, "action": "SCMP_ACT_ERRNO", "errnoRet": eperm,
				"args": []map[string]any{{"index": 0, "value": bit, "valueTwo": bit, "op": "SCMP_CMP_MASKED_EQ"}},
			})
		}
	}
	return map[string]any{"defaultAction": "SCMP_ACT_ALLOW", "architectures": []string{arch}, "syscalls": syscalls}, nil
}
