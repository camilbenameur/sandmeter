// Package sandbox defines the contract between the engine and an isolation
// backend: what the engine asks for (Spec, ExecOptions), what it gets back
// (Result), what a backend can enforce on this host (Capabilities), and the
// two interfaces a backend implements (Backend, Sandbox).
//
// # Who is trusted with what
//
// The engine builds a Spec from a policy that was already checked against the
// operator's ceiling and against the backend's Capabilities. A backend may
// therefore assume that the Spec asks for nothing the operator forbids. It
// may not assume that it can honour the Spec: a backend that is asked for
// something it does not enforce refuses, with ErrUnsupported, and never runs
// the command without it. "The policy says X" and "the backend does X" must
// not drift apart silently.
//
// Everything a Result holds is the backend's own observation, made from the
// host side. Nothing in it is taken on the word of a process inside the
// sandbox, with one exception that is named where it occurs: the reason an
// exec failed.
//
// # Three values
//
// Wherever a measurement can be absent, its absence is explicit: a nil
// pointer, a false Recorded, an Err. A zero in a Result always means zero.
//
// # Lifetime
//
// A sandbox is a session: a writable layer that persists from one command to
// the next, and nothing else. Between two commands no process, no mount and
// no network device exists for it; a session is then a directory. Each Exec
// builds a fresh set of namespaces, runs one command in it and takes
// everything down again.
//
// # Who owns what on the host
//
// The engine creates the directory of a session, holds its lock for as long
// as the session lives, and removes it. It hands the directory to the backend
// in Spec.Dir. A backend keeps everything it puts on disk for the session
// inside that directory. Two kernel objects may outlive a command: the
// session's cgroup, which is named after Spec.ID, and, with StorageTmpfs, the
// tmpfs of the writable layer, which is mounted inside Spec.Dir in the
// private mount namespace of the engine's process and goes when that process
// does. That is the whole footprint of a session, by construction: when the
// process that owned a session dies, a sweep finds the directory without a
// lock holder, empties and removes the cgroup of that name and removes the
// directory, without asking a backend and without knowing which one it was.
// A backend must not create anything on the host that this rule does not
// cover: no mount in the host's mount namespace, no network device, no file
// outside Spec.Dir.
package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/camilbenameur/sandmeter/internal/hostprobe"
	"github.com/camilbenameur/sandmeter/internal/ids"
	"github.com/camilbenameur/sandmeter/policy"
)

// Errors of the contract. A backend wraps them with what it was asked for.
var (
	// ErrNotBuilt is returned by a function that is declared and not written
	// yet. Such a function fails closed: nothing runs, nothing is accepted.
	ErrNotBuilt = errors.New("not built in this version")
	// ErrUnsupported is returned when a Spec or an option asks for something
	// the backend does not provide on this host. The backend's Capabilities
	// say the same thing beforehand; the error is the second line of defence
	// and means that a check upstream was skipped.
	ErrUnsupported = errors.New("not supported by this backend on this host")
	// ErrInvalid is returned for a Spec that is malformed: a field left at
	// its zero value where a value is required, a limit that is neither a
	// positive amount nor explicitly none, a mode that does not exist. It
	// means that whoever built the Spec forgot a field or skipped a check.
	// No backend guesses what was meant, and none runs anything.
	ErrInvalid = errors.New("invalid sandbox specification")
	// ErrBusy is returned by an operation that needs the sandbox at rest
	// while a command runs in it, and by Exec while another Exec runs.
	// Commands are never queued.
	ErrBusy = errors.New("a command is running in this sandbox")
	// ErrStopped is returned by every operation but Stop once Stop was
	// called, whether that call succeeded or not: a session that somebody
	// began to stop runs nothing more. Only Stop itself may be repeated.
	ErrStopped = errors.New("the sandbox is stopped")
	// ErrUnknownSnapshot is returned by Restore for a snapshot the sandbox
	// does not have.
	ErrUnknownSnapshot = errors.New("no such snapshot")
)

// IDCount is the number of user and group ids mapped into a sandbox: ids 0
// to IDCount-1 inside are ids Spec.IDBase to Spec.IDBase+IDCount-1 on the
// host.
const IDCount = 65536

// Capabilities is what a backend can enforce on this host. The type belongs
// to package policy, which reads it to refuse a policy and may import nothing
// internal; this is the same type under the name the backends use.
//
// A backend builds it from the report of the host probe: it starts from
// hostprobe.Report.Capabilities, which answers for the host, then sets its
// minimums and withdraws, each with a reason, the controls it does not offer.
// It never adds one: a control is enforced only if a check of the probe said
// so on this host, never because a constant in the backend's code does.
type Capabilities = policy.Capabilities

// Limit is one resource limit of a Spec. It says one of two things, and says
// it explicitly: a positive amount, or that no limit is in force. The zero
// Limit says neither. Spec.Validate refuses it, so that a field somebody
// forgot to fill is an error and never reads as "no limit".
type Limit struct {
	// Value is the limit, in the unit of the field that holds it. It is
	// positive, and zero when None is set.
	Value int64
	// None says that no limit is in force: the policy asked for "unlimited"
	// and the ceiling granted it, or a built-in default was not applied
	// because the backend cannot enforce it. The backend then sets none.
	None bool
}

// AtMost returns the Limit of v, which must be positive.
func AtMost(v int64) Limit { return Limit{Value: v} }

// NoLimit returns the Limit that says no limit is in force.
func NoLimit() Limit { return Limit{None: true} }

// Valid reports whether l is a positive amount or an explicit absence.
func (l Limit) Valid() bool {
	if l.None {
		return l.Value == 0
	}
	return l.Value > 0
}

// Get returns the amount and true, or zero and false when no limit is in
// force. A Limit that is not valid reads as an amount and never as "none":
// code that used a Spec nobody validated then applies the harshest reading
// of it, a limit of zero, which the kernel refuses or which lets nothing
// run.
func (l Limit) Get() (v int64, limited bool) {
	if l.None && l.Value == 0 {
		return 0, false
	}
	return l.Value, true
}

// Duration is Get for a limit that holds nanoseconds.
func (l Limit) Duration() (d time.Duration, limited bool) {
	v, limited := l.Get()
	return time.Duration(v), limited
}

// Limits are the resource limits of a sandbox, already resolved: the engine
// applied the defaults and the ceiling. Every field is a Limit and has to be
// filled in: there is no value that means "no limit" by being left out.
type Limits struct {
	// CPUMillis is the CPU limit of the session in thousandths of a core.
	CPUMillis Limit
	// MemoryBytes is the memory limit of the session. Swap is always
	// refused to the sandbox.
	MemoryBytes Limit
	// PIDs is the largest number of tasks of the workload. Tasks the backend
	// needs for its own processes inside the sandbox come on top of it and
	// are the backend's to reserve.
	PIDs Limit
	// Wall is the longest one command may run, in nanoseconds: read it with
	// Limit.Duration.
	Wall Limit
	// DiskBytes and DiskInodes are the hard quota of the writable layer.
	// With StorageDisk both are NoLimit: that mode has no quota. With
	// StorageTmpfs both are amounts, or both are NoLimit for a memory-backed
	// layer that only the memory limit of the session bounds. DiskInodes is
	// InodesFor of DiskBytes unless the engine has a reason to say otherwise.
	DiskBytes  Limit
	DiskInodes Limit
}

// InodesFor returns the inode quota that goes with a byte quota: one inode
// per 16 KiB, and never fewer than 4096.
func InodesFor(diskBytes int64) int64 {
	const bytesPerInode, floor = 16 << 10, 4096
	if n := diskBytes / bytesPerInode; n > floor {
		return n
	}
	return floor
}

// StorageMode says where the writable layer of a sandbox lives.
type StorageMode string

const (
	// StorageDisk keeps the writable layer in the session's directory on the
	// state filesystem, with no quota of its own. A free-space floor on that
	// filesystem guards the host.
	StorageDisk StorageMode = policy.UpperDisk
	// StorageTmpfs keeps the writable layer on a tmpfs of Limits.DiskBytes
	// and Limits.DiskInodes, charged to the memory limit of the session.
	StorageTmpfs StorageMode = policy.UpperTmpfs
)

// NetworkMode is the network a sandbox gets.
type NetworkMode string

const (
	// NetworkNone is a network namespace with loopback only.
	NetworkNone NetworkMode = policy.NetworkNone
	// NetworkProxy is the same namespace with one listener on its loopback,
	// served from the host side by the egress proxy. The namespace still has
	// no other interface and no route, and nothing is added to the network
	// namespace of the host.
	NetworkProxy NetworkMode = policy.NetworkProxy
)

// ProxyAddr is where the egress proxy listens inside a sandbox in
// NetworkProxy mode. The backend points HTTP_PROXY, HTTPS_PROXY and their
// lower-case forms at it.
const ProxyAddr = "127.0.0.1:3128"

// Floor is the free-space guard of the state filesystem, from the operator
// file. It is a guard for the host and not a quota for the sandbox: it bounds
// what is left for everybody else, not what one session may write.
type Floor struct {
	// MinFreeBytes and MinFreeInodes are what must stay free on the
	// filesystem of Spec.Dir. The guard is always on: both are positive, the
	// operator file has no value that switches either half off, and a Spec
	// with a zero in one of them is refused.
	MinFreeBytes  int64
	MinFreeInodes int64
}

// Network is the network part of a Spec.
type Network struct {
	Mode NetworkMode
	// Allow is the allow list of the proxy: normalised, de-duplicated
	// destinations from policy.ParseDest. It is empty with NetworkNone.
	Allow []policy.Dest
	// DenyExtra lists address prefixes the operator forbids the proxy to
	// dial, on top of the special-purpose addresses and the host's own,
	// which are always forbidden. No policy can shorten either list.
	DenyExtra []netip.Prefix
}

// Spec is everything a backend needs to start a sandbox. The engine fills
// it; no field comes from a client unchecked, and no field is a path that a
// client chose.
//
// The zero Spec is not a sandbox with everything switched off: it is
// invalid. Every field that decides a protection has to be given a value,
// and Validate, which every backend calls first, refuses a Spec in which one
// was left out.
type Spec struct {
	// ID is the session identifier. The service generated it; no client
	// chose it. The backend names the session's cgroup after it and after
	// nothing else, so that a sweep can tell what belongs to a session from
	// its name alone.
	ID ids.ID
	// Dir is the directory of the session: an absolute path that the engine
	// created for this session alone, readable by root only, on the state
	// filesystem. The engine holds the session's lock for as long as the
	// sandbox exists and removes the directory after Stop. The backend puts
	// everything it keeps on disk for the session inside it (the writable
	// layer, the snapshots, mount points, what an external runtime stores)
	// and nothing anywhere else. It never changes the owner or the mode of
	// Dir itself.
	Dir string
	// Layers are the read-only image layer directories, bottom layer first.
	// They are absolute paths inside the image store and their files are
	// owned by ids IDBase to IDBase+IDCount-1.
	Layers []string
	// Workspace is the directory of the workspace layer, or empty when the
	// session has no project. Its only content is a directory named
	// "workspace": the private copy of the project, owned by IDBase. The
	// backend stacks it above the image layers and under the writable layer,
	// read-only, so that what a command writes under /workspace lands in the
	// one writable layer.
	//
	// The engine changes the content of this directory between two commands
	// to follow the project on the host, never during one. A backend reads
	// the directory afresh for each command and keeps nothing derived from
	// its content.
	Workspace string
	// Limits apply to the session as a whole, except Wall.
	Limits Limits
	// Storage is where the writable layer lives.
	Storage StorageMode
	// Floor is the free-space guard. The engine refuses to start a command
	// under it; the backend watches it while a command runs and kills the
	// command when it is crossed (KillDiskFloor).
	Floor Floor
	// Network is the network of every command of the session.
	Network Network
	// SyscallProfile is policy.ProfileDefault, policy.ProfileCompat or
	// policy.ProfileOff.
	SyscallProfile string
	// ReadOnlyRoot makes the root filesystem read-only except /tmp and
	// /workspace. Writes to those two go to the writable layer.
	ReadOnlyRoot bool
	// Env is the environment of every command, as "NAME=value" strings, in
	// the order given, the last one winning for a repeated name. The engine
	// has already merged the image's variables, the policy's and the values
	// passed from the client. The backend adds the proxy variables in
	// NetworkProxy mode and nothing else. Every string is valid UTF-8 with
	// no NUL byte.
	Env []string
	// Workdir is the working directory of commands: an absolute path inside
	// the sandbox, or empty for "/".
	Workdir string
	// Hostname is the host name inside the sandbox, or empty for the
	// backend's default.
	Hostname string
	// IDBase is the host id that user and group 0 of the sandbox map to.
	// The image layers and the workspace layer were written for this base.
	// It is never 0, which would make root of the sandbox root of the host,
	// and the whole range lies above the ids a host gives its own accounts.
	IDBase uint32
}

// MaxHostnameBytes is the longest host name the kernel takes.
const MaxHostnameBytes = 64

// Validate reports everything that is wrong with the form of s, as one error
// that wraps ErrInvalid and names each fault. It asks the host nothing: it
// checks what must hold for every backend, which is that every field that
// decides a protection was given a meaningful value.
//
// Invariant: no backend starts anything for a Spec that Validate refuses.
// Start calls it before it touches the host. Without it a forgotten field
// would be read as the weakest setting of that field: no limit, no guard,
// the host's own root.
func (s Spec) Validate() error {
	var faults []string
	bad := func(format string, args ...any) {
		faults = append(faults, fmt.Sprintf(format, args...))
	}
	absolute := func(what, p string) {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			bad("%s %q is not an absolute, clean path", what, p)
		}
	}
	text := func(what, v string) bool {
		if !utf8.ValidString(v) || strings.ContainsRune(v, 0) {
			bad("%s is not valid UTF-8 or holds a NUL byte", what)
			return false
		}
		return true
	}

	if s.ID.IsZero() {
		bad("no session identifier")
	}
	absolute("the session directory", s.Dir)
	for i, l := range s.Layers {
		absolute(fmt.Sprintf("image layer %d", i), l)
	}
	if s.Workspace != "" {
		absolute("the workspace layer", s.Workspace)
	}

	faults = append(faults, s.Limits.faults(s.Storage)...)
	switch s.Storage {
	case StorageDisk, StorageTmpfs:
	default:
		bad("storage mode %q is not %q or %q", s.Storage, StorageDisk, StorageTmpfs)
	}
	if s.Floor.MinFreeBytes <= 0 || s.Floor.MinFreeInodes <= 0 {
		bad("the free-space floor is %d bytes and %d inodes: the guard is always on, and both are positive", s.Floor.MinFreeBytes, s.Floor.MinFreeInodes)
	}

	switch s.Network.Mode {
	case NetworkNone:
		if len(s.Network.Allow) != 0 {
			bad("network mode %q with %d allowed destinations", NetworkNone, len(s.Network.Allow))
		}
	case NetworkProxy:
	default:
		bad("network mode %q is not %q or %q", s.Network.Mode, NetworkNone, NetworkProxy)
	}
	for i, d := range s.Network.Allow {
		if d.Host == "" || d.Port == 0 {
			bad("allowed destination %d is not a parsed destination", i)
		}
	}
	for i, p := range s.Network.DenyExtra {
		if !p.IsValid() {
			bad("denied prefix %d is not a prefix", i)
		}
	}

	switch s.SyscallProfile {
	case policy.ProfileDefault, policy.ProfileCompat, policy.ProfileOff:
	default:
		bad("syscall profile %q is not %q, %q or %q", s.SyscallProfile, policy.ProfileDefault, policy.ProfileCompat, policy.ProfileOff)
	}

	for i, e := range s.Env {
		if !text(fmt.Sprintf("environment entry %d", i), e) {
			continue
		}
		if eq := strings.IndexByte(e, '='); eq <= 0 {
			bad("environment entry %d is not NAME=value", i)
		}
	}
	if text("the working directory", s.Workdir) && s.Workdir != "" && !strings.HasPrefix(s.Workdir, "/") {
		bad("the working directory is not an absolute path")
	}
	if text("the host name", s.Hostname) && len(s.Hostname) > MaxHostnameBytes {
		bad("the host name is %d bytes long, more than %d", len(s.Hostname), MaxHostnameBytes)
	}

	// Invariant: root of a sandbox is never root of the host, nor any id a
	// host account can have. The whole range also has to exist: the kernel
	// has no id above 2^32-2.
	switch {
	case s.IDBase < IDCount:
		bad("id base %d: ids of the sandbox would be ids of the host's own accounts, root included below %d", s.IDBase, IDCount)
	case uint64(s.IDBase)+IDCount-1 > math.MaxUint32-1:
		bad("id base %d: the %d ids of a sandbox do not fit under the largest id", s.IDBase, IDCount)
	}

	if len(faults) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(faults, "; "))
}

// faults lists what is wrong with the limits for a storage mode.
func (l Limits) faults(storage StorageMode) []string {
	var out []string
	for _, f := range []struct {
		name string
		l    Limit
	}{
		{"the cpu limit", l.CPUMillis}, {"the memory limit", l.MemoryBytes}, {"the task limit", l.PIDs},
		{"the wall limit", l.Wall}, {"the disk quota", l.DiskBytes}, {"the inode quota", l.DiskInodes},
	} {
		if !f.l.Valid() {
			out = append(out, fmt.Sprintf("%s is %+v: a limit is a positive amount or explicitly none, and never left out", f.name, f.l))
		}
	}
	switch {
	case storage == StorageDisk && (!l.DiskBytes.None || !l.DiskInodes.None):
		out = append(out, fmt.Sprintf("a disk quota with storage mode %q, which has none", StorageDisk))
	case l.DiskBytes.None != l.DiskInodes.None:
		out = append(out, "a byte quota without an inode quota, or the reverse")
	}
	return out
}

// FromPolicy returns the part of a Spec that a resolved policy decides:
// Limits, Storage, Network.Mode, Network.Allow, SyscallProfile, ReadOnlyRoot
// and Workdir. The engine fills the rest: ID, Dir, Layers, Workspace, Floor,
// Network.DenyExtra, Env (which includes the policy's own variables),
// Hostname and IDBase.
//
// A limit that is nil in the policy becomes NoLimit: nothing is in force for
// it, whether "unlimited" was granted or a default was not applied. A limit
// that is set must be at least 1, as policy.Resolve guarantees; one that is
// zero or negative is refused with ErrInvalid.
//
// Invariant: "set to zero" and "not limited" never meet. They are two
// different values in a policy, and a kernel interface that reads zero as
// "no limit" must never be handed a limit somebody set.
func FromPolicy(n policy.Normal) (Spec, error) {
	var faults []string
	limit := func(key string, p *int64) Limit {
		if p == nil {
			return NoLimit()
		}
		if *p <= 0 {
			faults = append(faults, fmt.Sprintf("%s is %d in the policy in force: a limit that is set is at least 1", key, *p))
		}
		return AtMost(*p)
	}
	s := Spec{
		Limits: Limits{
			CPUMillis:   limit(policy.KeyLimitCPU, n.Limits.CPUMillis),
			MemoryBytes: limit(policy.KeyLimitMemory, n.Limits.MemoryBytes),
			PIDs:        limit(policy.KeyLimitPIDs, n.Limits.PIDs),
			Wall:        limit(policy.KeyLimitWall, n.Limits.WallNanos),
			DiskBytes:   limit(policy.KeyLimitDisk, n.Limits.DiskBytes),
			DiskInodes:  NoLimit(),
		},
		Storage:        StorageMode(n.Storage.Upper),
		Network:        Network{Mode: NetworkMode(n.Network.Mode), Allow: append([]policy.Dest(nil), n.Network.Allow...)},
		SyscallProfile: n.Syscalls.Profile,
		ReadOnlyRoot:   n.Filesystem.ReadOnlyRoot,
		Workdir:        n.Process.Workdir,
	}
	if v, limited := s.Limits.DiskBytes.Get(); limited && v > 0 {
		s.Limits.DiskInodes = AtMost(InodesFor(v))
	}
	if len(faults) == 0 {
		faults = s.Limits.faults(s.Storage)
	}
	switch s.Storage {
	case StorageDisk, StorageTmpfs:
	default:
		faults = append(faults, fmt.Sprintf("storage.upper is %q", n.Storage.Upper))
	}
	switch s.Network.Mode {
	case NetworkNone, NetworkProxy:
	default:
		faults = append(faults, fmt.Sprintf("network.mode is %q", n.Network.Mode))
	}
	switch s.SyscallProfile {
	case policy.ProfileDefault, policy.ProfileCompat, policy.ProfileOff:
	default:
		faults = append(faults, fmt.Sprintf("syscalls.profile is %q", n.Syscalls.Profile))
	}
	if len(faults) > 0 {
		return Spec{}, fmt.Errorf("%w: the policy in force cannot be turned into a sandbox: %s", ErrInvalid, strings.Join(faults, "; "))
	}
	return s, nil
}

// ExecOptions are the options of one command.
type ExecOptions struct {
	// Stdout and Stderr receive the output of the command as it is produced.
	// The backend never keeps output: what a writer does not take is gone.
	// Nil discards the stream. The two may be written from two goroutines at
	// once, each from one goroutine at a time.
	//
	// A writer that returns an error gets no more data, and the rest of that
	// stream is discarded: the command is not stopped, and never blocks, on
	// behalf of a reader that went away. A caller that wants the command to
	// end with its reader cancels the context.
	Stdout io.Writer
	Stderr io.Writer
	// Timeout shortens the wall limit for this command. Zero means the
	// limit of the Spec, which may be none. A negative value, and a value
	// above that limit, is refused: an option never widens what the policy
	// set.
	Timeout time.Duration
	// Workdir replaces Spec.Workdir for this command when not empty.
	Workdir string
	// Env is added to Spec.Env for this command, the option winning for a
	// repeated name.
	Env []string
}

// Status says how a command ended. The values are those a receipt records.
type Status string

const (
	// StatusExited: the command ran and ended by itself. Result.ExitCode is
	// its exit status.
	StatusExited Status = "exited"
	// StatusSignalled: a signal the sandbox did not send ended the command,
	// such as its own abort or a segmentation fault. Result.Signal is set.
	StatusSignalled Status = "signalled"
	// StatusKilled: the sandbox ended the command. Result.KillReason says
	// why, and Result.Signal is the signal that did it when one did.
	StatusKilled Status = "killed"
	// StatusExecFailed: the sandbox was set up and the command could not be
	// started in it. Result.ExitCode is ExitNotExecutable or ExitNotFound
	// and Result.Error says why. This is a result, not a failure of the
	// sandbox: an agent that mistypes a command gets an answer and a record.
	StatusExecFailed Status = "exec-failed"
	// StatusSetupFailed: the sandbox could not be set up, or was found not
	// to be in the posture the Spec requires. No process of the command ever
	// ran. Result.Error says why.
	StatusSetupFailed Status = "setup-failed"
)

// Exit statuses of a command that could not be started, after the convention
// shells and container runtimes share.
const (
	// ExitNotExecutable: the command was found and cannot be executed.
	ExitNotExecutable = 126
	// ExitNotFound: the command, or the working directory, does not exist.
	ExitNotFound = 127
)

// KillReason says why the sandbox ended a command. The list is closed.
type KillReason string

const (
	// KillWallTimeout: the command ran longer than its wall limit.
	KillWallTimeout KillReason = "wall-timeout"
	// KillOOM: the kernel killed the sandbox for exceeding its memory limit.
	KillOOM KillReason = "oom"
	// KillCancelled: the context of Exec was cancelled.
	KillCancelled KillReason = "cancelled"
	// KillStopped: Stop was called while the command ran.
	KillStopped KillReason = "stopped"
	// KillDiskFloor: free space or free inodes on the state filesystem fell
	// under the operator's floor while the command ran.
	KillDiskFloor KillReason = "disk-floor"
	// KillSupervisorLost: the sandbox lost the host process that supervised
	// it and ended itself. A backend reports it when a part of its own
	// supervision died under a command that it could still account for.
	KillSupervisorLost KillReason = "supervisor-lost"
	// KillInitLost: the first process of the sandbox ended without reporting
	// how the command ended, for instance because the command killed it.
	// The sandbox is gone; what the command did before is unknown.
	KillInitLost KillReason = "init-lost"
)

// KillReasons is the closed list of kill reasons.
var KillReasons = []KillReason{
	KillWallTimeout, KillOOM, KillCancelled, KillStopped, KillDiskFloor, KillSupervisorLost, KillInitLost,
}

// Scope says which processes the counters of a Result cover.
type Scope string

const (
	// ScopeWorkload: the command and its descendants, nothing else.
	ScopeWorkload Scope = "workload"
	// ScopeInitAndWorkload: the command and the first process of the
	// sandbox, which is a small program of the backend's.
	ScopeInitAndWorkload Scope = "init+workload"
	// ScopeRuntimeAndWorkload: the command and the user-space kernel that
	// runs it. Limits and counters then include the runtime's own use.
	ScopeRuntimeAndWorkload Scope = "runtime+workload"
)

// Counters are resource counters of one command, read by the backend from
// the host side after the command ended. A nil counter was not measured: the
// kernel does not have it, or reading it failed and Err says why. A counter
// that is not nil is exact, zero included.
type Counters struct {
	// Scope says what the numbers cover. It is set even when every counter
	// is nil.
	Scope           Scope
	MemoryPeakBytes *int64
	OOMKills        *int64
	CPUUsageUsec    *int64
	PIDsPeak        *int64
	// PIDsMaxHits counts the forks that the task limit refused.
	PIDsMaxHits *int64
	// Err is why counters could not be read, when that is the reason some
	// are nil. Empty when the kernel simply lacks them.
	Err string
}

// Verdict is what the egress proxy decided for one request.
type Verdict string

const (
	// VerdictAllowed: the destination is in the allow list. The request may
	// still have failed afterwards; Flow.Reason then says how.
	VerdictAllowed Verdict = "allowed"
	// VerdictDenied: the proxy refused the request.
	VerdictDenied Verdict = "denied"
)

// FlowReason says why a request was denied or failed. The list is closed;
// the values are those a receipt records.
type FlowReason string

const (
	// FlowNotAllowed: the name and port are not in the allow list. Nothing
	// was resolved and nothing was dialled.
	FlowNotAllowed FlowReason = "not-allowed"
	// FlowSpecialAddress: the address about to be dialled is forbidden.
	FlowSpecialAddress FlowReason = "special-address"
	// FlowSNIMismatch: the TLS handshake in the tunnel named another server
	// than the request.
	FlowSNIMismatch FlowReason = "sni-mismatch"
	// FlowNotTLS: the destination requires TLS and the tunnel did not start
	// with a TLS handshake.
	FlowNotTLS FlowReason = "not-tls"
	// FlowBadRequest: not a request the proxy serves, or not a valid target.
	FlowBadRequest FlowReason = "bad-request"
	// FlowResolveFailed: the allowed name did not resolve.
	FlowResolveFailed FlowReason = "resolve-failed"
	// FlowDialFailed: the connection to the allowed destination failed.
	FlowDialFailed FlowReason = "dial-failed"
	// FlowLimit: a bound of the proxy was reached.
	FlowLimit FlowReason = "limit"
)

// Flow is one request the egress proxy received.
type Flow struct {
	// Name is the host of the request, normalised by policy.ParseDest: a DNS
	// name or an IPv4 address. The program in the sandbox chose it. It is
	// data, to be shown as data: it must never be pasted into a sentence
	// that sandmeter utters itself. It is empty when the target was not a
	// valid destination; InvalidBytes and InvalidSHA256 then stand for it.
	Name string
	Port uint16
	// InvalidBytes and InvalidSHA256 are the length and the lower-case
	// hexadecimal SHA-256 of a target that was not valid.
	InvalidBytes  int64
	InvalidSHA256 string
	// Address is the address that was dialled; the zero Addr when none was.
	Address netip.Addr
	Verdict Verdict
	// Reason is empty for an allowed request that went through.
	Reason FlowReason
	// BytesUp and BytesDown count what was relayed from and to the sandbox.
	BytesUp   int64
	BytesDown int64
}

// Flows is the network record of one command.
type Flows struct {
	// Recorded is false when nothing recorded requests: there is no proxy
	// with NetworkNone. Records is then empty, and its emptiness proves
	// nothing.
	Recorded bool
	// Complete is true when every request the proxy received is in Records.
	// When it is false, Incomplete says why: the proxy died, its account was
	// cut short, a bound on the number of records was reached.
	Complete   bool
	Incomplete string
	// Records lists the requests in the order the proxy received them. It is
	// the proxy's own account: the proxy is a host-side process of sandmeter
	// that reads bytes the sandbox controls.
	Records []Flow
}

// Posture is the security posture of the tasks of one process, read from
// /proc/<pid>/task/*/status by the backend, from the host side. Tasks is how
// many tasks were read; each other field holds a value only if every one of
// them agreed on it, and is nil or empty otherwise.
type Posture struct {
	Tasks *int
	// SeccompMode and NoNewPrivs are the fields of that name.
	SeccompMode *int
	NoNewPrivs  *bool
	// The capability sets, as the hexadecimal masks of the same file.
	CapEff, CapPrm, CapInh, CapBnd, CapAmb string
}

// Setting is one kernel setting as the backend read it back.
type Setting struct {
	// Name is the name under /proc/sys with dots for slashes, such as
	// "user.max_user_namespaces".
	Name string
	// Value is what the kernel printed, trimmed.
	Value string
}

// Names of the settings a backend writes for the user namespace of a sandbox
// that shares the host's kernel, and reads back into Enforcement.Settings.
const (
	// SettingMaxUserNamespaces is written as 0: a process in the sandbox can
	// then create no user namespace of its own, whatever the syscall profile.
	SettingMaxUserNamespaces = "user.max_user_namespaces"
	// SettingMaxInotifyInstances and SettingMaxInotifyWatches are lowered to
	// a share of the host's values. The kernel charges these objects to the
	// creator of the user namespace as well, which is the host's root: left
	// alone, one sandbox could use up what every root process of the host
	// can create.
	SettingMaxInotifyInstances = "user.max_inotify_instances"
	SettingMaxInotifyWatches   = "user.max_inotify_watches"
)

// RuntimeProcess is one host process of the external runtime a backend
// wraps, with the ids it really ran under.
type RuntimeProcess struct {
	// Role says what the process is, in the runtime's own words: "sentry" or
	// "gofer" for gVisor.
	Role string
	// UID and GID are its effective ids on the host, read from
	// /proc/<pid>/status. 0 is the host's root.
	UID, GID uint32
}

// Enforcement is what was in force around a command, as the backend read it
// back from the kernel after setting it and before the command started. A
// field that could not be read is nil, or empty for the fields that copy
// kernel text and for the lists; it is never filled with what was intended.
// A backend that finds a value other than the one the Spec requires does not
// start the command: the result is StatusSetupFailed.
type Enforcement struct {
	// SyscallProfile is the profile that was installed, and SeccompSHA256
	// the lower-case hexadecimal SHA-256 of the filter program; empty with
	// policy.ProfileOff.
	SyscallProfile string
	SeccompSHA256  string
	// Workload is the posture of the process that became the command, read
	// when everything was installed on it and before it executed the
	// command's program.
	Workload Posture
	// Init is the posture of the first process of the sandbox when that is
	// a program of the backend's on the host's kernel. The zero Posture on a
	// backend without one.
	Init Posture
	// UIDMap and GIDMap are the lines of the uid_map and gid_map files of
	// the workload, fields separated by one space and lines by a newline.
	// A backend whose workload is not a process of the host's kernel leaves
	// them empty: the mapping it asked its runtime for is an intention, not
	// something it read back.
	UIDMap, GIDMap string
	// Settings lists the kernel settings written for the sandbox's user
	// namespace, each read back through the descriptor it was written
	// through, sorted by name. A setting that could not be read back is not
	// in the list.
	Settings []Setting
	// The limits, as read from the cgroup files of the session: verbatim,
	// trimmed.
	CPUMax, MemoryMax, MemorySwapMax, PIDsMax string
	// MountOptions are the options of the root overlay as mountinfo reports
	// them.
	MountOptions string
	// Runtime lists the host processes of the external runtime that ran the
	// command. A backend that maps the sandbox's ids for file ownership while
	// its runtime runs under other ids says so here, by listing the ids that
	// were read; it claims nothing it did not read. Empty for a backend that
	// wraps no runtime.
	Runtime []RuntimeProcess
}

// StorageFacts describes the writable layer after a command.
type StorageFacts struct {
	Upper StorageMode
	// QuotaBytes and QuotaInodes are the hard quota; nil with StorageDisk.
	QuotaBytes, QuotaInodes *int64
	// UsedBytes and UsedInodes are what the layer holds; nil when it could
	// not be measured.
	UsedBytes, UsedInodes *int64
}

// Result is the outcome of one command, as observed from the host.
//
// A Result has no exit status of its own to offer a shell. The status a
// sandmeter command ends with is decided in one place, from the outcome a
// record carries (package exit): a command killed at its time limit, for
// instance, ends with the status reserved for that and not with 128 plus the
// signal that happened to do the killing.
type Result struct {
	// Status says how the command ended and which of ExitCode, Signal,
	// KillReason and Error are meaningful.
	Status Status
	// ExitCode is set with StatusExited and StatusExecFailed.
	ExitCode int
	// Signal is set with StatusSignalled, and with StatusKilled when a
	// signal did the killing.
	Signal int
	// KillReason is set with StatusKilled.
	KillReason KillReason
	// Error is the reason of StatusExecFailed and StatusSetupFailed. For an
	// exec failure it is reported by the backend's own code inside the
	// sandbox, which ran before any byte of the command did.
	Error string

	// Started is when the backend began to set the command up and Duration
	// how long the command itself ran, on a monotonic clock.
	Started  time.Time
	Duration time.Duration

	Counters    Counters
	Flows       Flows
	Enforcement Enforcement
	Storage     StorageFacts

	// CleanupErr is what failed while the command was torn down: a cgroup
	// that would not empty, a mount that would not go away. The outcome
	// above stands whatever it says. The engine records it and the command
	// that ran it exits with the status reserved for a failed teardown, so
	// that a leak is never silent.
	CleanupErr error
}

// BaseKind says what a writable layer sits on.
type BaseKind string

const (
	// BaseImage: the image layers and the workspace layer.
	BaseImage BaseKind = "image"
	// BaseSnapshot: a snapshot, itself on top of the image or of an earlier
	// snapshot.
	BaseSnapshot BaseKind = "snapshot"
)

// Base names what the writable layer of a sandbox is on top of, and so what
// a diff of that layer is relative to. The zero Base is not valid.
type Base struct {
	Kind BaseKind
	// Snapshot is set with BaseSnapshot, and zero otherwise. A snapshot is
	// named by an identifier of the same kind as a session's, which the
	// backend generates: a client can only send one back through the
	// validating parser of package ids.
	Snapshot ids.ID
}

// ImageBase is the Base of a sandbox with no snapshot under its writable
// layer.
var ImageBase = Base{Kind: BaseImage}

// LayerKind says what a read-only layer of a sandbox is.
type LayerKind string

const (
	// LayerSnapshot is a former writable layer, frozen by Snapshot. Like the
	// writable layer it can hold whiteouts and opaque directories.
	LayerSnapshot LayerKind = "snapshot"
	// LayerWorkspace is the private copy of the project.
	LayerWorkspace LayerKind = "workspace"
	// LayerImage is one layer of the image.
	LayerImage LayerKind = "image"
)

// Layer is one read-only layer of a sandbox.
type Layer struct {
	// Dir is the directory of the layer: an absolute path the backend or the
	// engine made.
	Dir  string
	Kind LayerKind
	// Snapshot is the identifier of the snapshot, for a LayerSnapshot.
	Snapshot ids.ID
}

// LayerView is what a diff needs to find the layers of a sandbox on the
// host. It is only meaningful while nothing is mounted: between commands.
//
// Everything under Upper and under a LayerSnapshot directory was written by
// the sandbox. Whoever walks it, as root, walks a tree that a hostile program
// shaped: it follows no link, trusts no name and bounds its depth and its
// descriptors.
//
// Between two commands the engine may read every layer, change the content of
// the workspace layer, and remove entries from Upper and from the snapshot
// layers (when the project changed on the host at a path the session had
// written, the host's version wins). It adds nothing to Upper or to a
// snapshot, and it renames, adds or removes no layer: Snapshot and Restore
// do.
type LayerView struct {
	// Upper is the directory of the writable layer.
	Upper string
	// Lowers are the read-only layers, topmost first, in the order the
	// overlay resolves a name: the snapshots the writable layer sits on,
	// newest first, then the workspace layer if there is one, then the image
	// layers from top to bottom.
	Lowers []Layer
	// Base is what Upper is relative to.
	Base Base
	// XattrPrefix is the prefix of the extended attributes the overlay uses
	// for its own marks in these layers, such as "trusted.overlay.". A diff
	// honours marks under this prefix and under no other: a mark in another
	// namespace is ordinary data that the sandbox may have written.
	XattrPrefix string
}

// Info describes a backend.
type Info struct {
	// Name is the backend name used in the operator file and in receipts:
	// "native" or "gvisor".
	Name string
	// Isolation names the mechanism in a few words.
	Isolation string
	// Version is the release of the external runtime the backend wraps, and
	// empty when it wraps none.
	Version string
	// Scope is what the counters of this backend's results cover.
	Scope Scope
}

// Backend starts sandboxes. It is safe for concurrent use.
type Backend interface {
	// Info describes the backend. It does not touch the host.
	Info() Info
	// Capabilities reports what the backend enforces on the host that report
	// describes. It is a pure function of the report and of how the backend
	// was configured: it runs nothing and touches nothing. The engine runs
	// the probe once and asks every enabled backend with the same report, so
	// that the policy check, the doctor command and the start of a session
	// cannot disagree.
	Capabilities(report hostprobe.Report) Capabilities
	// Start creates a sandbox for spec and returns it at rest: what is cheap
	// to keep for the session exists inside spec.Dir, and nothing that has
	// to be taken down after a command does. No process runs.
	//
	// Start first calls spec.Validate and refuses, with its error, a spec
	// that is malformed. It then refuses, with ErrUnsupported, a spec it
	// cannot honour in full. When it fails it leaves nothing behind outside
	// spec.Dir. After a successful Start the caller must call Stop.
	Start(ctx context.Context, spec Spec) (Sandbox, error)
}

// Sandbox is one session of a backend. Exec, Snapshot, Restore and Layers
// exclude one another: a sandbox does one thing at a time and answers
// ErrBusy to a second. Stop may be called at any time, from any goroutine.
type Sandbox interface {
	// ID returns the session identifier of the Spec.
	ID() ids.ID

	// Exec runs argv in the sandbox and waits for it to end. It streams the
	// output to the writers of opts while the command runs.
	//
	// The error is not nil only when nothing was attempted: an empty argv,
	// an argument that is not valid UTF-8 or holds a NUL byte, an option the
	// backend refuses (ErrUnsupported), a stopped sandbox (ErrStopped) or a
	// running command (ErrBusy). Once the backend has begun to set the
	// command up, every way it can end is a Result with a nil error, set-up
	// failures included, so that there is always something to record.
	//
	// When ctx is cancelled the command is killed and the result says
	// KillCancelled. Exec returns only when every process of the command is
	// gone and everything built for it has been taken down, or CleanupErr
	// says what could not be.
	Exec(ctx context.Context, argv []string, opts ExecOptions) (Result, error)

	// Stop ends the session. If a command is running it is killed, its Exec
	// returns a result that says KillStopped, and Stop waits for that. Then
	// everything the session holds in the kernel is released: its cgroup,
	// any mount kept for it, what an external runtime holds. The content of
	// Spec.Dir stays for the engine to remove.
	//
	// Stop is idempotent. When a release fails it returns the error and
	// leaves the rest in a state where calling it again tries again. ctx
	// bounds the wait, not the duty: a Stop that gave up can be repeated.
	Stop(ctx context.Context) error

	// Snapshot freezes the writable layer and starts an empty one on top of
	// it. The new snapshot becomes the Base, and its identifier is returned.
	Snapshot(ctx context.Context) (ids.ID, error)
	// Restore discards the writable layer and starts an empty one on top of
	// to: ImageBase, or a snapshot of this sandbox. Snapshots taken after
	// that one are kept. ErrUnknownSnapshot is returned for any other.
	Restore(ctx context.Context, to Base) error

	// Layers returns where the layers are. See LayerView for what the engine
	// may do with them between two commands.
	Layers() (LayerView, error)
}
