package policy

// Backend names, as the operator file lists them and as Capabilities.Backend
// and receipts record them.
const (
	// BackendNative is the backend written on Linux namespaces, cgroups and
	// seccomp. Sandboxes share the kernel of the host.
	BackendNative = "native"
	// BackendGVisor runs commands on gVisor's user-space kernel. It is a
	// preview: off unless the operator lists it.
	BackendGVisor = "gvisor"
)

// ControlID names one control: one thing a backend can enforce around a
// command. The list is closed. The same identifiers are used by the host
// probe (which check backs which control), by the policy check (which key
// needs which control) and by receipts (what was in force).
type ControlID string

// The controls.
const (
	// ControlCPU is the CPU limit of the session (limits.cpu).
	ControlCPU ControlID = "limits.cpu"
	// ControlMemory is the memory limit of the session, with swap refused
	// (limits.memory).
	ControlMemory ControlID = "limits.memory"
	// ControlPIDs is the limit on the number of tasks (limits.pids).
	ControlPIDs ControlID = "limits.pids"
	// ControlWall is the kill of a command that runs longer than limits.wall.
	ControlWall ControlID = "limits.wall"
	// ControlTmpfsUpper is the writable layer on a tmpfs of a fixed size and
	// inode count: storage.upper = "tmpfs" and the quota of limits.disk.
	ControlTmpfsUpper ControlID = "storage.tmpfs"
	// ControlDiskFloor is the free-space guard on the state filesystem: a
	// command does not start under the floor and is killed when the floor is
	// crossed. It is a guard for the host, not a quota for the sandbox, and
	// no policy key asks for it: it is always required.
	ControlDiskFloor ControlID = "storage.floor"
	// ControlNetworkNone is the network namespace with loopback only
	// (network.mode = "none").
	ControlNetworkNone ControlID = "network.none"
	// ControlNetworkProxy is the name-filtering proxy as the only way out
	// (network.mode = "proxy").
	ControlNetworkProxy ControlID = "network.proxy"
	// ControlReadOnlyRoot is the read-only root filesystem
	// (filesystem.read_only_root = true).
	ControlReadOnlyRoot ControlID = "filesystem.read_only_root"
	// ControlSyscallDefault is the allow-list system call filter
	// (syscalls.profile = "default").
	ControlSyscallDefault ControlID = "syscalls.default"
	// ControlSyscallCompat is the deny-list system call filter
	// (syscalls.profile = "compat").
	ControlSyscallCompat ControlID = "syscalls.compat"
	// ControlNoNestedUserns is the refusal of user namespaces created inside
	// the sandbox, which holds whatever the syscall profile, including "off".
	// No policy key asks for it: it is always required.
	ControlNoNestedUserns ControlID = "userns.nested"
	// ControlWorkspace is the import of a project directory as a private
	// copy and the export of what commands changed in it. No policy key asks
	// for it: it is required when a session is started with a project.
	ControlWorkspace ControlID = "workspace"
	// ControlSnapshot is the snapshot and restore of the writable layer. It
	// is required by the snapshot and restore operations only.
	ControlSnapshot ControlID = "snapshot"
)

// Controls is the closed list of controls, in the order they are shown.
var Controls = []ControlID{
	ControlCPU,
	ControlMemory,
	ControlPIDs,
	ControlWall,
	ControlTmpfsUpper,
	ControlDiskFloor,
	ControlNetworkNone,
	ControlNetworkProxy,
	ControlReadOnlyRoot,
	ControlSyscallDefault,
	ControlSyscallCompat,
	ControlNoNestedUserns,
	ControlWorkspace,
	ControlSnapshot,
}

// AlwaysRequired lists the controls every session needs, whatever its policy.
var AlwaysRequired = []ControlID{ControlDiskFloor, ControlNoNestedUserns}

// Control says whether one control is enforced on this host by one backend.
// It is three-valued through Reason: a control that could not be checked is
// not enforced, and the reason says that it could not be checked.
type Control struct {
	// Enforced is true only if the backend enforces the control here: the
	// real operation was tried by the host probe and worked. It is never
	// true because a version number looks right.
	Enforced bool `json:"enforced"`
	// Reason says, in one sentence, why the control is not enforced. It is
	// empty when Enforced is true.
	Reason string `json:"reason,omitempty"`
}

// Problem is one fact about the host that keeps a backend from running at
// all, whatever the policy: not root, no cgroup v2, a kernel under the floor,
// an id range that overlaps another user's.
type Problem struct {
	// ID is the identifier of the host check that found the problem.
	ID string `json:"id"`
	// Detail says what was found.
	Detail string `json:"detail"`
	// Fix says what to do about it, when something can be done.
	Fix string `json:"fix,omitempty"`
}

// Capabilities is what one backend can enforce on this host: the input of the
// policy check. A backend builds it from the report of the host probe; no
// value in it may come from a constant in the backend's code, because the
// promise to refuse an unenforceable policy is only as true as this struct.
//
// The policy check, the doctor command, the start of a session and the MCP
// server all read the same Capabilities for a given backend and host.
type Capabilities struct {
	// Backend is the backend name: "native" or "gvisor".
	Backend string `json:"backend"`
	// Controls holds the state of every control. A control that is missing
	// from the map is not enforced: read the map through Control, which
	// fails closed.
	Controls map[ControlID]Control `json:"controls"`
	// MinMemoryBytes is the smallest memory limit under which the backend
	// can run a command at all. A policy under it is refused.
	MinMemoryBytes int64 `json:"min_memory_bytes"`
	// MinPIDs is the smallest task limit under which the backend can run a
	// command, not counting what the backend reserves for its own processes.
	MinPIDs int64 `json:"min_pids"`
	// Problems lists what keeps the backend from running here. When it is
	// not empty every policy is refused, with these as the reasons.
	Problems []Problem `json:"problems,omitempty"`
}

// Control returns the state of one control. A control the backend did not
// report is not enforced.
func (c Capabilities) Control(id ControlID) Control {
	if ctl, ok := c.Controls[id]; ok {
		if ctl.Enforced {
			// An enforced control carries no reason, whatever was stored.
			return Control{Enforced: true}
		}
		if ctl.Reason == "" {
			ctl.Reason = "the " + c.backendName() + " backend does not enforce it on this host"
		}
		return ctl
	}
	return Control{Reason: "the " + c.backendName() + " backend did not report it"}
}

// Usable reports whether the backend can run on this host at all.
func (c Capabilities) Usable() bool { return len(c.Problems) == 0 }

func (c Capabilities) backendName() string {
	if c.Backend == "" {
		return "chosen"
	}
	return c.Backend
}

// Requirement is one control a policy needs, with the key that asks for it.
type Requirement struct {
	// Key is the policy key, in dotted form, that makes the control needed.
	// For a control that is always required it is the control's own name.
	Key     string
	Control ControlID
}

// Requires lists the controls n needs from a backend, in the order of the
// keys in the schema, followed by the controls every session needs. A policy
// runs only on a backend that enforces every one of them: this list is what
// "refused before anything runs" is checked against.
//
// A limit that is "unlimited" needs no control. syscalls.profile = "off"
// needs none either.
func (n Normal) Requires() []Requirement {
	var reqs []Requirement
	need := func(key string, id ControlID) {
		reqs = append(reqs, Requirement{Key: key, Control: id})
	}
	if n.Limits.CPUMillis != nil {
		need("limits.cpu", ControlCPU)
	}
	if n.Limits.MemoryBytes != nil {
		need("limits.memory", ControlMemory)
	}
	if n.Limits.PIDs != nil {
		need("limits.pids", ControlPIDs)
	}
	if n.Limits.WallNanos != nil {
		need("limits.wall", ControlWall)
	}
	if n.Limits.DiskBytes != nil {
		need("limits.disk", ControlTmpfsUpper)
	}
	if n.Storage.Upper == UpperTmpfs {
		need("storage.upper", ControlTmpfsUpper)
	}
	switch n.Network.Mode {
	case NetworkProxy:
		need("network.mode", ControlNetworkProxy)
	default:
		// Anything that is not the proxy needs the closed namespace, so that
		// an unknown mode can never be read as "no control needed".
		need("network.mode", ControlNetworkNone)
	}
	if n.Filesystem.ReadOnlyRoot {
		need("filesystem.read_only_root", ControlReadOnlyRoot)
	}
	switch n.Syscalls.Profile {
	case ProfileOff:
	case ProfileCompat:
		need("syscalls.profile", ControlSyscallCompat)
	default:
		need("syscalls.profile", ControlSyscallDefault)
	}
	for _, id := range AlwaysRequired {
		need(string(id), id)
	}
	return reqs
}
