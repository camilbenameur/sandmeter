// Package hostprobe says what this host can do for a sandbox, by trying it.
//
// One probe feeds everything that needs to know: the policy check, the doctor
// command, the start of a session and the MCP server all read the same
// Report. No part of sandmeter decides that a control is enforced from a
// constant, a version number alone or a guess: a control is enforced when
// every check that backs it answered yes on this host, and not otherwise.
//
// This file is the contract: the checks that exist, the control each one
// backs, the shape of a report and how a report is read. The code that runs
// the checks lives beside it.
//
// # Reading a report
//
// A check has three outcomes. Yes means the operation was tried, or the fact
// was read, and it holds. No means it does not. Unknown means the check could
// not tell: it needs a privilege the probing process lacks, it ran out of
// time, the file it reads is missing. Unknown is never rounded up: wherever a
// decision is taken, unknown counts as no, and the reason says "could not be
// verified".
//
// The table Checks gives each check a role:
//
//   - a required check must say yes for a backend to run at all; when it
//     does not, the backend has a Problem and every policy is refused;
//   - a check that backs controls must say yes for each of those controls to
//     be enforced; when it does not, only the policies that need one of them
//     are refused;
//   - a check that is neither is advisory: the doctor command shows it, and
//     nothing is refused because of it.
//
// A report holds no path chosen by a client and nothing secret: it is sent
// to unprivileged clients as it is.
package hostprobe

import (
	"fmt"

	"github.com/camilbenameur/sandmeter/policy"
)

// Outcome is the answer of one check.
type Outcome string

const (
	// Yes: the operation was tried, or the fact was read, and it holds.
	Yes Outcome = "yes"
	// No: it does not hold on this host.
	No Outcome = "no"
	// Unknown: the check could not tell. It counts as No wherever something
	// is decided.
	Unknown Outcome = "unknown"
)

// CheckID names one check. The list is closed: see Checks.
type CheckID string

// The checks.
const (
	// CheckPrivilege: the probing process is root. Mounts, cgroups and
	// namespaces need it, and so do the checks that try them.
	CheckPrivilege CheckID = "privilege"
	// CheckKernel: the kernel release is at or above the floor (6.1). The
	// detail says "untested kernel" for a release that the project's
	// continuous integration did not run.
	CheckKernel CheckID = "kernel"
	// CheckInstall: the running executable and every directory above it are
	// owned by root and not writable by group or others. The sandbox's first
	// process is this executable. The home and state directories, when they
	// exist, and every directory above them, are owned by root and not
	// writable by group or others either; the home and the state directory
	// themselves give the group and others nothing at all (the mode package
	// layout prescribes): what they hold includes files owned by the ids of
	// sandboxes, set-user-ID bits included, which no other user may reach.
	CheckInstall CheckID = "install"
	// CheckCgroupV2: the unified cgroup hierarchy is mounted and the cgroup
	// the service was given can hold a subtree. Commands are killed through
	// it, never by signalling a recorded pid.
	CheckCgroupV2 CheckID = "cgroup.v2"
	// CheckCgroupCPU, CheckCgroupMemory and CheckCgroupPIDs: the controller
	// is available to that subtree. All three are required: the default
	// policy bounds processor time, memory and the number of tasks, and a
	// default limit that cannot be enforced is left out of a session rather
	// than refused (policy.Resolve). Were a missing controller only a
	// control that is not enforced, a host without it would run every
	// default session unbounded. It is a host that cannot run the backend,
	// and the report says which controller to enable.
	CheckCgroupCPU    CheckID = "cgroup.cpu"
	CheckCgroupMemory CheckID = "cgroup.memory"
	CheckCgroupPIDs   CheckID = "cgroup.pids"
	// CheckCgroupSwap: swap can be refused to a group (memory.swap.max
	// exists), or the host has no swap. Without it a memory limit does not
	// bound what a sandbox can push out to swap.
	CheckCgroupSwap CheckID = "cgroup.swap"
	// CheckCgroupCounters: the kernel provides memory.peak and pids.peak.
	// Without them the counters of a receipt are null; nothing is refused.
	CheckCgroupCounters CheckID = "cgroup.counters"
	// CheckNamespaces: user namespaces can be created
	// (user.max_user_namespaces is above zero). Every sandbox is one.
	CheckNamespaces CheckID = "namespaces"
	// CheckUsernsLimit: a sandbox can be kept from creating user namespaces
	// of its own, by the mechanism the native backend uses, tried here in a
	// throwaway child. In a new user namespace, with a procfs the child
	// mounted itself and checked to be one, the child writes 0 to
	// user.max_user_namespaces through that procfs and reads it back; it
	// then tries to create a user namespace, which must fail; and it tries
	// to write a larger value back, which must fail too. The answer is yes
	// only when the three did what is expected. Nothing of the host is
	// touched: the setting written is that of the child's own namespace.
	//
	// That user namespaces can be created says nothing about whether their
	// creation can be bounded from inside one: only the trial does. The
	// check concerns the native backend, whose sandboxes run on the host's
	// kernel. A user namespace created inside a gVisor sandbox is one of
	// gVisor's kernel, not of the host's.
	CheckUsernsLimit CheckID = "userns.limit"
	// CheckIDRange: the ids given to sandboxes, and the service ids just
	// above them, overlap no entry of /etc/subuid or /etc/subgid and no
	// account of the host.
	CheckIDRange CheckID = "ids.range"
	// CheckStateSpace: the filesystem of the state directory has more free
	// bytes and inodes than the operator's floor.
	CheckStateSpace CheckID = "state.space"
	// CheckOverlay: an overlay with the pinned options mounts on the state
	// filesystem, and the kernel reports those options back.
	CheckOverlay CheckID = "state.overlay"
	// CheckTmpfsUpper: an overlay whose writable layer is a size-capped tmpfs
	// mounts and takes a write and a deletion.
	CheckTmpfsUpper CheckID = "state.tmpfs-upper"
	// CheckSeccomp: the kernel takes a seccomp filter with the actions the
	// profiles use.
	CheckSeccomp CheckID = "seccomp"
	// CheckProxyListener: a listener created on the loopback of a sandbox's
	// network namespace can be served from the host side, and the service ids
	// that serve it are free. It backs the egress proxy of the native
	// backend.
	CheckProxyListener CheckID = "network.listener"
	// CheckRunsc: the runsc binary is at an absolute path owned by root, not
	// writable by others, and its release is at or above the minimum. It
	// concerns the gVisor backend only.
	CheckRunsc CheckID = "gvisor.runsc"
	// CheckLSM: which Linux security modules are in force. Advisory: the
	// detail names them, and says so when the host runs a configuration the
	// project never ran under.
	CheckLSM CheckID = "lsm"
	// CheckCorePattern: whether kernel.core_pattern pipes crashes to a
	// handler, which then runs on the host when a sandboxed process crashes.
	// Advisory: sandboxes set a core limit that keeps the handler from
	// starting.
	CheckCorePattern CheckID = "core-pattern"
)

// Spec is the fixed description of one check.
type Spec struct {
	ID CheckID
	// Title says in a few words what the check establishes.
	Title string
	// Backs lists the controls that are enforced only if this check says
	// yes.
	Backs []policy.ControlID
	// Required is true when no backend the check concerns can run unless it
	// says yes.
	Required bool
	// Backend is the one backend the check concerns, or empty when it
	// concerns every backend.
	Backend string
}

// Advisory reports whether nothing is ever refused because of the check.
func (s Spec) Advisory() bool { return !s.Required && len(s.Backs) == 0 }

// Concerns reports whether the check has a say about the named backend.
func (s Spec) Concerns(backend string) bool { return s.Backend == "" || s.Backend == backend }

// Checks is the closed list of checks, in the order a report holds them and
// the doctor command shows them.
var Checks = []Spec{
	{ID: CheckPrivilege, Title: "the service runs as root", Required: true},
	{ID: CheckKernel, Title: "kernel release", Required: true},
	{ID: CheckInstall, Title: "the installed files belong to root", Required: true},
	{ID: CheckCgroupV2, Title: "cgroup v2 subtree", Required: true, Backs: []policy.ControlID{policy.ControlWall}},
	{ID: CheckCgroupCPU, Title: "cpu controller", Required: true, Backs: []policy.ControlID{policy.ControlCPU}},
	{ID: CheckCgroupMemory, Title: "memory controller", Required: true, Backs: []policy.ControlID{policy.ControlMemory}},
	{ID: CheckCgroupSwap, Title: "swap can be refused", Backs: []policy.ControlID{policy.ControlMemory}},
	{ID: CheckCgroupPIDs, Title: "pids controller", Required: true, Backs: []policy.ControlID{policy.ControlPIDs}},
	{ID: CheckCgroupCounters, Title: "peak counters"},
	{ID: CheckNamespaces, Title: "user namespaces", Required: true, Backs: []policy.ControlID{policy.ControlNetworkNone, policy.ControlNoNestedUserns}},
	{ID: CheckUsernsLimit, Title: "nested user namespaces can be refused", Required: true, Backs: []policy.ControlID{policy.ControlNoNestedUserns}, Backend: policy.BackendNative},
	{ID: CheckIDRange, Title: "sandbox id range is free", Required: true},
	{ID: CheckStateSpace, Title: "free space on the state filesystem", Required: true, Backs: []policy.ControlID{policy.ControlDiskFloor}},
	{ID: CheckOverlay, Title: "overlay on the state filesystem", Required: true, Backs: []policy.ControlID{policy.ControlReadOnlyRoot, policy.ControlWorkspace, policy.ControlSnapshot}},
	{ID: CheckTmpfsUpper, Title: "tmpfs writable layer", Backs: []policy.ControlID{policy.ControlTmpfsUpper}},
	{ID: CheckSeccomp, Title: "seccomp filter", Backs: []policy.ControlID{policy.ControlSyscallDefault, policy.ControlSyscallCompat}},
	{ID: CheckProxyListener, Title: "egress proxy listener", Backs: []policy.ControlID{policy.ControlNetworkProxy}, Backend: policy.BackendNative},
	{ID: CheckRunsc, Title: "runsc binary and release", Required: true, Backend: policy.BackendGVisor},
	{ID: CheckLSM, Title: "security modules"},
	{ID: CheckCorePattern, Title: "core dump handler"},
}

// SpecOf returns the description of a check, and false for an identifier
// that is not in Checks.
func SpecOf(id CheckID) (Spec, bool) {
	for _, s := range Checks {
		if s.ID == id {
			return s, true
		}
	}
	return Spec{}, false
}

// Check is the result of one check on one host.
type Check struct {
	ID      CheckID `json:"id"`
	Outcome Outcome `json:"outcome"`
	// Detail says what was found, in one sentence: the release, the missing
	// controller, the overlapping entry, the errno. With Unknown it says why
	// the check could not tell.
	Detail string `json:"detail"`
	// Fix says what the operator can do when the outcome is not Yes, as one
	// line; empty when nothing can be done or nothing needs to be.
	Fix string `json:"fix,omitempty"`
}

// Report is the result of one run of the probe: every check of Checks, once,
// in that order. It is a plain value. The zero Report holds no check and
// reads as "nothing could be verified".
type Report struct {
	// Kernel is the kernel release the probe saw, for display.
	Kernel string `json:"kernel"`
	// Checks holds one Check per entry of the table Checks, in its order.
	Checks []Check `json:"checks"`
}

// Blank returns a report in which no check has run: every check is Unknown.
// The probe starts from it and fills in what it finds, so that a check it
// forgets, or that panics, stays visible as unknown.
func Blank() Report {
	r := Report{Checks: make([]Check, len(Checks))}
	for i, s := range Checks {
		r.Checks[i] = Check{ID: s.ID, Outcome: Unknown, Detail: "the check did not run"}
	}
	return r
}

// Set records the result of one check in a report made by Blank. It panics
// on an identifier that is not in Checks: that is a programming error, never
// input.
func (r *Report) Set(c Check) {
	for i := range r.Checks {
		if r.Checks[i].ID == c.ID {
			r.Checks[i] = c
			return
		}
	}
	panic("hostprobe: no check " + string(c.ID) + " in this report")
}

// Validate reports whether r holds exactly the checks of the table Checks,
// in order, each with a known outcome. A report that crossed a process
// boundary is validated before it is read.
func (r Report) Validate() error {
	if len(r.Checks) != len(Checks) {
		return fmt.Errorf("host report: %d checks, want %d", len(r.Checks), len(Checks))
	}
	for i, s := range Checks {
		c := r.Checks[i]
		if c.ID != s.ID {
			return fmt.Errorf("host report: check %d is %q, want %q", i, c.ID, s.ID)
		}
		switch c.Outcome {
		case Yes, No, Unknown:
		default:
			return fmt.Errorf("host report: check %q has the outcome %q", c.ID, c.Outcome)
		}
	}
	return nil
}

// Lookup returns the result of one check. A check the report does not hold
// is Unknown.
func (r Report) Lookup(id CheckID) Check {
	for _, c := range r.Checks {
		if c.ID == id {
			return c
		}
	}
	return Check{ID: id, Outcome: Unknown, Detail: "the report does not hold this check"}
}

// reason turns a check that did not say yes into a sentence.
func reason(c Check) string {
	detail := c.Detail
	if detail == "" {
		detail = "check " + string(c.ID)
	}
	if c.Outcome == No {
		return detail
	}
	return "could not be verified: " + detail
}

// Control says whether the host lets the named backend enforce one control:
// yes only if every check that backs the control for that backend said yes.
// The reason is that of the first check, in the order of Checks, that did
// not. A control that no check backs for that backend is not enforced: an
// answer is never yes for want of a question.
//
// This is the host's side of the answer. A backend that does not offer a
// control withdraws it afterwards, with its own reason; it never turns a no
// from here into a yes.
func (r Report) Control(id policy.ControlID, backend string) policy.Control {
	backed := false
	for _, s := range Checks {
		if !s.Concerns(backend) || !backs(s, id) {
			continue
		}
		backed = true
		if c := r.Lookup(s.ID); c.Outcome != Yes {
			return policy.Control{Reason: reason(c)}
		}
	}
	if !backed {
		return policy.Control{Reason: "no host check backs it for the " + backend + " backend"}
	}
	return policy.Control{Enforced: true}
}

func backs(s Spec, id policy.ControlID) bool {
	for _, b := range s.Backs {
		if b == id {
			return true
		}
	}
	return false
}

// Problems lists what keeps the named backend from running on this host at
// all: every required check that concerns it and did not say yes, in the
// order of Checks.
func (r Report) Problems(backend string) []policy.Problem {
	var ps []policy.Problem
	for _, s := range Checks {
		if !s.Required || !s.Concerns(backend) {
			continue
		}
		if c := r.Lookup(s.ID); c.Outcome != Yes {
			ps = append(ps, policy.Problem{ID: string(s.ID), Detail: reason(c), Fix: c.Fix})
		}
	}
	return ps
}

// Warnings lists the advisory checks that did not say yes, for display.
func (r Report) Warnings() []Check {
	var ws []Check
	for _, s := range Checks {
		if !s.Advisory() {
			continue
		}
		if c := r.Lookup(s.ID); c.Outcome != Yes {
			ws = append(ws, c)
		}
	}
	return ws
}

// Capabilities returns what the host lets the named backend enforce: the
// state of every control of policy.Controls and the problems of the backend.
// It is where a backend starts from. The backend then sets its minimums and
// withdraws, with a reason, each control it does not offer; it adds nothing.
func (r Report) Capabilities(backend string) policy.Capabilities {
	caps := policy.Capabilities{
		Backend:  backend,
		Controls: make(map[policy.ControlID]policy.Control, len(policy.Controls)),
		Problems: r.Problems(backend),
	}
	for _, id := range policy.Controls {
		caps.Controls[id] = r.Control(id, backend)
	}
	return caps
}
