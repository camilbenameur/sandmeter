package policy

import "errors"

// ErrNotBuilt is returned by the functions of this file that are declared but
// not written yet. Each of them fails closed: a policy that goes through one
// is refused, never accepted. Nothing that runs a command calls them today.
// The variable goes away with the last of them.
var ErrNotBuilt = errors.New("policy: not built in this version")

// notBuilt is what a function that returns Violations answers until it is
// written: one violation, so that a caller who only looks at the length of
// the list refuses the policy.
func notBuilt() Violations {
	return Violations{{Key: "policy", Reason: ErrNotBuilt.Error()}}
}

// KeyBackend is the key of a violation that is not about a key of the policy
// file but about the backend chosen to run it: the backend cannot run on this
// host at all (see Resolve).
const KeyBackend = "backend"

// Default returns the built-in default policy, written out: what a session
// gets for every key its policy file leaves out, before the ceiling clamps
// it. It is small enough that a fork bomb or a memory hog does not hurt the
// host, has no network, a read-only root and the strict syscall profile.
func Default() Policy {
	readOnly := true
	return Policy{
		Version: Version2,
		Limits: Limits{
			CPU:    Num(1),
			Memory: "512MiB",
			PIDs:   Num(256),
			Wall:   "60s",
		},
		Storage:    Storage{Upper: UpperDisk},
		Network:    Network{Mode: NetworkNone},
		Filesystem: Filesystem{ReadOnlyRoot: &readOnly},
		Syscalls:   Syscalls{Profile: ProfileDefault},
	}
}

// BuiltinCeiling returns the ceiling in force when the operator file has no
// [ceiling] table, or does not exist: the limits of Default, a disk quota no
// larger than the memory limit that backs it, no network, no passed
// variable, and ProfileCompat as the weakest profile. A field that an
// operator's [ceiling] leaves out takes its value from here.
//
// With this ceiling a client can make its sandbox smaller, and can ask for
// two things the default policy does not give: a writable layer in memory
// under a hard quota, and a writable root filesystem. Neither reaches
// outside the sandbox. What a command writes to a writable root lands in the
// session's own writable layer, exactly as what it writes under /tmp and
// /workspace does with a read-only root: the image is never modified, the
// same quota or free-space guard applies and the diff in the record of every
// command lists it. A read-only root is a default that keeps a command from
// changing the system it runs on by accident; an operator who wants it for
// every session sets read_only_root = true in the [ceiling] table.
func BuiltinCeiling() Ceiling {
	readOnly := false
	return Ceiling{
		Limits: Limits{
			CPU:    Num(1),
			Memory: "512MiB",
			PIDs:   Num(256),
			Wall:   "60s",
			Disk:   "512MiB",
		},
		Storage:    Storage{Upper: UpperTmpfs},
		Network:    Network{Mode: NetworkNone},
		Filesystem: Filesystem{ReadOnlyRoot: &readOnly},
		Syscalls:   Syscalls{Profile: ProfileCompat},
	}
}

// Parse decodes a policy file. It accepts schema v2, and schema v1 mapped as
// the package comment says. An unknown key, a key of the wrong type and a
// version it does not know are errors. Keys the file leaves out stay zero in
// the result: Parse resolves nothing.
//
// Not built yet: it returns ErrNotBuilt.
func Parse(data []byte) (Policy, error) {
	return Policy{}, ErrNotBuilt
}

// Load reads the file at path and parses it with Parse. The path is one the
// calling process chose for itself: the root side receives policy text, never
// a path.
//
// Not built yet: it returns ErrNotBuilt.
func Load(path string) (Policy, error) {
	return Policy{}, ErrNotBuilt
}

// Within reports every key of p that asks for more than c grants, and every
// value of p that is malformed: a size that does not parse, a destination
// that ParseDest refuses, an environment name that ValidEnvName refuses, and
// any limit that is not a positive amount. A limit written as zero or as a
// negative number, and one so small that it would be zero in the unit the
// policy in force holds it in (a cpu value under one thousandth of a core:
// see NormalLimits), is a violation whose reason says to write "unlimited"
// or to leave the key out. A limit that is set never becomes "no limit" on
// its way to the kernel.
//
// The allow list is checked against the ceiling's with Uncovered, list
// against list. Within is a pure function. An empty result means that the
// policy may run under the ceiling; it says nothing about the host (see
// Resolve).
//
// A key that p leaves out is never a violation here: it takes the built-in
// default, lowered to the ceiling, in Resolve.
//
// Not built yet: it refuses every policy.
func Within(p Policy, c Ceiling) Violations {
	return notBuilt()
}

// Resolve resolves p under the ceiling c, for the backend that caps
// describes on this host, into the policy in force. It is the one function
// that decides whether a session may run and under what: the root side calls
// it for every start and for every check, with the Capabilities the backend
// built from the host probe.
//
// It tells apart what the file sets from what it leaves out, which only a
// Policy can show. That difference decides what happens when the backend
// does not enforce a control on this host.
//
// A key the file sets is a demand:
//
//   - malformed, or above what c grants: a violation, the same one Within
//     reports. The violations of Resolve include those of Within(p, c);
//   - in need of a control that caps does not report as enforced: a
//     violation that carries the backend's reason. A setting somebody wrote
//     is never weakened in silence, and never applied in part;
//   - a limit under the backend's minimum (Capabilities.MinCPUMillis,
//     MinMemoryBytes, MinPIDs): a violation of that key.
//
// A key the file leaves out takes the value of Default, lowered to the
// ceiling where the default is above it. Then:
//
//   - a default limit (limits.cpu, limits.memory, limits.pids, limits.wall)
//     that needs a control caps does not report as enforced is not applied.
//     The session runs without that limit: the limit is nil in the Normal,
//     the key is listed in Normal.DefaultsNotApplied, and the second result
//     holds one Unapplied for it with the control and the backend's reason.
//     Nothing was asked for, so nothing is refused; nothing is hidden
//     either, since the policy in force and the record of every command say
//     that the limit is not there;
//   - any other default the backend cannot enforce (the closed network, the
//     read-only root, the syscall profile) is a violation, as if the file
//     had set it. Such a protection has no weaker form to fall back on that
//     a ceiling would grant without being asked;
//   - a default limit that, once lowered to the ceiling, is under the
//     backend's minimum is a violation of that key: the ceiling leaves no
//     value the backend can run under.
//
// The controls every session needs (AlwaysRequired) are checked as demands.
// A backend that cannot run at all (caps.Usable is false) refuses every
// policy: each of its problems is a violation with the key KeyBackend. A
// caller that wants to answer "this host cannot run the backend" apart from
// "this policy is refused" asks caps.Usable first.
//
// In the Normal, sizes are bytes, durations nanoseconds, and the allow list
// is parsed, de-duplicated and sorted. It is meaningful only when the
// Violations are empty.
//
// Properties to hold when the Violations are empty:
//
//   - every field of the Normal is at or under the corresponding field of
//     c, except the limits listed in DefaultsNotApplied, which are nil;
//   - caps reports as enforced every control of the Normal's Requires, and
//     reports as not enforced the control of every Unapplied;
//   - the Unapplied list and DefaultsNotApplied name the same keys, in the
//     same order;
//   - a limit that is not nil is at least 1.
//
// Not built yet: it refuses every policy.
func Resolve(p Policy, c Ceiling, caps Capabilities) (Normal, []Unapplied, Violations) {
	return Normal{}, nil, notBuilt()
}

// Hash returns the hash of the ceiling that a receipt records: the lower-case
// hexadecimal SHA-256 of the canonical encoding of c with every field
// resolved (built-in values filled in, sizes in bytes, durations in
// nanoseconds, destinations sorted), so that two operator files that grant
// the same things have the same hash.
//
// Not built yet: it returns ErrNotBuilt.
func (c Ceiling) Hash() (string, error) {
	return "", ErrNotBuilt
}
