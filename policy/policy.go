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
// variable, a read-only root, and ProfileCompat as the weakest profile. A
// field that an operator's [ceiling] leaves out takes its value from here.
//
// With this ceiling a client can make its sandbox smaller and nothing else.
func BuiltinCeiling() Ceiling {
	readOnly := true
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
// value of p that is malformed (a size that does not parse, a destination
// that ParseDest refuses, a negative limit). It is a pure function. An empty
// result means that the policy may run under the ceiling; it says nothing yet
// about the host (see Check).
//
// A key that p leaves out is never a violation: it takes the built-in
// default, clamped to the ceiling, in Effective.
//
// Not built yet: it refuses every policy.
func Within(p Policy, c Ceiling) Violations {
	return notBuilt()
}

// Effective resolves p under c into the policy in force: every key that p
// leaves out takes its value from Default, lowered to the ceiling where the
// default is above it; sizes become bytes, durations nanoseconds, and the
// allow list is parsed, de-duplicated and sorted. The result is only
// meaningful when the Violations are empty, and they are empty exactly when
// Within(p, c) is.
//
// Property to hold: when the Violations are empty, every field of the Normal
// is at or under the corresponding field of c.
//
// Not built yet: it refuses every policy.
func Effective(p Policy, c Ceiling) (Normal, Violations) {
	return Normal{}, notBuilt()
}

// Check reports why n cannot run on the backend that caps describes: every
// control of n.Requires that the backend does not enforce on this host, with
// the backend's reason; every limit under the backend's minimum; and, when
// the backend cannot run at all, each of its problems. An empty result means
// that everything the policy asks for will be enforced.
//
// Not built yet: it refuses every policy.
func Check(n Normal, caps Capabilities) Violations {
	return notBuilt()
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
