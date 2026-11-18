package engine

import (
	"github.com/camilbenameur/sandmeter/internal/prototype/sandbox"
	"github.com/camilbenameur/sandmeter/receipt"
)

// A receipt holds the capabilities, the connections and the counters of a
// run in the frozen shapes of schema v1, which the receipt package declares
// for itself. The functions here turn what a backend reports into those
// shapes. The counters are converted whole in the one place that needs them,
// so that a field added to the backend's type stops the build there.

// capabilitiesV1 gives the capabilities a backend declared the shape a v1
// receipt records them in. It is a copy field by field because the network
// modes have a type of their own on the backend's side.
func capabilitiesV1(c sandbox.Capabilities) receipt.CapabilitiesV1 {
	var networks []string
	if c.Networks != nil {
		// Nil and empty encode differently ("null" and "[]"), and a signed
		// receipt can hold either: keep them apart.
		networks = make([]string, len(c.Networks))
		for i, m := range c.Networks {
			networks[i] = string(m)
		}
	}
	return receipt.CapabilitiesV1{
		Backend:      c.Backend,
		Isolation:    c.Isolation,
		CPULimit:     c.CPULimit,
		MemoryLimit:  c.MemoryLimit,
		PIDsLimit:    c.PIDsLimit,
		WallTimeout:  c.WallTimeout,
		Networks:     networks,
		ReadOnlyRoot: c.ReadOnlyRoot,
		Seccomp:      c.Seccomp,
		DropCaps:     c.DropCaps,
		Snapshot:     c.Snapshot,
		NeedsRoot:    c.NeedsRoot,
		Notes:        c.Notes,
	}
}

// The capabilities a backend declares have exactly the fields listed here, in
// this order and with these types (tags do not count): the conversion below
// does not compile otherwise.
//
// A keyed literal alone does not notice a new field. It would compile, and
// the control would silently be absent from every receipt that is signed.
// When this stops compiling, decide in capabilitiesV1 what a v1 receipt holds
// for the new shape, then bring the list in line.
var _ = struct {
	Backend      string
	Isolation    string
	CPULimit     bool
	MemoryLimit  bool
	PIDsLimit    bool
	WallTimeout  bool
	Networks     []sandbox.NetworkMode
	ReadOnlyRoot bool
	Seccomp      bool
	DropCaps     bool
	Snapshot     bool
	NeedsRoot    bool
	Notes        []string
}(sandbox.Capabilities{})

// connectionsV1 gives the flows a backend saw the shape a v1 receipt records
// them in. The result is never nil: a receipt lists its connections as an
// empty list, not as null, when there were none.
func connectionsV1(conns []sandbox.Connection) []receipt.ConnectionV1 {
	out := make([]receipt.ConnectionV1, len(conns))
	for i, c := range conns {
		out[i] = receipt.ConnectionV1(c)
	}
	return out
}
