package image

import "github.com/camilbenameur/sandmeter/internal/hidden/entry"

// FetchMain is the hidden entry point entry.Fetch: the process that talks to
// a registry and decompresses what it answers. Those are the bytes of a
// stranger, so the work is done here, without privilege and under an id of
// its own, and never in a root process: the entry point refuses to run as
// root. What it fetched goes back to its parent as a stream.
//
// It never returns. It refuses to run without the handshake on its control
// descriptor.
//
// Not built yet: after the handshake it exits with a message.
func FetchMain() {
	entry.MustAccept(entry.ControlFD, entry.Fetch)
	entry.NotBuilt(entry.Fetch)
}
