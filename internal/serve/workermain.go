// Package serve is the root side of the control protocol: the small acceptor
// that listens on the service's socket, and the worker that serves one
// connection.
//
// The acceptor holds no session and parses nothing a client sends: for each
// connection it reads the caller's uid from the kernel, applies the
// connection budget and starts one worker. A worker serves exactly one
// connection and at most one session, in a mount namespace and a cgroup of
// its own, and exits when the connection closes; whatever it held goes with
// it.
//
// Only the entry point of the worker is declared so far.
package serve

import "github.com/camilbenameur/sandmeter/internal/hidden/entry"

// WorkerMain is the hidden entry point entry.Worker: the worker of one
// connection. The acceptor of the service starts it for each connection it
// accepts, and root starts it directly, over a socket pair, when it runs a
// command without the service. Both ways it is the same program reading the
// same operator file.
//
// It never returns. It refuses to run without the handshake on its control
// descriptor.
//
// Not built yet: after the handshake it exits with a message.
func WorkerMain() {
	entry.MustAccept(entry.ControlFD, entry.Worker)
	entry.NotBuilt(entry.Worker)
}
