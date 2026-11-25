package main

import (
	"os"

	"github.com/camilbenameur/sandmeter/internal/hidden"
)

// dispatchHidden hands the process over to a hidden entry point when the
// command line selects one, and returns otherwise. It dispatches the table
// in which every entry point begins with the handshake, and never the one
// that also holds the init of the first backend.
//
// Invariant: it is the first statement of main, before a flag is parsed, a
// file is opened or a goroutine is started. This binary is what the root
// side re-executes as the first process of a sandbox, as the worker of a
// connection, as the egress proxy and as the image fetcher: a process
// started for one of those jobs must never run a line of the ordinary
// command line, which would treat the descriptors and the privileges
// prepared for that job as its own. A test of this package reads main and
// fails if anything comes before this call.
func dispatchHidden() {
	hidden.Dispatch(os.Args)
}
