// Command sandmeterd is the root side of sandmeter: the service that
// unprivileged sandmeter clients reach through a Unix socket, the operator's
// commands, and the hidden entry points that the root side re-executes
// itself as (see package hidden).
//
// It links neither the MCP SDK nor a model SDK: nothing that parses what an
// agent or a model wrote runs as root. A test of the import graph holds that.
//
// The service and the operator's commands are not built yet: this file is
// the skeleton they replace. Today the binary answers to the hidden entry
// points only.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/camilbenameur/sandmeter/internal/exit"
)

func main() {
	dispatchHidden()
	os.Exit(run(os.Args[1:], os.Stderr))
}

// run is the visible command line.
func run(args []string, stderr io.Writer) int {
	fmt.Fprintln(stderr, "sandmeterd: the root service is not built in this version")
	return exit.Failure
}
