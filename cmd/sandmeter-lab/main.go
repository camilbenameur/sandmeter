// Command sandmeter-lab measures a sandmeter build: the benchmark and the
// agent escape eval. Both start sandboxes themselves and need root, and the
// eval asks a model to attack the host it runs on, so the lab is for
// throwaway machines. It is a binary of its own so that the sandmeter binary
// links no model SDK.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/camilbenameur/sandmeter/internal/hidden"
)

var version = "dev"

func main() {
	// The sandbox init is this same binary, re-executed inside the new
	// namespaces. It must take over before anything else runs.
	hidden.DispatchLegacy(os.Args)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

const usageText = `usage: sandmeter-lab <command> [flags]

commands:
  bench       measure start time, snapshot time and overhead
  eval-agent  ask a model to escape, k times, with a hard budget (throwaway CI only)
  version     print the version

Environment: SANDMETER_HOME (default /var/lib/sandmeter) holds images,
the signing key and receipts, as for sandmeter. Both commands need root.
`

type usageError struct{ error }

type command func(ctx context.Context, args []string, stdout io.Writer) error

func commands() map[string]command {
	return map[string]command{
		"bench":      cmdBench,
		"eval-agent": cmdEvalAgent,
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	switch args[0] {
	case "version":
		fmt.Fprintln(stdout, version)
		return 0
	case "-h", "-help", "--help", "help":
		fmt.Fprint(stdout, usageText)
		return 0
	}
	cmd, ok := commands()[args[0]]
	if !ok {
		fmt.Fprintf(stderr, "sandmeter-lab: unknown command %q\n%s", args[0], usageText)
		return 2
	}
	err := cmd(ctx, args[1:], stdout)
	if err == nil {
		return 0
	}
	var ex exitError
	if errors.As(err, &ex) {
		return ex.code
	}
	fmt.Fprintln(stderr, "sandmeter-lab:", err)
	var u usageError
	if errors.As(err, &u) {
		return 2
	}
	return 1
}

// exitError carries an exit code out of a command without a message: flag
// parsing uses it for -h.
type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }
