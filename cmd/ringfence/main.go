// Command ringfence runs commands in isolated sandboxes, signs a receipt for
// each run, and measures the isolation with an escape test suite.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/camilbenameur/ringfence/backend/native"
)

var version = "dev"

func main() {
	// The sandbox init is this same binary, re-executed inside the new
	// namespaces. It must take over before anything else runs.
	if len(os.Args) > 1 && os.Args[1] == native.InitArg {
		native.Init()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

const usageText = `usage: ringfence <command> [flags]

commands:
  run      run a command in a sandbox and write a signed receipt
  pull     pull an image into the local store
  verify   check a receipt's signature and print it
  replay   run a receipt's command again and compare the results
  escape   run the escape test suite on one or more backends
  bench    measure start time, snapshot time and overhead
  eval-agent  ask a model to escape, k times, with a hard budget (throwaway CI only)
  mcp      serve the sandbox to agents over MCP (stdio)
  keygen   create the receipt signing key
  caps     print what a backend can enforce on this host
  check    validate a policy file against a backend
  version  print the version

Environment: RINGFENCE_HOME (default /var/lib/ringfence) holds images,
the signing key and receipts. Most commands need root.
`

type usageError struct{ error }

type command func(ctx context.Context, args []string, stdout io.Writer) error

func commands() map[string]command {
	return map[string]command{
		"run":        cmdRun,
		"pull":       cmdPull,
		"verify":     cmdVerify,
		"replay":     cmdReplay,
		"escape":     cmdEscape,
		"bench":      cmdBench,
		"eval-agent": cmdEvalAgent,
		"mcp":        cmdMCP,
		"keygen":     cmdKeygen,
		"caps":       cmdCaps,
		"check":      cmdCheck,
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
		fmt.Fprintf(stderr, "ringfence: unknown command %q\n%s", args[0], usageText)
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
	fmt.Fprintln(stderr, "ringfence:", err)
	var u usageError
	if errors.As(err, &u) {
		return 2
	}
	return 1
}

// exitError carries the sandboxed command's exit code out of "run".
type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }
