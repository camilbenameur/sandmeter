// Package hidden holds the one table of hidden entry points: the first
// command-line arguments that turn a binary of the root side into something
// other than its command line, such as the first process of a sandbox or the
// worker of a connection.
//
// The root side gets code of its own into a new sandbox, or into a process
// with fewer privileges, by re-executing the running binary
// (/proc/self/exe) with such an argument. Every binary that can start a
// sandbox must therefore hand control over before it does anything else, and
// so must every test binary that starts one: Dispatch is the first statement
// of their main or TestMain.
//
// The table is a slice literal in this file, on purpose. Nothing registers
// itself from an init function, so reading this file is enough to know every
// way a binary can be entered besides its documented commands. Each entry
// calls one exported function of the package that owns the entry point, and
// each of those functions starts with the handshake of package entry: an
// entry point that is not started by sandmeter itself exits at once.
//
// One entry point is older than the handshake: the init of the first native
// backend, which today's commands still start. It is not in the table. It
// has a table of its own, which only the binaries that still run the first
// backend dispatch (DispatchLegacy), and the root service is not one of
// them: no argument makes sandmeterd read a sandbox configuration from a
// descriptor without a handshake. Until that init is deleted, this package
// checks for it what it does not check itself, that its configuration
// arrives on a pipe.
//
// # Tests that need Dispatch
//
// This package imports every package that owns an entry point. A test inside
// one of those packages, or inside a package one of them imports, cannot
// import this package back: Go refuses the cycle. Such a test goes in an
// external test package (package x_test in the same directory), which may
// import both.
package hidden

import (
	"fmt"
	"os"

	"github.com/camilbenameur/sandmeter/internal/backend/native"
	"github.com/camilbenameur/sandmeter/internal/egress"
	"github.com/camilbenameur/sandmeter/internal/exit"
	"github.com/camilbenameur/sandmeter/internal/hidden/entry"
	"github.com/camilbenameur/sandmeter/internal/image"
	"github.com/camilbenameur/sandmeter/internal/serve"
)

// EntryPoint is one hidden way into a binary.
type EntryPoint struct {
	// Arg is the first command-line argument that selects the entry point.
	Arg string
	// Doc says in one line what runs there and who starts it.
	Doc string
	// Run takes over the process. It must not return: it ends by replacing
	// the process image or by exiting.
	Run func()
}

// entryPoints is the table. Keep every entry here, spelled out. Every Run in
// it begins with the handshake.
var entryPoints = []EntryPoint{
	{
		Arg: entry.Worker,
		Doc: "worker of one client connection, started as root by the service for each connection it accepts, " +
			"or by root itself in direct mode: serves the control protocol and holds at most one session",
		Run: serve.WorkerMain,
	},
	{
		Arg: entry.Init,
		Doc: "first stage of the init of a native sandbox, started by the native backend inside the new namespaces: " +
			"builds the root filesystem, starts the second stage, drops its privileges and stays process 1 for the life of the command",
		Run: native.InitMain,
	},
	{
		Arg: entry.Exec,
		Doc: "second stage of the init, started by the first inside the finished sandbox: " +
			"drops capabilities, installs the syscall filter and executes the command",
		Run: native.ExecMain,
	},
	{
		Arg: entry.Egress,
		Doc: "egress proxy of one command, started by the native backend without privilege under an id of its own: " +
			"serves the listener on the sandbox's loopback and forwards only to the destinations the policy lists",
		Run: egress.Main,
	},
	{
		Arg: entry.Fetch,
		Doc: "image fetcher, started without privilege under an id of its own: " +
			"talks to the registry and decompresses layers so that no root process parses what a registry sent",
		Run: image.FetchMain,
	},
}

// legacyConfigFD is the descriptor on which the init of the first native
// backend reads its configuration.
const legacyConfigFD = 3

// legacyEntryPoints holds the one entry point that has no handshake. It
// serves the sandboxes of today's commands and goes away, with this table
// and DispatchLegacy, when the native backend starts its commands through
// entry.Init and entry.Exec.
var legacyEntryPoints = []EntryPoint{
	{
		Arg: native.InitArg,
		Doc: "init of a native sandbox as the first backend builds it, started inside the new namespaces: " +
			"builds the root filesystem, drops capabilities, installs the syscall filter and execs the command",
		Run: func() {
			// Invariant: this init takes a root filesystem, a host name and a
			// command from its configuration, and acts on them. It must not
			// take them from a file somebody redirected onto the descriptor:
			// its backend hands it a pipe, and anything else is refused here,
			// before a byte is read.
			if err := entry.CheckChannel(legacyConfigFD); err != nil {
				fmt.Fprintf(os.Stderr, "sandmeter: %s: %v: %v\n%s is an internal entry point: sandmeter starts it itself, and it does nothing when it is started any other way.\n",
					native.InitArg, entry.ErrRefused, err, native.InitArg)
				os.Exit(exit.Failure)
			}
			native.Init()
		},
	},
}

// Dispatch runs the hidden entry point that args selects and does not come
// back from it. With any other command line it returns at once and the
// caller goes on with its ordinary main. Pass os.Args.
//
// Only the first argument selects an entry point, and only by exact match:
// an argument further along the command line is data for a visible command
// and never changes what the binary is.
//
// This is the table of the root service: every entry point it reaches
// begins with the handshake.
func Dispatch(args []string) {
	dispatch(entryPoints, args)
}

// DispatchLegacy is Dispatch for the binaries that still run sandboxes with
// the first native backend, in their own process: it also answers to that
// backend's init. The root service never calls it. It goes away with the
// first backend.
func DispatchLegacy(args []string) {
	dispatch(legacyEntryPoints, args)
	dispatch(entryPoints, args)
}

func dispatch(table []EntryPoint, args []string) {
	if len(args) < 2 {
		return
	}
	for _, e := range table {
		if args[1] != e.Arg {
			continue
		}
		e.Run()
		// Invariant: a process entered through a hidden entry point never
		// reaches the ordinary command line. It was started with the
		// descriptors, the environment and the privileges of that entry
		// point; parsing its arguments as a user command would run the wrong
		// program with them. An entry point that returns is a bug, and the
		// process stops here.
		panic("hidden: entry point " + e.Arg + " returned")
	}
}
