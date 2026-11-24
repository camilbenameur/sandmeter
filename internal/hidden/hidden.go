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
// # Tests that need Dispatch
//
// This package imports every package that owns an entry point. A test inside
// one of those packages, or inside a package one of them imports, cannot
// import this package back: Go refuses the cycle. Such a test goes in an
// external test package (package x_test in the same directory), which may
// import both.
package hidden

import (
	"github.com/camilbenameur/sandmeter/internal/backend/native"
	"github.com/camilbenameur/sandmeter/internal/egress"
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

// entryPoints is the table. Keep every entry here, spelled out.
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
	{
		// The init of the first native backend. It serves the sandboxes of
		// today's commands and goes away, with this entry, when the native
		// backend starts its commands through entry.Init and entry.Exec.
		Arg: native.InitArg,
		Doc: "init of a native sandbox as the first backend builds it, started inside the new namespaces: " +
			"builds the root filesystem, drops capabilities, installs the syscall filter and execs the command",
		Run: native.Init,
	},
}

// Dispatch runs the hidden entry point that args selects and does not come
// back from it. With any other command line it returns at once and the
// caller goes on with its ordinary main. Pass os.Args.
//
// Only the first argument selects an entry point, and only by exact match:
// an argument further along the command line is data for a visible command
// and never changes what the binary is.
func Dispatch(args []string) {
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
