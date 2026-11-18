// Package hidden holds the one table of hidden entry points: the first
// command-line arguments that turn a sandmeter binary into something other
// than its command line, such as the init of a sandbox.
//
// A backend gets code of its own inside a new sandbox by re-executing the
// running binary (/proc/self/exe) with such an argument. Every binary that
// can start a sandbox must therefore hand control over before it does
// anything else, and so must every test binary that starts one: Dispatch is
// the first statement of their main or TestMain.
//
// The table is a slice literal in this file, on purpose. Nothing registers
// itself from an init function, so reading this file is enough to know every
// way a binary can be entered besides its documented commands.
package hidden

import (
	"github.com/camilbenameur/sandmeter/internal/backend/native"
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
		Arg: native.InitArg,
		Doc: "init of a native sandbox, started by the native backend inside the new namespaces: " +
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
