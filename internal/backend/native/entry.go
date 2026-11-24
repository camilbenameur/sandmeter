//go:build linux

package native

import "github.com/camilbenameur/sandmeter/internal/hidden/entry"

// InitMain is the hidden entry point entry.Init: the first stage of the
// init of a native sandbox, which stays process 1 of the sandbox's pid
// namespace for the life of one command. It builds the root filesystem,
// starts the second stage, gives up its privileges, reaps, and ends the
// whole sandbox the moment its supervisor on the host goes away.
//
// It never returns. It refuses to run without the handshake on its control
// descriptor.
//
// Not built yet: after the handshake it exits with a message. The init that
// runs today's sandboxes is Init, selected by InitArg.
func InitMain() {
	entry.MustAccept(entry.ControlFD, entry.Init)
	entry.NotBuilt(entry.Init)
}

// ExecMain is the hidden entry point entry.Exec: the second stage, started
// by the first inside the finished sandbox. It drops the capabilities the
// command must not have, forbids new privileges, installs the syscall filter
// and executes the command; a command that cannot be started is reported as
// such, with the status a shell would give.
//
// It never returns. It refuses to run without the handshake on its control
// descriptor.
//
// Not built yet: after the handshake it exits with a message.
func ExecMain() {
	entry.MustAccept(entry.ControlFD, entry.Exec)
	entry.NotBuilt(entry.Exec)
}
