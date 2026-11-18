// Package probe is the code of sandmeter-probe, a static helper copied into
// the sandbox rootfs as /usr/local/bin/sandmeter-probe. Escape cases shell
// out to it for syscall-level checks busybox applets cannot do on their own.
//
// Every subcommand is read-only or self-contained: it never changes host
// state, only reports what the kernel let it do from inside the sandbox.
//
// The binary is built from cmd/sandmeter-probe, which only calls Main. The
// code lives here, next to the cases and the harness, because the three
// depend on each other: the harness installs the probe under the name the
// cases call, and the cases pick its subcommands and read its exit status.
package probe

import (
	"errors"
	"fmt"
	"os"
)

// Main is the whole sandmeter-probe program. It runs the subcommand named by
// os.Args[1] and tells the case that called it how the attempt went, through
// the exit status:
//
//	0  the attempt got through; Main returns and the command ends normally
//	3  the probe could not make the attempt at all (see untestableError)
//	2  no subcommand was given, or one the probe does not have
//	1  anything else, such as an attempt that was refused or got no answer
func Main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sandmeter-probe <syscalls|shocker|userns-mount|egress|dns|icmp|maps> [args...]")
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "syscalls":
		err = runSyscalls()
	case "shocker":
		err = runShocker()
	case "userns-mount":
		err = runUsernsMount()
	case "egress":
		err = runEgress(os.Args[2:])
	case "dns":
		err = runDNS(os.Args[2:])
	case "icmp":
		err = runICMP(os.Args[2:])
	case "maps":
		err = runMaps()
	case usernsChildArg:
		err = runUsernsChild()
	case noopArg:
		// Internal: the child of checkUnshareNewuser; being started at all
		// is the whole result.
	case syscallCheckArg:
		// Internal: one probe re-execs itself with this hidden subcommand
		// so a syscall that gets SIGSYS-killed by seccomp only takes down
		// the child, not the whole batch. See runSyscalls.
		err = runSyscallCheck(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "sandmeter-probe: unknown subcommand %q\n", os.Args[1])
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		var ue *untestableError
		if errors.As(err, &ue) {
			os.Exit(exitUntestable)
		}
		os.Exit(1)
	}
}
