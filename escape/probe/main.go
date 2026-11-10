// Command rfprobe is a static helper copied into the sandbox rootfs as
// /usr/local/bin/rfprobe. Escape cases shell out to it for syscall-level
// checks busybox applets cannot do on their own.
//
// Every subcommand is read-only or self-contained: it never changes host
// state, only reports what the kernel let it do from inside the sandbox.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: rfprobe <syscalls|shocker|userns-mount|egress|maps> [args...]")
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
	case "maps":
		err = runMaps()
	case syscallCheckArg:
		// Internal: one probe re-execs itself with this hidden subcommand
		// so a syscall that gets SIGSYS-killed by seccomp only takes down
		// the child, not the whole batch. See runSyscalls.
		err = runSyscallCheck(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "rfprobe: unknown subcommand %q\n", os.Args[1])
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
