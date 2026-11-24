//go:build integration && linux

package kernelfacts

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The kill switch.
//
// Stage 1 of the init stays PID 1 of the sandbox's pid namespace and holds
// the read end of a pipe whose write end only the supervisor has. When the
// supervisor goes away for any reason, PID 1 reads end-of-file and exits,
// and the kernel kills every process of the namespace (pid_namespaces(7)).
// No signal has to reach anybody and no pid is ever named.

// Descriptors the init receives from the supervisor.
const (
	switchDeath = 3 // read end of the pipe the supervisor holds
	switchReady = 4 // one byte when the workload is running
)

// switchProcesses is how many processes the namespace holds once it is ready:
// the init, two children and one orphan.
const switchProcesses = 4

// childSleep never ends by itself.
func childSleep([]string) error {
	for {
		unix.Pause()
	}
}

// childSwitchSupervisor starts the init in new user, mount and pid namespaces,
// inside the leaf, and then only holds the pipe. args: leaf directory.
func childSwitchSupervisor(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: switch-supervisor LEAF")
	}
	death, hold, err := os.Pipe()
	if err != nil {
		return err
	}
	ready, readyW, err := os.Pipe()
	if err != nil {
		return err
	}
	leaf, err := unix.Open(args[0], unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open the leaf: %w", err)
	}
	cmd := exec.Command("/proc/self/exe", childArg, "switch-init")
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{death, readyW}
	attr := &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS | unix.CLONE_NEWPID, UseCgroupFD: true, CgroupFD: leaf}
	usernsAttr(attr)
	cmd.SysProcAttr = attr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start the init: %w", err)
	}
	death.Close()
	readyW.Close()
	unix.Close(leaf)

	buf := make([]byte, 1)
	if n, err := ready.Read(buf); n != 1 {
		return fmt.Errorf("the init ended before its workload ran: %v", err)
	}
	if err := sayReady(map[string]int{"init": cmd.Process.Pid}); err != nil {
		return err
	}
	// From here on this process only exists. The test kills it; the kernel
	// then closes the write end of the pipe, which nobody else holds.
	waitRelease()
	runtime.KeepAlive(hold)
	return nil
}

// childSwitchInit is PID 1: it starts a workload and exits when the supervisor
// is gone.
func childSwitchInit([]string) error {
	if os.Getpid() != 1 {
		return fmt.Errorf("pid %d: expected to be PID 1 of a new pid namespace", os.Getpid())
	}
	// The workload inherits neither pipe.
	unix.CloseOnExec(switchDeath)
	unix.CloseOnExec(switchReady)
	for range 2 {
		if err := exec.Command("/proc/self/exe", childArg, "sleep").Start(); err != nil {
			return fmt.Errorf("start a workload process: %w", err)
		}
	}
	// One process that loses its parent and falls to PID 1.
	if err := exec.Command("/proc/self/exe", childArg, "orphaner").Run(); err != nil {
		return fmt.Errorf("start the orphan: %w", err)
	}
	if _, err := unix.Write(switchReady, []byte{1}); err != nil {
		return fmt.Errorf("report readiness: %w", err)
	}
	unix.Close(switchReady)

	// End-of-file: the supervisor is gone. Exiting is all PID 1 has to do.
	_, _ = io.Copy(io.Discard, os.NewFile(switchDeath, "death"))
	os.Exit(0)
	return nil
}

// childOrphaner leaves a process behind in a session of its own.
func childOrphaner([]string) error {
	cmd := exec.Command("/proc/self/exe", childArg, "sleep")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}

func TestPid1ExitKillsNamespace(t *testing.T) {
	r := declare(t, "init-kill-switch")
	r.needRoot()
	r.needCgroup2()

	tr, err := newCgTree(t, "killswitch")
	if err != nil {
		r.no("init-kill-switch", "the cgroup layout could not be created: %v", err)
		return
	}
	sup, err := spawnChild(t, spawn{name: "switch-supervisor", args: []string{tr.leaf}})
	if err != nil {
		r.no("init-kill-switch", "the supervisor did not start: %v", err)
		return
	}
	var rdy struct {
		Init int `json:"init"`
	}
	if err := sup.ready(&rdy); err != nil {
		r.no("init-kill-switch", "the init and its workload did not start in new user, mount and pid namespaces inside the leaf: %v", err)
		return
	}
	var procs []int
	if !poll(5*time.Second, func() bool {
		procs = cgProcs(tr.leaf)
		return len(procs) == switchProcesses
	}) {
		r.no("init-kill-switch", "cgroup.procs of the leaf lists %v where %d processes were expected (the init, two children, one orphan)", procs, switchProcesses)
		return
	}

	killed := time.Now()
	sup.kill()
	var left []int
	empty := poll(2*time.Second, func() bool {
		left = cgProcs(tr.leaf)
		return len(left) == 0
	})
	took := time.Since(killed)
	r.judge("init-kill-switch", empty && slices.Contains(procs, rdy.Init),
		"the namespace held %d processes %v, the init being pid %d on the host; after SIGKILL of the supervisor, cgroup.procs of the leaf was empty after %s (limit 2 s); left: %v",
		len(procs), procs, rdy.Init, millis(took), left)
}
