//go:build integration && linux

package kernelfacts

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A Go process as PID 1 of a sandbox.
//
// The init of a sandbox is the service's own binary. It stays PID 1 of the
// command's pid namespace and shares the leaf group of the command with the
// workload: pids.max there is what the policy allows the workload, plus a
// reserve for the threads of the init. Two things a workload can do to such
// an init were never run.
//
// It can send it signals. A process can only send the init of its pid
// namespace the signals the init has a handler for, and the Go runtime
// installs a handler for nearly every signal, most of which end the
// program. So the init asks for every signal first thing, with
// signal.Notify, and forwards none.
//
// And it can fill the leaf up to pids.max, which counts threads. A Go
// runtime that needs one more thread at that moment, and is refused for a
// fifth of a second, ends the program: PID 1 dies of a runtime error, the
// kernel kills the sandbox, and a command that was stopped reads as one
// that crashed.
//
// The init of these tests is a stand-in made of the parts that matter for
// both: every signal caught, GOMAXPROCS=1, a goroutine that reaps with
// wait4, a control pipe whose end-of-file means exit, a workload started
// with fork and exec and stopped by signals to its process group.

// Descriptors the stand-in init receives from its supervisor.
const (
	initControl = 3 // read end: end-of-file tells it to exit
	initReport  = 4 // write end: one line when the workload runs, one when it is over
)

// What the init tells its workload, in the environment.
const (
	initPidEnv    = "KERNELFACTS_INIT_PID"    // the init, as the workload names it
	initCaughtEnv = "KERNELFACTS_INIT_CAUGHT" // the signals it has a handler for, as /proc prints that mask
)

// The pids.max of the leaf and of the session group in the root tests: what
// a policy would allow the workload, and the reserve of the design for the
// threads of the init.
const (
	workloadPids = 48
	initReserve  = 16
)

// standInPatience is how long a supervisor waits for its init to say that
// the workload is over.
const standInPatience = 45 * time.Second

// initStarted is the first line of the init's report: the workload runs.
type initStarted struct {
	Pid      int    `json:"pid"`      // the init, as it sees itself
	Workload int    `json:"workload"` // the first process of the workload, likewise
	Threads  int    `json:"threads"`  // threads of the init at that moment
	MaxProcs int    `json:"maxprocs"` // its GOMAXPROCS
	Caught   string `json:"caught"`   // signals it has a handler for: SigCgt of /proc/self/status
}

// initFinal is the second and last line: the workload is over.
type initFinal struct {
	Workload string `json:"workload"` // how the first process of the workload ended
	Term     string `json:"term"`     // SIGTERM to the process group of the workload
	Kill     string `json:"kill"`     // SIGKILL to that group, 100 ms later
	Reaped   int    `json:"reaped"`   // processes reaped, that first one included
	Left     string `json:"left"`     // "" when wait4 said no child was left, else why the init stopped waiting
	Signals  []int  `json:"signals"`  // signals its handler received, each listed once
	Threads  int    `json:"threads"`  // threads of the init at the end
}

// statusField reads one field of a /proc/<pid>/status file, "" when there
// is none.
func statusField(path, key string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, key+":"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// threadsOf counts the threads of a process, named as /proc names it
// ("self", or a pid); -1 when the process cannot be read.
func threadsOf(pid string) int {
	n, err := strconv.Atoi(statusField(filepath.Join("/proc", pid, "status"), "Threads"))
	if err != nil {
		return -1
	}
	return n
}

// writeLine writes one JSON value and a newline in a single write.
func writeLine(f *os.File, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}

// endOf says how a process ended, in the words of os.ProcessState.
func endOf(ws syscall.WaitStatus) string {
	switch {
	case ws.Exited():
		return fmt.Sprintf("exit status %d", ws.ExitStatus())
	case ws.Signaled():
		return "signal: " + ws.Signal().String()
	default:
		return fmt.Sprintf("wait status %#x", uint32(ws))
	}
}

// killGroup sends a signal to the process group the init made for its
// workload, whose id is the pid of the workload's first process.
//
// That id is never 0 or 1 here, and the function refuses them: with them
// kill(2) means the caller's own group, or every process the caller may
// signal.
func killGroup(pgid int, sig syscall.Signal) error {
	if pgid <= 1 {
		return fmt.Errorf("refusing to signal the process group %d", pgid)
	}
	return syscall.Kill(-pgid, sig)
}

// childStandInInit is the stand-in init. args: "pid1" when it must be PID 1
// of a new pid namespace, or "subreaper" when it stands in without one, for
// the self-test; then the workload, a helper and its arguments.
func childStandInInit(args []string) error {
	// First thing: every signal has a handler, and none of them ends the
	// program. Nothing received here is forwarded.
	sigs := make(chan os.Signal, 256)
	signal.Notify(sigs)
	// As the init of the design does: whatever dies in here, this process
	// included, feeds no core handler of the host. Where the hard limit is
	// already 0 there is nothing to lower.
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 1, Max: 1})

	if len(args) < 2 {
		return errors.New("usage: standin-init pid1|subreaper WORKLOAD...")
	}
	switch args[0] {
	case "pid1":
		if os.Getpid() != 1 {
			return fmt.Errorf("pid %d: expected to be PID 1 of a new pid namespace", os.Getpid())
		}
		if err := outsideHost("pid", hostPidEnv); err != nil {
			return err
		}
	case "subreaper":
		// Without a pid namespace the nearest thing to an init: what the
		// workload leaves behind falls to this process.
		if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
			return fmt.Errorf("PR_SET_CHILD_SUBREAPER: %w", err)
		}
	default:
		return fmt.Errorf("unknown mode %q", args[0])
	}
	// The workload inherits neither pipe.
	unix.CloseOnExec(initControl)
	unix.CloseOnExec(initReport)
	control, report := os.NewFile(initControl, "control"), os.NewFile(initReport, "report")

	caught := statusField("/proc/self/status", "SigCgt")
	workload, err := syscall.ForkExec("/proc/self/exe", append([]string{"/proc/self/exe", childArg}, args[1:]...), &syscall.ProcAttr{
		Env:   append(os.Environ(), initPidEnv+"="+strconv.Itoa(os.Getpid()), initCaughtEnv+"="+caught),
		Files: []uintptr{0, 1, 2},
		// A process group of its own: the handle by which it is stopped.
		Sys: &syscall.SysProcAttr{Setpgid: true},
	})
	if err != nil {
		return fmt.Errorf("start the workload: %w", err)
	}

	// The reaper: wait4 on any child, and nothing from os/exec, which would
	// take the status of the workload away from it. With no child left
	// there is no process of the workload left either.
	type exited struct {
		pid    int
		status syscall.WaitStatus
	}
	exits := make(chan exited, 2*forkBudgetMost)
	go func() {
		defer close(exits)
		for {
			var ws syscall.WaitStatus
			pid, err := syscall.Wait4(-1, &ws, 0, nil)
			if err == syscall.EINTR {
				continue
			}
			if err != nil {
				return
			}
			exits <- exited{pid, ws}
		}
	}()
	gone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, control)
		close(gone)
	}()

	if err := writeLine(report, initStarted{
		Pid: os.Getpid(), Workload: workload, Threads: threadsOf("self"), MaxProcs: runtime.GOMAXPROCS(0), Caught: caught,
	}); err != nil {
		return fmt.Errorf("report that the workload runs: %w", err)
	}

	var fin initFinal
	received := map[int]bool{}
	var grace, limit <-chan time.Time
	for exits != nil {
		select {
		case s := <-sigs:
			if n, ok := s.(syscall.Signal); ok {
				received[int(n)] = true
			}
		case e, ok := <-exits:
			if !ok {
				exits = nil // nothing is left
				break
			}
			fin.Reaped++
			if e.pid != workload {
				break
			}
			// The first process of the workload is over. Stop what it left
			// behind: its process group, gently, then for good.
			fin.Workload = endOf(e.status)
			fin.Term = errnoName(killGroup(workload, syscall.SIGTERM))
			grace = time.After(100 * time.Millisecond)
			limit = time.After(10 * time.Second)
		case <-grace:
			grace = nil
			fin.Kill = errnoName(killGroup(workload, syscall.SIGKILL))
		case <-limit:
			fin.Left = "children were still left 10 s after the first process of the workload ended"
			exits = nil
		case <-gone:
			// The supervisor let go before the workload was over. Exiting
			// is all PID 1 has to do: the kernel takes the rest.
			os.Exit(0)
		}
	}
	if fin.Kill == "" {
		fin.Kill = "not sent: nothing was left before the 100 ms were over"
	}
	// What the handler took and the loop did not get to yet.
	time.Sleep(50 * time.Millisecond)
	for drained := false; !drained; {
		select {
		case s := <-sigs:
			if n, ok := s.(syscall.Signal); ok {
				received[int(n)] = true
			}
		default:
			drained = true
		}
	}
	fin.Signals = slices.Sorted(maps.Keys(received))
	fin.Threads = threadsOf("self")
	if err := writeLine(report, fin); err != nil {
		return fmt.Errorf("report that the workload is over: %w", err)
	}
	<-gone
	os.Exit(0)
	return nil
}

// standInResult is what the supervisor of a stand-in init reports.
type standInResult struct {
	Init     int          `json:"init"`     // the init, in the pid namespace of the test
	Started  *initStarted `json:"started"`  // nil when the init did not get as far as its workload
	Final    *initFinal   `json:"final"`    // nil when the init never said that the workload was over
	End      string       `json:"end"`      // how the init ended
	Stderr   string       `json:"stderr"`   // end of what the init and its workload wrote on standard error
	Workload string       `json:"workload"` // what the workload printed
}

// childStandInSupervisor starts a stand-in init with a workload, follows
// its report, lets it go and says how it ended. args: the mode of the init,
// the leaf group to clone it into ("" in the self-test), a directory for
// what the init and its workload print, then the workload.
func childStandInSupervisor(args []string) error {
	if len(args) < 4 {
		return errors.New("usage: standin-supervisor pid1|subreaper LEAF DIR WORKLOAD...")
	}
	mode, leaf, dir := args[0], args[1], args[2]
	ctlR, ctlW, err := os.Pipe()
	if err != nil {
		return err
	}
	repR, repW, err := os.Pipe()
	if err != nil {
		return err
	}
	outPath, errPath := filepath.Join(dir, "workload.stdout"), filepath.Join(dir, "init.stderr")
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	errf, err := os.Create(errPath)
	if err != nil {
		return err
	}

	cmd := exec.Command("/proc/self/exe", append([]string{childArg, "standin-init", mode}, args[3:]...)...)
	cmd.Stdout, cmd.Stderr = out, errf
	cmd.ExtraFiles = []*os.File{ctlR, repW}
	cmd.Env = append(os.Environ(), "GOMAXPROCS=1")
	attr := &syscall.SysProcAttr{}
	if mode == "pid1" {
		fd, err := unix.Open(leaf, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open the leaf: %w", err)
		}
		defer unix.Close(fd)
		attr.Cloneflags = unix.CLONE_NEWNS | unix.CLONE_NEWPID
		attr.UseCgroupFD, attr.CgroupFD = true, fd
		usernsAttr(attr)
	}
	cmd.SysProcAttr = attr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start the init: %w", err)
	}
	for _, f := range []*os.File{ctlR, repW, out, errf} {
		f.Close()
	}

	res := standInResult{Init: cmd.Process.Pid}
	lines := bufio.NewReader(repR)
	next := func(v any, within time.Duration) error {
		if err := repR.SetReadDeadline(time.Now().Add(within)); err != nil {
			return err
		}
		line, err := lines.ReadBytes('\n')
		if err != nil {
			return err
		}
		return json.Unmarshal(line, v)
	}
	var started initStarted
	if err := next(&started, readyTimeout); err == nil {
		res.Started = &started
		if err := sayReady(res); err != nil {
			return err
		}
		var final initFinal
		if err := next(&final, standInPatience); err == nil {
			res.Final = &final
		}
	}

	// End-of-file on its control pipe: the init exits, if it still can.
	ctlW.Close()
	waited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(waited)
	}()
	stuck := ""
	select {
	case <-waited:
	case <-time.After(10 * time.Second):
		stuck = fmt.Sprintf("; it was still there 10 s after its control pipe was closed, in state %q, and the supervisor killed it",
			statusField(fmt.Sprintf("/proc/%d/status", cmd.Process.Pid), "State"))
		_ = cmd.Process.Kill()
		<-waited
	}
	res.End = "unknown: the wait failed"
	if cmd.ProcessState != nil {
		res.End = cmd.ProcessState.String()
	}
	res.End += stuck
	res.Stderr = bothEnds(strings.TrimSpace(contentOf(errPath)), 500)
	res.Workload = tail(contentOf(outPath), 4000)
	return sayResult(res)
}

// bothEnds keeps the first and the last n bytes of a text. A Go runtime
// that ends its program says why in its first lines, and prints every
// goroutine after them.
func bothEnds(s string, n int) string {
	if len(s) <= 2*n {
		return s
	}
	return s[:n] + " ... " + s[len(s)-n:]
}

// survived reports whether the init did all of its job: it saw the workload
// end, reaped everything, said so, and exited with status 0 when its
// supervisor let go, and not before.
func (res standInResult) survived() bool {
	return res.Final != nil && res.Final.Left == "" && res.End == "exit status 0"
}

// fate says in one clause what became of the init.
func (res standInResult) fate() string {
	switch {
	case res.Started == nil:
		return fmt.Sprintf("the init did not get as far as its workload and ended with %q; standard error: %q", res.End, res.Stderr)
	case res.Final == nil:
		return fmt.Sprintf("the init never said that the workload was over and ended with %q; standard error: %q", res.End, res.Stderr)
	default:
		f := res.Final
		s := fmt.Sprintf("the init saw the workload end with %q, sent its group SIGTERM (%s) and SIGKILL (%s), reaped %d processes", f.Workload, f.Term, f.Kill, f.Reaped)
		if f.Left != "" {
			s += ", gave up (" + f.Left + ")"
		}
		s += fmt.Sprintf(", and ended with %q when its supervisor let go; its threads: %d when the workload started, %d at the end", res.End, res.Started.Threads, f.Threads)
		if !res.survived() && res.Stderr != "" {
			s += fmt.Sprintf("; standard error: %q", res.Stderr)
		}
		return s
	}
}

// forkBudgetMost bounds the fork bomb, whatever it is asked for: where no
// limit of the kernel stops it, it stops here.
const forkBudgetMost = 512

// bombReport is what the fork bomb prints once it cannot go on.
type bombReport struct {
	Forked int    `json:"forked"` // processes started
	Stop   string `json:"stop"`   // what refused the next one, or "budget"
}

// childForkBomb starts processes that sleep until the kernel refuses one,
// keeps them for a while and exits without them: they fall to the init.
// args: the path of sleep, how many processes to try at most, and for how
// many milliseconds to hold them.
func childForkBomb(args []string) error {
	if len(args) != 3 {
		return errors.New("usage: forkbomb SLEEP BUDGET HOLD-MS")
	}
	budget, err := strconv.Atoi(args[1])
	if err != nil {
		return err
	}
	hold, err := strconv.Atoi(args[2])
	if err != nil {
		return err
	}
	if budget < 1 || budget > forkBudgetMost || hold < 0 || hold > 10_000 {
		return fmt.Errorf("refusing a budget of %d processes held for %d ms: at most %d, for at most 10 s", budget, hold, forkBudgetMost)
	}
	rep := bombReport{Stop: "budget"}
	for rep.Forked < budget {
		// Each of them ends by itself after a minute, whatever becomes of
		// the test.
		_, err := syscall.ForkExec(args[0], []string{"sleep", "60"}, &syscall.ProcAttr{Files: []uintptr{0, 1, 2}})
		if err != nil {
			rep.Stop = errnoName(err)
			break
		}
		rep.Forked++
	}
	if err := say("saturated ", rep); err != nil {
		return err
	}
	time.Sleep(time.Duration(hold) * time.Millisecond)
	return nil
}

// signalReport is what the signaller prints.
type signalReport struct {
	Target  int              `json:"target"`  // the init it signalled
	Results map[string][]int `json:"results"` // the signals sent, by what the kernel answered: "ok" or an errno
	Stopped string           `json:"stopped"` // "" or why it stopped before the last signal
	Alive   string           `json:"alive"`   // signal 0 to the init at the end
}

// childSignaller sends the init that started it one signal after the
// other. args: "all" for the 64 signals, or "caught" for the ones the init
// has a handler for.
//
// The invariant that keeps this helper harmless is that a signal only ever
// goes to that init. As PID 1 the init can only be named by the number 1,
// which in the pid namespace of the test process is the init of the
// machine: there the helper refuses. An init that is not PID 1 is named by
// a descriptor of the process, which cannot come to mean another one, and
// only gets signals it has a handler for.
func childSignaller(args []string) error {
	if len(args) != 1 || (args[0] != "all" && args[0] != "caught") {
		return errors.New("usage: signaller all|caught")
	}
	target, err := strconv.Atoi(os.Getenv(initPidEnv))
	if err != nil || target < 1 {
		return fmt.Errorf("%s=%q: this helper is only started by a stand-in init", initPidEnv, os.Getenv(initPidEnv))
	}
	caught, err := strconv.ParseUint(os.Getenv(initCaughtEnv), 16, 64)
	if err != nil {
		return fmt.Errorf("%s=%q: %w", initCaughtEnv, os.Getenv(initCaughtEnv), err)
	}
	if ppid := os.Getppid(); ppid != target {
		return fmt.Errorf("the parent of this process is %d, not the init %d that is to be signalled: refusing to go on", ppid, target)
	}
	var send func(sig syscall.Signal) error
	if target == 1 {
		if err := outsideHost("pid", hostPidEnv); err != nil {
			return err
		}
		// kill(2), as a workload would.
		send = func(sig syscall.Signal) error { return syscall.Kill(1, sig) }
	} else {
		if args[0] != "caught" {
			return fmt.Errorf("the init %d is not PID 1: only the signals it has a handler for may be sent to it", target)
		}
		pidfd, err := unix.PidfdOpen(target, 0)
		if err != nil {
			return fmt.Errorf("pidfd_open(%d): %w", target, err)
		}
		defer unix.Close(pidfd)
		// Still the parent: the descriptor names the init, for good.
		if ppid := os.Getppid(); ppid != target {
			return fmt.Errorf("the init %d went away: refusing to go on", target)
		}
		send = func(sig syscall.Signal) error { return unix.PidfdSendSignal(pidfd, sig, nil, 0) }
	}

	// The signals the init has a handler for first; then, when asked, the
	// ones it has none for, which no handler can keep from ending a
	// process that is not an init.
	var order []syscall.Signal
	for sig := syscall.Signal(1); sig <= 64; sig++ {
		if caught&(1<<(sig-1)) != 0 {
			order = append(order, sig)
		}
	}
	if args[0] == "all" {
		for sig := syscall.Signal(1); sig <= 64; sig++ {
			if caught&(1<<(sig-1)) == 0 {
				order = append(order, sig)
			}
		}
	}
	rep := signalReport{Target: target, Results: map[string][]int{}}
	for _, sig := range order {
		if ppid := os.Getppid(); ppid != target {
			rep.Stopped = fmt.Sprintf("before signal %d: the parent of this process is now %d, the init is gone", int(sig), ppid)
			break
		}
		res := errnoName(send(sig))
		rep.Results[res] = append(rep.Results[res], int(sig))
		time.Sleep(2 * time.Millisecond)
	}
	rep.Alive = "not asked: the init is gone"
	if rep.Stopped == "" {
		rep.Alive = errnoName(send(0))
	}
	return sayResult(rep)
}

// ranges prints a list of numbers as ranges: "1-8,10-18,20".
func ranges(numbers []int) string {
	sorted := slices.Sorted(slices.Values(numbers))
	var out []string
	for i := 0; i < len(sorted); {
		j := i
		for j+1 < len(sorted) && sorted[j+1] <= sorted[j]+1 {
			j++
		}
		if sorted[i] == sorted[j] {
			out = append(out, strconv.Itoa(sorted[i]))
		} else {
			out = append(out, fmt.Sprintf("%d-%d", sorted[i], sorted[j]))
		}
		i = j + 1
	}
	if len(out) == 0 {
		return "none"
	}
	return strings.Join(out, ",")
}

// signalsOfMask lists the signals of a mask as /proc prints one: sixteen
// hexadecimal digits, bit n-1 for signal n.
func signalsOfMask(hex string) []int {
	mask, err := strconv.ParseUint(hex, 16, 64)
	if err != nil {
		return nil
	}
	var out []int
	for sig := 1; sig <= 64; sig++ {
		if mask&(1<<(sig-1)) != 0 {
			out = append(out, sig)
		}
	}
	return out
}

// startStandIn starts a supervisor with a stand-in init as PID 1 of new
// user, mount and pid namespaces, inside the leaf of a fresh cgroup layout
// that carries the limits of the design.
func startStandIn(t *testing.T, name string, workload ...string) (*child, *cgTree, error) {
	t.Helper()
	tr, err := newCgTree(t, name)
	if err != nil {
		return nil, nil, fmt.Errorf("the cgroup layout could not be created: %w", err)
	}
	limit := strconv.Itoa(workloadPids + initReserve)
	if err := errors.Join(cgWrite(tr.session, "pids.max", limit), cgWrite(tr.leaf, "pids.max", limit)); err != nil {
		return nil, nil, err
	}
	dir := scratch(t, name)
	c, err := spawnChild(t, spawn{name: "standin-supervisor", args: append([]string{"pid1", tr.leaf, dir}, workload...)})
	if err != nil {
		return nil, nil, fmt.Errorf("the supervisor did not start: %w", err)
	}
	return c, tr, nil
}

// bombRound is one fork bomb against one init, and what was seen of it from
// the host.
type bombRound struct {
	res       standInResult
	bomb      bombReport // what the bomb printed; its Stop is "" when it printed nothing
	refused   int64      // "max" of the leaf's pids.events while the bomb held
	current   int64      // pids.current of the leaf then
	threads   int        // threads of the init then, read from the host
	events    string     // pids.events of the leaf at the end
	session   string     // pids.events of the session group at the end
	localLeaf string     // pids.events.local of the leaf at the end
}

// saturated reports whether the bomb did fill the leaf: the kernel refused
// it a process, and counted the refusal on the leaf.
func (b bombRound) saturated() bool { return b.bomb.Stop == "EAGAIN" && b.refused > 0 }

// withinReserve reports whether the init never had more threads than the
// design reserves for it, as far as it was looked at.
func (b bombRound) withinReserve() bool {
	most := b.threads
	if b.res.Started != nil {
		most = max(most, b.res.Started.Threads)
	}
	if b.res.Final != nil {
		most = max(most, b.res.Final.Threads)
	}
	return most <= initReserve
}

func (b bombRound) String() string {
	return fmt.Sprintf("the bomb started %d processes and was stopped by %q; the leaf then held %d tasks, of which %d threads of the init, and had refused %d forks; %s; at the end pids.events reads %s on the leaf (pids.events.local: %s) and %s on the session group",
		b.bomb.Forked, b.bomb.Stop, b.current, b.threads, b.refused, b.res.fate(), b.events, b.localLeaf, b.session)
}

// judgeBomb turns the rounds into the outcome and the detail of the fact.
// A round in which the leaf was never full measured nothing, whatever
// became of the init.
func judgeBomb(rounds []bombRound) (outcome, detail string) {
	limits := fmt.Sprintf("pids.max %d on the leaf and on the session group (%d for the workload, %d reserved for the init), GOMAXPROCS=1", workloadPids+initReserve, workloadPids, initReserve)
	for i, b := range rounds {
		switch {
		case !b.res.survived():
			return no, fmt.Sprintf("%s; round %d of %d: %v", limits, i+1, len(rounds), b)
		case !b.saturated():
			return skipped, fmt.Sprintf("%s; round %d of %d did not fill the leaf, so nothing was measured: %v", limits, i+1, len(rounds), b)
		case !b.withinReserve():
			return no, fmt.Sprintf("%s; round %d of %d: the init had more threads than its reserve: %v", limits, i+1, len(rounds), b)
		}
	}
	if len(rounds) == 0 {
		return skipped, "no round ran"
	}
	return yes, fmt.Sprintf("%s; the init outlived the bomb in each of %d rounds; the last one: %v", limits, len(rounds), rounds[len(rounds)-1])
}

// bombRounds is how many times the bomb is tried, each time against a new
// init in a new leaf: a runtime that only sometimes needs a thread at the
// wrong moment is the case to catch.
const bombRounds = 5

// bombHold is how long the bomb keeps the leaf full, in milliseconds: five
// times the fifth of a second during which the Go runtime retries a thread
// that was refused.
const bombHold = 1000

// runBombRound runs one round and gathers what the host saw of it.
func runBombRound(t *testing.T, n int, sleep string) (bombRound, error) {
	t.Helper()
	var b bombRound
	budget := 4 * (workloadPids + initReserve) // far beyond pids.max, and bounded all the same
	c, tr, err := startStandIn(t, fmt.Sprintf("init-bomb-%d", n), "forkbomb", sleep, strconv.Itoa(budget), strconv.Itoa(bombHold))
	if err != nil {
		return b, err
	}
	var rdy standInResult
	if err := c.ready(&rdy); err != nil {
		return b, fmt.Errorf("the init and its workload did not start in new user, mount and pid namespaces inside the leaf: %w", err)
	}
	// While the bomb holds: the leaf refuses forks, and the init is there.
	poll(10*time.Second, func() bool {
		select {
		case <-c.exited:
			return true
		default:
			b.refused = cgCounter(tr.leaf, "pids.events", "max")
			return b.refused > 0
		}
	})
	b.current, _ = cgInt(tr.leaf, "pids.current")
	b.threads = threadsOf(strconv.Itoa(rdy.Init))
	if err := c.result(&b.res); err != nil {
		return b, err
	}
	if p, ok := findLine([]byte(b.res.Workload), "saturated "); ok {
		_ = json.Unmarshal(p, &b.bomb)
	}
	b.events = cgFlat(tr.leaf, "pids.events")
	b.localLeaf = cgFlat(tr.leaf, "pids.events.local")
	b.session = cgFlat(tr.session, "pids.events")
	return b, nil
}

func TestInitUnderForkBomb(t *testing.T) {
	r := declare(t, "init-fork-bomb")
	r.needRoot()
	r.needCgroup2()
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		r.skip("init-fork-bomb", "sleep is not installed: the bomb has nothing to fork")
		return
	}
	var rounds []bombRound
	for n := 1; n <= bombRounds; n++ {
		b, err := runBombRound(t, n, sleep)
		if err != nil {
			r.no("init-fork-bomb", "round %d of %d did not complete: %v", n, bombRounds, err)
			return
		}
		rounds = append(rounds, b)
		if !b.res.survived() {
			break // one init lost is the answer
		}
	}
	outcome, detail := judgeBomb(rounds)
	r.record("init-fork-bomb", outcome, detail)
}

// judgeSignals turns what the signaller and the init reported into the
// outcome and the detail of the fact.
func judgeSignals(res standInResult, rep *signalReport) (outcome, detail string) {
	if rep == nil {
		return no, "the workload reported nothing about the signals it sent; " + res.fate()
	}
	var sent []string
	tried := 0
	for _, result := range slices.Sorted(maps.Keys(rep.Results)) {
		sent = append(sent, fmt.Sprintf("%s for %s", result, ranges(rep.Results[result])))
		tried += len(rep.Results[result])
	}
	handlers, received := "unknown", "unknown"
	if res.Started != nil {
		handlers = ranges(signalsOfMask(res.Started.Caught))
	}
	if res.Final != nil {
		received = ranges(res.Final.Signals)
	}
	detail = fmt.Sprintf("the workload sent PID 1 the signals 1 to 64 with kill(2), the ones it has a handler for first: %s; signal 0 at the end: %s; PID 1 has handlers for %s and its handlers received %s; %s",
		strings.Join(sent, ", "), rep.Alive, handlers, received, res.fate())
	if rep.Stopped != "" {
		detail += "; the workload stopped " + rep.Stopped
	}
	if res.survived() && rep.Stopped == "" && rep.Alive == "ok" && tried == 64 {
		return yes, detail
	}
	return no, detail
}

func TestInitSignalledByWorkload(t *testing.T) {
	r := declare(t, "init-signals")
	r.needRoot()
	r.needCgroup2()

	c, _, err := startStandIn(t, "init-signals", "signaller", "all")
	if err != nil {
		r.no("init-signals", "%v", err)
		return
	}
	var res standInResult
	if err := c.result(&res); err != nil {
		r.no("init-signals", "the supervisor of the init did not complete: %v", err)
		return
	}
	var rep *signalReport
	if p, ok := findLine([]byte(res.Workload), "result "); ok {
		rep = &signalReport{}
		if err := json.Unmarshal(p, rep); err != nil {
			rep = nil
		}
	}
	outcome, detail := judgeSignals(res, rep)
	r.record("init-signals", outcome, detail)
}

// runStandInHere runs a supervisor, a stand-in init and a workload without
// any namespace or cgroup: the init is then a subreaper, not PID 1.
func runStandInHere(t *testing.T, workload ...string) standInResult {
	t.Helper()
	var res standInResult
	err := runChild(t, spawn{name: "standin-supervisor", args: append([]string{"subreaper", "", t.TempDir()}, workload...)}, &res)
	if err != nil {
		t.Fatalf("the supervisor of the stand-in init: %v", err)
	}
	return res
}

// The stand-in init without what needs root: no namespace, no limit. It
// starts a workload, adopts and reaps what the workload leaves behind,
// stops it by its process group, and exits when the supervisor lets go.
func TestSelfStandInInit(t *testing.T) {
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep is not installed")
	}
	res := runStandInHere(t, "forkbomb", sleep, "6", "150")
	if !res.survived() {
		t.Fatalf("the stand-in init did not do its job: %s", res.fate())
	}
	var bomb bombReport
	if p, ok := findLine([]byte(res.Workload), "saturated "); !ok || json.Unmarshal(p, &bomb) != nil || bomb.Forked != 6 || bomb.Stop != "budget" {
		t.Errorf("the bomb printed %q, want 6 processes started and stopped by its budget", res.Workload)
	}
	// The bomb itself and its six orphans, which only a subreaper gets.
	if f := res.Final; f.Reaped != 7 || f.Workload != "exit status 0" || f.Term != "ok" {
		t.Errorf("the init reaped %d processes, saw the workload end with %q and sent SIGTERM with result %s; want 7, exit status 0, ok", f.Reaped, f.Workload, f.Term)
	}
	if res.Started.MaxProcs != 1 || res.Started.Threads < 1 || res.Final.Threads < 1 {
		t.Errorf("GOMAXPROCS %d, threads %d then %d: want GOMAXPROCS=1 and thread counts read from /proc", res.Started.MaxProcs, res.Started.Threads, res.Final.Threads)
	}
	if res.Started.Threads > initReserve || res.Final.Threads > initReserve {
		t.Errorf("the stand-in init had %d then %d threads: more than the %d the design reserves", res.Started.Threads, res.Final.Threads, initReserve)
	}
}

// The signals half, on the signals that need no namespace to be survived:
// the ones the init has a handler for. Every one of them must reach the
// handler and leave the init alive.
func TestSelfStandInSignals(t *testing.T) {
	res := runStandInHere(t, "signaller", "caught")
	if !res.survived() {
		t.Fatalf("the stand-in init did not survive the signals it has a handler for: %s; the workload printed %q", res.fate(), res.Workload)
	}
	var rep signalReport
	if p, ok := findLine([]byte(res.Workload), "result "); !ok || json.Unmarshal(p, &rep) != nil {
		t.Fatalf("the signaller printed no result: %q", res.Workload)
	}
	caught := signalsOfMask(res.Started.Caught)
	if rep.Stopped != "" || rep.Alive != "ok" || !slices.Equal(rep.Results["ok"], caught) || len(rep.Results) != 1 {
		t.Errorf("the signaller reports %+v; want every signal of the init's mask %s sent with result ok, and the init alive", rep, ranges(caught))
	}
	// SIGKILL and SIGSTOP can have no handler, and a signal without one
	// must never be sent to an init that is not PID 1.
	for _, sig := range []int{int(syscall.SIGKILL), int(syscall.SIGSTOP)} {
		if slices.Contains(caught, sig) {
			t.Errorf("the mask of caught signals %s lists signal %d", res.Started.Caught, sig)
		}
	}
	// What other processes send most, and what ends a Go program that did
	// not ask for it.
	for _, sig := range []syscall.Signal{
		syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGILL, syscall.SIGTRAP, syscall.SIGABRT,
		syscall.SIGBUS, syscall.SIGFPE, syscall.SIGUSR1, syscall.SIGSEGV, syscall.SIGUSR2, syscall.SIGPIPE,
		syscall.SIGALRM, syscall.SIGTERM, syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU, syscall.SIGXCPU, syscall.SIGSYS,
	} {
		if !slices.Contains(res.Final.Signals, int(sig)) {
			t.Errorf("signal %d (%v) was sent and did not reach the handler of the init, which received %s", int(sig), sig, ranges(res.Final.Signals))
		}
	}

	// As PID 1 in the pid namespace of the test process, the signaller
	// would be signalling the init of the machine.
	t.Setenv(initPidEnv, "1")
	t.Setenv(initCaughtEnv, "0")
	var nothing struct{}
	err := runChild(t, spawn{name: "signaller", args: []string{"all"}}, &nothing)
	if err == nil || !strings.Contains(err.Error(), "refusing to go on") {
		t.Errorf("a signaller started outside a stand-in init, told to signal PID 1, did not refuse: %v", err)
	}
}

// The verdicts, on reports written by hand: an init that the runtime
// ended, a leaf that never filled, an init with too many threads.
func TestSelfInitVerdicts(t *testing.T) {
	alive := standInResult{
		Init:    4242,
		Started: &initStarted{Pid: 1, Workload: 2, Threads: 7, MaxProcs: 1, Caught: "fffffffc7ffbfeff"},
		Final:   &initFinal{Workload: "exit status 0", Term: "ok", Kill: "ESRCH", Reaped: 50, Signals: []int{15, 17}, Threads: 7},
		End:     "exit status 0",
	}
	full := bombRound{res: alive, bomb: bombReport{Forked: 49, Stop: "EAGAIN"}, refused: 3, current: 64, threads: 7}
	if outcome, detail := judgeBomb([]bombRound{full, full}); outcome != yes || !strings.Contains(detail, "each of 2 rounds") {
		t.Errorf("two rounds survived at a full leaf: %s, %s", outcome, detail)
	}

	aborted := alive
	aborted.Final, aborted.End, aborted.Stderr = nil, "exit status 2", "runtime: failed to create new OS thread (have 7 already; errno=11)"
	dead := full
	dead.res = aborted
	if outcome, detail := judgeBomb([]bombRound{full, dead}); outcome != no || !strings.Contains(detail, "round 2 of 2") || !strings.Contains(detail, "failed to create new OS thread") {
		t.Errorf("an init ended by its runtime: %s, %s", outcome, detail)
	}

	idle := full
	idle.bomb, idle.refused = bombReport{Forked: 256, Stop: "budget"}, 0
	if outcome, detail := judgeBomb([]bombRound{idle}); outcome != skipped || !strings.Contains(detail, "did not fill the leaf") {
		t.Errorf("a bomb that no limit stopped: %s, %s", outcome, detail)
	}

	crowded := full
	crowded.threads = initReserve + 1
	if outcome, _ := judgeBomb([]bombRound{crowded}); outcome != no {
		t.Errorf("an init with more threads than its reserve: %s", outcome)
	}
	if outcome, _ := judgeBomb(nil); outcome != skipped {
		t.Errorf("no round at all: %s", outcome)
	}

	all := make([]int, 64)
	for i := range all {
		all[i] = i + 1
	}
	rep := &signalReport{Target: 1, Results: map[string][]int{"ok": all}, Alive: "ok"}
	if outcome, detail := judgeSignals(alive, rep); outcome != yes || !strings.Contains(detail, "ok for 1-64") {
		t.Errorf("an init that survived the 64 signals: %s, %s", outcome, detail)
	}
	killed := alive
	killed.Final, killed.End = nil, "signal: quit"
	gone := &signalReport{Target: 1, Results: map[string][]int{"ok": {1, 2, 3}}, Stopped: "before signal 4: the parent of this process is now 0, the init is gone", Alive: "not asked: the init is gone"}
	if outcome, detail := judgeSignals(killed, gone); outcome != no || !strings.Contains(detail, "signal: quit") {
		t.Errorf("an init that a signal ended: %s, %s", outcome, detail)
	}
	if outcome, _ := judgeSignals(alive, nil); outcome != no {
		t.Errorf("a workload that reported nothing: %s", outcome)
	}

	for _, c := range []struct {
		in   []int
		want string
	}{
		{nil, "none"},
		{[]int{5}, "5"},
		{[]int{3, 1, 2, 9, 10, 20}, "1-3,9-10,20"},
	} {
		if got := ranges(c.in); got != c.want {
			t.Errorf("ranges(%v) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := signalsOfMask("0000000000004003"); !slices.Equal(got, []int{1, 2, 15}) {
		t.Errorf("signalsOfMask = %v, want [1 2 15]", got)
	}
	if got := bothEnds(strings.Repeat("a", 10)+strings.Repeat("b", 10), 3); got != "aaa ... bbb" {
		t.Errorf("bothEnds of a long text = %q", got)
	}
	if got := bothEnds("short", 3); got != "short" {
		t.Errorf("bothEnds of a short text = %q", got)
	}
	for _, pgid := range []int{-1, 0, 1} {
		if err := killGroup(pgid, 0); err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Errorf("killGroup(%d) = %v: it must refuse the groups that mean the caller's own, or everybody", pgid, err)
		}
	}
	if got := threadsOf("self"); got < 1 {
		t.Errorf("threadsOf(self) = %d", got)
	}
	if got := threadsOf("0"); got != -1 {
		t.Errorf("threadsOf of a process that does not exist = %d, want -1", got)
	}
}
