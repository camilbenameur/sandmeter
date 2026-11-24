//go:build integration && linux

package kernelfacts

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The threads of the test process.
//
// A namespace entered with setns belongs to a thread, not to the process.
// The Go runtime ends a thread whose goroutine exits while locked to it,
// with one exception: the main thread is never ended, it is parked for
// good, in whatever namespace it was left. /proc/self names that thread, so
// a main thread parked in the namespace of a sandbox would make every later
// reading of /proc/self/ns describe the sandbox and not the host. The main
// goroutine is therefore wired to the main thread before the first test
// (init, in main_test.go): no goroutine of a test can ever run on it.

// strayThreads lists the threads of this process that are in another mount
// or network namespace than the process started in. Such a thread would do
// whatever the runtime gives it next in the namespace of a sandbox, and it
// keeps that namespace alive.
func strayThreads() string {
	return threadsOutside(map[string]string{"mnt": hostMntNS, "net": hostNetNS})
}

// threadsOutside lists the threads of this process whose namespace of a
// kind is not the one given for that kind.
func threadsOutside(home map[string]string) string {
	tasks, err := os.ReadDir("/proc/self/task")
	if err != nil {
		return "the threads of this process cannot be listed: " + err.Error()
	}
	var out []string
	for _, task := range tasks {
		for _, kind := range slices.Sorted(maps.Keys(home)) {
			link, err := os.Readlink(filepath.Join("/proc/self/task", task.Name(), "ns", kind))
			if err != nil {
				continue // the thread ended while we were looking
			}
			if link != home[kind] {
				out = append(out, fmt.Sprintf("thread %s is in %s, the process started in %s", task.Name(), link, home[kind]))
			}
		}
	}
	return strings.Join(out, "; ")
}

// goroutinesOnMainThread starts n goroutines that each hold a thread of
// their own at the same time, and counts those that got the main thread,
// whose id is the id of the process.
func goroutinesOnMainThread(n int) int {
	tids := make(chan int, n)
	var hold, done sync.WaitGroup
	hold.Add(1)
	for range n {
		done.Add(1)
		go func() {
			defer done.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			tids <- unix.Gettid()
			hold.Wait()
		}()
	}
	onMain := 0
	for range n {
		if <-tids == os.Getpid() {
			onMain++
		}
	}
	hold.Done()
	done.Wait()
	return onMain
}

func TestSelfMainThreadIsReserved(t *testing.T) {
	runtime.LockOSThread()
	self := unix.Gettid()
	runtime.UnlockOSThread()
	if self == os.Getpid() {
		t.Errorf("the goroutine of this test runs on the main thread (%d)", self)
	}
	// Enough of them, at the same time, to use every thread the runtime
	// has, the main one included if it were free.
	if n := goroutinesOnMainThread(48); n != 0 {
		t.Errorf("%d of 48 goroutines that each asked for a thread got the main thread: a test that enters a namespace on its thread could park the main thread there", n)
	}
}

// What the test of the egress listener counts on when a thread cannot be
// brought back from a namespace: a goroutine that exits while locked to its
// thread takes the thread with it.
func TestSelfLockedThreadEnds(t *testing.T) {
	tid := make(chan int)
	go func() {
		runtime.LockOSThread()
		tid <- unix.Gettid()
	}()
	task := filepath.Join("/proc/self/task", strconv.Itoa(<-tid))
	if !poll(3*time.Second, func() bool { return !exists(task) }) {
		t.Errorf("%s still exists 3 s after its goroutine exited without unlocking it: the runtime did not end the thread", task)
	}
}

func TestSelfStrayThreads(t *testing.T) {
	if d := strayThreads(); d != "" {
		t.Errorf("in a process no test moved: %s", d)
	}
	// A detector that never fires is worth nothing: against a namespace
	// that is not this process's, every thread is a stray, the main one
	// first.
	d := threadsOutside(map[string]string{"net": "net:[1]"})
	if want := fmt.Sprintf("thread %d is in %s, the process started in net:[1]", os.Getpid(), hostNetNS); !strings.Contains(d, want) {
		t.Errorf("threadsOutside does not report the main thread against another namespace: %q does not contain %q", d, want)
	}
}
