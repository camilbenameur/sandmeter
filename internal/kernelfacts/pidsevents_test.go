//go:build integration && linux

package kernelfacts

import (
	"fmt"
	"strconv"
	"testing"
)

// Where a refused fork is counted.
//
// The receipt reads the pids counter of the command's leaf, and the escape
// case for fork bombs is judged from it. The meaning of pids.events changed
// between kernel generations: older kernels count a refused fork in the
// group of the process that forked, newer ones in the group whose limit was
// hit, and add pids.events.local. The two hosted kernels are on opposite
// sides. With a limit on the leaf itself both count there, which is why the
// design sets pids.max twice.
//
// The forks are made by the test with clone3(CLONE_INTO_CGROUP), the way
// the supervisor starts a command. The pids controller charges and counts
// such a clone in the same function as a fork made from inside the group.

// pidsReport is what one layout of limits showed.
type pidsReport struct {
	current      int64    // tasks in the leaf when the limits were written
	leafMax      int64    // pids.max of the leaf
	sessionMax   int64    // pids.max of the session group
	forks        []string // result of each clone into the leaf
	leaf         string   // pids.events of the leaf
	session      string   // pids.events of the session group
	leafLocal    string   // pids.events.local of the leaf
	sessionLocal string   // pids.events.local of the session group
	leafCount    int64    // "max" of the leaf's pids.events
}

func (p pidsReport) String() string {
	return fmt.Sprintf("%d tasks in the leaf; pids.max: leaf %d, session %d; three clones into the leaf: %v; pids.events: leaf %s, session %s; pids.events.local: leaf %s, session %s",
		p.current, p.leafMax, p.sessionMax, p.forks, p.leaf, p.session, p.leafLocal, p.sessionLocal)
}

// refused reports whether every clone was refused with EAGAIN.
func (p pidsReport) refused() bool {
	for _, f := range p.forks {
		if f != "EAGAIN" {
			return false
		}
	}
	return len(p.forks) > 0
}

// The two limits of a scenario. The low one refuses every further task
// whatever the group holds, so the three clones are refused for certain;
// the high one is never reached.
const (
	pidsLow  = 0
	pidsHigh = 1000
)

// pidsScenario puts one process in a leaf, sets pids.max on the leaf and on
// the session group, and tries three more clones into the leaf. The limit
// that refuses them is the leaf's when onLeaf is set, the session's
// otherwise.
func pidsScenario(t *testing.T, name string, onLeaf bool) (pidsReport, error) {
	t.Helper()
	var rep pidsReport
	tr, err := newCgTree(t, name)
	if err != nil {
		return rep, err
	}
	// One process in the leaf, as a command would be, and fully started
	// before the limits are written: its runtime creates threads on the way.
	c, err := spawnChild(t, spawn{name: "echo", cgroup: tr.leaf})
	if err != nil {
		return rep, fmt.Errorf("start a process in the leaf: %w", err)
	}
	var up struct{}
	if err := c.ready(&up); err != nil {
		return rep, err
	}
	if rep.current, err = cgInt(tr.leaf, "pids.current"); err != nil {
		return rep, err
	}

	rep.leafMax, rep.sessionMax = pidsLow, pidsHigh
	if !onLeaf {
		rep.leafMax, rep.sessionMax = pidsHigh, pidsLow
	}
	if err := cgWrite(tr.session, "pids.max", strconv.FormatInt(rep.sessionMax, 10)); err != nil {
		return rep, err
	}
	if err := cgWrite(tr.leaf, "pids.max", strconv.FormatInt(rep.leafMax, 10)); err != nil {
		return rep, err
	}

	for range 3 {
		c, err := startChild(t.TempDir(), spawn{name: "noop", cgroup: tr.leaf})
		if err != nil {
			rep.forks = append(rep.forks, errnoName(err))
			continue
		}
		c.stop()
		rep.forks = append(rep.forks, "started")
	}
	rep.leaf = cgFlat(tr.leaf, "pids.events")
	rep.session = cgFlat(tr.session, "pids.events")
	rep.leafLocal = cgFlat(tr.leaf, "pids.events.local")
	rep.sessionLocal = cgFlat(tr.session, "pids.events.local")
	rep.leafCount = cgCounter(tr.leaf, "pids.events", "max")
	return rep, nil
}

func TestPidsEvents(t *testing.T) {
	r := declare(t, "pids-events-leaf", "pids-events-session")
	r.needRoot()
	r.needCgroup2()

	leaf, err := pidsScenario(t, "pids-leaf", true)
	if err != nil {
		r.no("pids-events-leaf", "the scenario did not complete: %v", err)
	} else {
		r.judge("pids-events-leaf", leaf.refused() && leaf.leafCount > 0,
			"limit hit on the leaf: %v (expected three EAGAIN and a leaf count above 0)", leaf)
	}

	session, err := pidsScenario(t, "pids-session", false)
	if err != nil {
		r.skip("pids-events-session", "the scenario did not complete: %v", err)
		return
	}
	r.judge("pids-events-session", session.refused() && session.leafCount > 0,
		"limit hit on the session group: %v", session)
}
