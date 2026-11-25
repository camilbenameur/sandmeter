package hostprobe

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/camilbenameur/sandmeter/policy"
)

// allYes returns a report in which every check passed.
func allYes() Report {
	r := Blank()
	for _, s := range Checks {
		r.Set(Check{ID: s.ID, Outcome: Yes, Detail: "ok"})
	}
	return r
}

func TestTable(t *testing.T) {
	seen := map[CheckID]bool{}
	for _, s := range Checks {
		if s.ID == "" || s.Title == "" {
			t.Errorf("check %q: an identifier and a title are required", s.ID)
		}
		if seen[s.ID] {
			t.Errorf("check %q is listed twice", s.ID)
		}
		seen[s.ID] = true
		if s.Backend != "" && s.Backend != policy.BackendNative && s.Backend != policy.BackendGVisor {
			t.Errorf("check %q concerns the unknown backend %q", s.ID, s.Backend)
		}
		for _, c := range s.Backs {
			known := false
			for _, id := range policy.Controls {
				known = known || id == c
			}
			if !known {
				t.Errorf("check %q backs %q, which is not a control", s.ID, c)
			}
		}
		if got, ok := SpecOf(s.ID); !ok || !reflect.DeepEqual(got, s) {
			t.Errorf("SpecOf(%q) = %+v, %v", s.ID, got, ok)
		}
	}
	if _, ok := SpecOf("no-such-check"); ok {
		t.Error("SpecOf knows a check that is not in the table")
	}
}

// TestEveryControlIsBacked is the rule that a capability is never a
// constant: for the native backend, each control of the policy package is
// enforced only because at least one check said so.
func TestEveryControlIsBacked(t *testing.T) {
	good := allYes()
	for _, id := range policy.Controls {
		if c := good.Control(id, policy.BackendNative); !c.Enforced || c.Reason != "" {
			t.Errorf("with every check passing, %s on native is %+v", id, c)
		}
		// With nothing verified, nothing is enforced.
		if c := Blank().Control(id, policy.BackendNative); c.Enforced || !strings.HasPrefix(c.Reason, "could not be verified") {
			t.Errorf("with no check run, %s on native is %+v", id, c)
		}
		if c := (Report{}).Control(id, policy.BackendNative); c.Enforced {
			t.Errorf("the zero report enforces %s", id)
		}
	}
}

func TestControlFollowsItsChecks(t *testing.T) {
	r := allYes()
	r.Set(Check{ID: CheckCgroupSwap, Outcome: No, Detail: "swap is on and memory.swap.max is missing", Fix: "boot with swap accounting"})
	if c := r.Control(policy.ControlMemory, policy.BackendNative); c.Enforced || c.Reason != "swap is on and memory.swap.max is missing" {
		t.Errorf("limits.memory with a failed swap check: %+v", c)
	}
	if c := r.Control(policy.ControlCPU, policy.BackendNative); !c.Enforced {
		t.Errorf("limits.cpu fell with an unrelated check: %+v", c)
	}
	// A failed check that backs controls without being required is not a
	// problem of the backend: only the policies that need the control are
	// refused.
	if ps := r.Problems(policy.BackendNative); len(ps) != 0 {
		t.Errorf("problems: %+v", ps)
	}

	r = allYes()
	r.Set(Check{ID: CheckTmpfsUpper, Outcome: Unknown, Detail: "needs the root service"})
	c := r.Control(policy.ControlTmpfsUpper, policy.BackendNative)
	if c.Enforced || c.Reason != "could not be verified: needs the root service" {
		t.Errorf("storage.tmpfs with an unknown check: %+v", c)
	}

	// The first failing check, in table order, gives the reason.
	r = allYes()
	r.Set(Check{ID: CheckCgroupMemory, Outcome: No, Detail: "first"})
	r.Set(Check{ID: CheckCgroupSwap, Outcome: No, Detail: "second"})
	if c := r.Control(policy.ControlMemory, policy.BackendNative); c.Reason != "first" {
		t.Errorf("reason %q, want that of the first failing check", c.Reason)
	}
}

// TestMissingControllerStopsTheBackend: the processor, memory and task limits
// of the default policy are dropped, not refused, when their control is not
// enforced. A host without one of the three controllers must therefore be
// unable to run a backend at all, or every default session there would run
// unbounded and only its record would say so.
func TestMissingControllerStopsTheBackend(t *testing.T) {
	for _, id := range []CheckID{CheckCgroupCPU, CheckCgroupMemory, CheckCgroupPIDs} {
		spec, ok := SpecOf(id)
		if !ok || !spec.Required {
			t.Errorf("check %q is declared as %+v, want a required check", id, spec)
			continue
		}
		for _, backend := range []string{policy.BackendNative, policy.BackendGVisor} {
			for _, outcome := range []Outcome{No, Unknown} {
				r := allYes()
				r.Set(Check{ID: id, Outcome: outcome, Detail: "the controller is not in cgroup.controllers", Fix: "enable it for the subtree"})
				if ps := r.Problems(backend); len(ps) == 0 {
					t.Errorf("%s is %s and the %s backend has no problem", id, outcome, backend)
				}
			}
		}
	}
}

// TestNoNestedUsernsRestsOnATrial: every session requires that a sandbox
// cannot create user namespaces of its own. On the native backend that is
// enforced only if the mechanism was tried on this host; the fact that user
// namespaces can be created is a prerequisite, not the proof.
func TestNoNestedUsernsRestsOnATrial(t *testing.T) {
	required := false
	for _, id := range policy.AlwaysRequired {
		required = required || id == policy.ControlNoNestedUserns
	}
	if !required {
		t.Fatal("the control is no longer required by every session: this test is about one that is")
	}
	spec, ok := SpecOf(CheckUsernsLimit)
	if !ok || !backs(spec, policy.ControlNoNestedUserns) || spec.Backend != policy.BackendNative {
		t.Fatalf("the trial is declared as %+v", spec)
	}

	for _, outcome := range []Outcome{No, Unknown} {
		r := allYes()
		r.Set(Check{ID: CheckUsernsLimit, Outcome: outcome, Detail: "a nested user namespace was created after the limit was written", Fix: "use a kernel that honours user.max_user_namespaces"})
		c := r.Control(policy.ControlNoNestedUserns, policy.BackendNative)
		if c.Enforced || !strings.Contains(c.Reason, "a nested user namespace was created") {
			t.Errorf("%s trial: userns.nested on native is %+v, although user namespaces can be created", outcome, c)
		}
		// Every native session needs the control: the host cannot run the
		// backend, and says so with the fix, instead of refusing each policy
		// with a line of its own.
		ps := r.Problems(policy.BackendNative)
		if len(ps) != 1 || ps[0].ID != string(CheckUsernsLimit) || ps[0].Fix == "" {
			t.Errorf("%s trial: problems of the native backend: %+v", outcome, ps)
		}
		// The other controls stand, and so does the other backend.
		if c := r.Control(policy.ControlNetworkNone, policy.BackendNative); !c.Enforced {
			t.Errorf("%s trial: network.none fell with it: %+v", outcome, c)
		}
		if c := r.Control(policy.ControlNoNestedUserns, policy.BackendGVisor); !c.Enforced {
			t.Errorf("%s trial: userns.nested on gvisor is %+v", outcome, c)
		}
		if ps := r.Problems(policy.BackendGVisor); len(ps) != 0 {
			t.Errorf("%s trial: a check of the native backend is a problem of gvisor: %+v", outcome, ps)
		}
	}

	// The prerequisite alone does not enforce it either way round.
	r := allYes()
	r.Set(Check{ID: CheckNamespaces, Outcome: No, Detail: "user.max_user_namespaces is 0"})
	for _, backend := range []string{policy.BackendNative, policy.BackendGVisor} {
		if c := r.Control(policy.ControlNoNestedUserns, backend); c.Enforced {
			t.Errorf("without user namespaces, userns.nested on %s is %+v", backend, c)
		}
	}
}

func TestBackendsAreToldApart(t *testing.T) {
	r := allYes()
	// The proxy listener is a check of the native backend: nothing backs the
	// proxy on gVisor, so the host's answer there is no.
	if c := r.Control(policy.ControlNetworkProxy, policy.BackendGVisor); c.Enforced || !strings.Contains(c.Reason, "no host check backs it") {
		t.Errorf("network.proxy on gvisor: %+v", c)
	}
	if c := r.Control(policy.ControlNetworkProxy, policy.BackendNative); !c.Enforced {
		t.Errorf("network.proxy on native: %+v", c)
	}

	r.Set(Check{ID: CheckRunsc, Outcome: No, Detail: "release 20250101.0 is older than the minimum", Fix: "install a newer runsc"})
	if ps := r.Problems(policy.BackendNative); len(ps) != 0 {
		t.Errorf("a runsc problem reached the native backend: %+v", ps)
	}
	ps := r.Problems(policy.BackendGVisor)
	if len(ps) != 1 || ps[0].ID != string(CheckRunsc) || ps[0].Fix != "install a newer runsc" {
		t.Errorf("gvisor problems: %+v", ps)
	}
}

func TestProblemsAndWarnings(t *testing.T) {
	r := allYes()
	r.Set(Check{ID: CheckKernel, Outcome: No, Detail: "kernel 5.15 is below 6.1"})
	r.Set(Check{ID: CheckIDRange, Outcome: Unknown, Detail: "/etc/subuid could not be read"})
	r.Set(Check{ID: CheckCorePattern, Outcome: Unknown, Detail: "crashes are piped to a handler"})
	ps := r.Problems(policy.BackendNative)
	if len(ps) != 2 || ps[0].ID != string(CheckKernel) || ps[1].ID != string(CheckIDRange) {
		t.Fatalf("problems: %+v", ps)
	}
	if ps[1].Detail != "could not be verified: /etc/subuid could not be read" {
		t.Errorf("an unknown required check reads %q", ps[1].Detail)
	}
	ws := r.Warnings()
	if len(ws) != 1 || ws[0].ID != CheckCorePattern {
		t.Errorf("warnings: %+v", ws)
	}
	// An advisory check never refuses anything.
	caps := r.Capabilities(policy.BackendNative)
	for _, p := range caps.Problems {
		if p.ID == string(CheckCorePattern) {
			t.Error("an advisory check became a problem")
		}
	}
}

func TestCapabilities(t *testing.T) {
	caps := allYes().Capabilities(policy.BackendNative)
	if caps.Backend != policy.BackendNative || !caps.Usable() || len(caps.Controls) != len(policy.Controls) {
		t.Fatalf("capabilities: %+v", caps)
	}
	for _, id := range policy.Controls {
		if !caps.Control(id).Enforced {
			t.Errorf("%s is not enforced with every check passing", id)
		}
	}
	none := Blank().Capabilities(policy.BackendNative)
	if none.Usable() {
		t.Error("a host where nothing was verified is usable")
	}
	for _, id := range policy.Controls {
		if none.Control(id).Enforced {
			t.Errorf("%s is enforced with no check run", id)
		}
	}
}

func TestValidate(t *testing.T) {
	if err := allYes().Validate(); err != nil {
		t.Errorf("a full report: %v", err)
	}
	if err := Blank().Validate(); err != nil {
		t.Errorf("a blank report: %v", err)
	}
	short := allYes()
	short.Checks = short.Checks[1:]
	swapped := allYes()
	swapped.Checks[0], swapped.Checks[1] = swapped.Checks[1], swapped.Checks[0]
	odd := allYes()
	odd.Checks[2].Outcome = "maybe"
	for name, r := range map[string]Report{"zero": {}, "short": short, "swapped": swapped, "odd outcome": odd} {
		if err := r.Validate(); err == nil {
			t.Errorf("%s: Validate accepted it", name)
		}
	}
}

func TestSetRefusesAnUnknownCheck(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Set took a check that is not in the table")
		}
	}()
	r := Blank()
	r.Set(Check{ID: "nope", Outcome: Yes})
}

// TestReportIsPlainJSON checks that a report crosses a process boundary and
// comes back the same.
func TestReportIsPlainJSON(t *testing.T) {
	r := allYes()
	r.Kernel = "6.8.0-1070-azure"
	r.Set(Check{ID: CheckKernel, Outcome: Yes, Detail: "6.8.0-1070-azure"})
	r.Set(Check{ID: CheckRunsc, Outcome: No, Detail: "not installed", Fix: "install runsc"})
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, r) {
		t.Errorf("read back\n %+v\nwant\n %+v", back, r)
	}
	if err := back.Validate(); err != nil {
		t.Error(err)
	}
}
