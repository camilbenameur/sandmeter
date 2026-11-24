package sandbox

import (
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/camilbenameur/sandmeter/internal/layout"
	"github.com/camilbenameur/sandmeter/policy"
	"github.com/camilbenameur/sandmeter/receipt"
)

// TestVocabularyIsTheReceipts checks that the words a backend reports are
// the words a receipt records, one for one. The two packages declare them
// apart, because the receipt format may not depend on an internal type; this
// test is what keeps them the same.
func TestVocabularyIsTheReceipts(t *testing.T) {
	for name, pair := range map[string][2]string{
		"exited":          {string(StatusExited), receipt.StatusExited},
		"signalled":       {string(StatusSignalled), receipt.StatusSignalled},
		"killed":          {string(StatusKilled), receipt.StatusKilled},
		"exec-failed":     {string(StatusExecFailed), receipt.StatusExecFailed},
		"setup-failed":    {string(StatusSetupFailed), receipt.StatusSetupFailed},
		"wall-timeout":    {string(KillWallTimeout), receipt.KillWallTimeout},
		"oom":             {string(KillOOM), receipt.KillOOM},
		"cancelled":       {string(KillCancelled), receipt.KillCancelled},
		"stopped":         {string(KillStopped), receipt.KillStopped},
		"disk-floor":      {string(KillDiskFloor), receipt.KillDiskFloor},
		"supervisor-lost": {string(KillSupervisorLost), receipt.KillSupervisorLost},
		"init-lost":       {string(KillInitLost), receipt.KillInitLost},
		"workload":        {string(ScopeWorkload), receipt.ScopeWorkload},
		"init+workload":   {string(ScopeInitAndWorkload), receipt.ScopeInitAndWorkload},
		"runtime":         {string(ScopeRuntimeAndWorkload), receipt.ScopeRuntimeAndLoad},
		"allowed":         {string(VerdictAllowed), receipt.VerdictAllowed},
		"denied":          {string(VerdictDenied), receipt.VerdictDenied},
		"not-allowed":     {string(FlowNotAllowed), receipt.FlowNotAllowed},
		"special-address": {string(FlowSpecialAddress), receipt.FlowSpecialAddress},
		"sni-mismatch":    {string(FlowSNIMismatch), receipt.FlowSNIMismatch},
		"not-tls":         {string(FlowNotTLS), receipt.FlowNotTLS},
		"bad-request":     {string(FlowBadRequest), receipt.FlowBadRequest},
		"resolve-failed":  {string(FlowResolveFailed), receipt.FlowResolveFailed},
		"dial-failed":     {string(FlowDialFailed), receipt.FlowDialFailed},
		"limit":           {string(FlowLimit), receipt.FlowLimit},
		"image":           {string(BaseImage), receipt.BaseImage},
		"snapshot":        {string(BaseSnapshot), receipt.BaseSnapshot},
		"none":            {string(NetworkNone), policy.NetworkNone},
		"proxy":           {string(NetworkProxy), policy.NetworkProxy},
		"disk":            {string(StorageDisk), policy.UpperDisk},
		"tmpfs":           {string(StorageTmpfs), policy.UpperTmpfs},
	} {
		if pair[0] != pair[1] || pair[0] == "" {
			t.Errorf("%s: the backend says %q and the receipt or the policy says %q", name, pair[0], pair[1])
		}
	}
	seen := map[KillReason]bool{}
	for _, r := range KillReasons {
		if seen[r] || r == "" {
			t.Errorf("kill reason %q is empty or listed twice", r)
		}
		seen[r] = true
	}
	if len(KillReasons) != 7 {
		t.Errorf("KillReasons has %d entries: the closed list changed without this test", len(KillReasons))
	}
}

// fieldNames returns the names of the fields of a struct type, sorted.
func fieldNames(t reflect.Type) []string {
	var names []string
	for i := range t.NumField() {
		names = append(names, t.Field(i).Name)
	}
	sort.Strings(names)
	return names
}

// TestWhatABackendReportsIsWhatAReceiptRecords compares, field name by field
// name, the blocks of a Result with the blocks of a version 2 receipt that
// are built from them. A field a backend can report and no receipt can hold
// would be evidence thrown away; a field a receipt holds and no backend can
// report could only ever be filled with a guess.
func TestWhatABackendReportsIsWhatAReceiptRecords(t *testing.T) {
	for _, tc := range []struct {
		name          string
		backend, wire reflect.Type
		// rename maps a backend field to the receipt's name for it.
		rename map[string]string
		// only lists what one side has for a stated reason.
		onlyBackend, onlyWire []string
	}{
		{name: "counters", backend: reflect.TypeFor[Counters](), wire: reflect.TypeFor[receipt.CountersV2](),
			rename: map[string]string{"Err": "Error"}},
		{name: "flow", backend: reflect.TypeFor[Flow](), wire: reflect.TypeFor[receipt.FlowV2]()},
		{name: "flows", backend: reflect.TypeFor[Flows](), wire: reflect.TypeFor[receipt.NetworkV2](),
			rename: map[string]string{"Records": "Flows"},
			// The mode is the policy's; the engine copies it.
			onlyWire: []string{"Mode"}},
		{name: "posture", backend: reflect.TypeFor[Posture](), wire: reflect.TypeFor[receipt.PostureV2]()},
		{name: "setting", backend: reflect.TypeFor[Setting](), wire: reflect.TypeFor[receipt.SettingV2]()},
		{name: "runtime process", backend: reflect.TypeFor[RuntimeProcess](), wire: reflect.TypeFor[receipt.RuntimeProcessV2]()},
		{name: "observed", backend: reflect.TypeFor[Enforcement](), wire: reflect.TypeFor[receipt.ObservedV2](),
			// The profile and the filter digest sit one level up in a receipt.
			onlyBackend: []string{"SyscallProfile", "SeccompSHA256"}},
		{name: "storage", backend: reflect.TypeFor[StorageFacts](), wire: reflect.TypeFor[receipt.StorageV2]()},
	} {
		want := map[string]bool{}
		for _, n := range fieldNames(tc.wire) {
			want[n] = true
		}
		for _, n := range tc.onlyWire {
			if !want[n] {
				t.Errorf("%s: the receipt has no field %s any more", tc.name, n)
			}
			delete(want, n)
		}
		skip := map[string]bool{}
		for _, n := range tc.onlyBackend {
			skip[n] = true
		}
		for _, n := range fieldNames(tc.backend) {
			if skip[n] {
				continue
			}
			if r, ok := tc.rename[n]; ok {
				n = r
			}
			if !want[n] {
				t.Errorf("%s: a backend reports %s and the receipt has no such field", tc.name, n)
			}
			delete(want, n)
		}
		for n := range want {
			t.Errorf("%s: the receipt records %s and no backend can report it", tc.name, n)
		}
	}
	// The same words name the settings on both sides.
	for _, name := range []string{SettingMaxUserNamespaces, SettingMaxInotifyInstances, SettingMaxInotifyWatches} {
		if !strings.HasPrefix(name, "user.max_") {
			t.Errorf("setting %q is not a per-user-namespace maximum", name)
		}
	}
}

func TestExitStatus(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    Result
		want int
	}{
		{"success", Result{Status: StatusExited}, 0},
		{"failure", Result{Status: StatusExited, ExitCode: 3}, 3},
		{"abort", Result{Status: StatusSignalled, Signal: 6}, 134},
		{"oom", Result{Status: StatusKilled, KillReason: KillOOM, Signal: 9}, 137},
		{"not found", Result{Status: StatusExecFailed, ExitCode: ExitNotFound}, 127},
		{"not executable", Result{Status: StatusExecFailed, ExitCode: ExitNotExecutable}, 126},
		{"set-up failed", Result{Status: StatusSetupFailed, ExitCode: 0}, -1},
		{"lost init", Result{Status: StatusKilled, KillReason: KillInitLost}, -1},
		{"zero value", Result{}, -1},
	} {
		if got := tc.r.ExitStatus(); got != tc.want {
			t.Errorf("%s: ExitStatus() = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// TestIDCountIsTheLayouts keeps the two statements of how many ids a sandbox
// has, the contract's and the installation's, equal.
func TestIDCountIsTheLayouts(t *testing.T) {
	if IDCount != layout.IDCount {
		t.Errorf("a sandbox maps %d ids and the layout reserves %d", IDCount, layout.IDCount)
	}
}

func TestInodesFor(t *testing.T) {
	for bytes, want := range map[int64]int64{0: 4096, 1 << 20: 4096, 64 << 20: 4096, 256 << 20: 16384, 1 << 30: 65536} {
		if got := InodesFor(bytes); got != want {
			t.Errorf("InodesFor(%d) = %d, want %d", bytes, got, want)
		}
	}
}

func p(v int64) *int64 { return &v }

func TestFromPolicy(t *testing.T) {
	allow := []policy.Dest{{Host: "pypi.org", Port: 443}}
	n := policy.Normal{
		Version: 2,
		Limits: policy.NormalLimits{
			CPUMillis: p(1500), MemoryBytes: p(1 << 30), PIDs: p(512), WallNanos: p(int64(10 * time.Minute)), DiskBytes: p(256 << 20),
		},
		Storage:    policy.Storage{Upper: policy.UpperTmpfs},
		Network:    policy.NormalNetwork{Mode: policy.NetworkProxy, Allow: allow},
		Filesystem: policy.NormalFilesystem{ReadOnlyRoot: true},
		Syscalls:   policy.Syscalls{Profile: policy.ProfileCompat},
		Process:    policy.NormalProcess{Workdir: "/workspace", Env: map[string]string{"A": "b"}},
	}
	got := FromPolicy(n)
	want := Spec{
		Limits:         Limits{CPUMillis: 1500, MemoryBytes: 1 << 30, PIDs: 512, Wall: 10 * time.Minute, DiskBytes: 256 << 20, DiskInodes: 16384},
		Storage:        StorageTmpfs,
		Network:        Network{Mode: NetworkProxy, Allow: allow},
		SyscallProfile: policy.ProfileCompat,
		ReadOnlyRoot:   true,
		Workdir:        "/workspace",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FromPolicy =\n %+v\nwant\n %+v", got, want)
	}
	// The Spec does not share the allow list with the policy it came from.
	got.Network.Allow[0].Host = "changed"
	if allow[0].Host != "pypi.org" {
		t.Error("FromPolicy returned the policy's own slice")
	}

	// An unlimited policy gives zero limits, and no inode quota without a
	// byte quota.
	open := FromPolicy(policy.Normal{Network: policy.NormalNetwork{Mode: policy.NetworkNone}, Storage: policy.Storage{Upper: policy.UpperDisk}})
	if open.Limits != (Limits{}) || open.Network.Mode != NetworkNone || open.Storage != StorageDisk {
		t.Errorf("an unlimited policy gives %+v", open)
	}
}
