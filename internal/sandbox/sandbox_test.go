package sandbox

import (
	"errors"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/camilbenameur/sandmeter/internal/ids"
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

// TestAResultOffersNoExitStatus keeps a second table of exit statuses from
// coming back. The status of a sandmeter command is decided in one place,
// from the outcome a record carries: a helper here that answered 128 plus
// the signal for every kill would report a time limit as 137.
func TestAResultOffersNoExitStatus(t *testing.T) {
	typ := reflect.TypeFor[Result]()
	for i := range typ.NumMethod() {
		if name := typ.Method(i).Name; strings.Contains(name, "Exit") || strings.Contains(name, "Status") {
			t.Errorf("Result has a method %s: exit statuses are decided by package exit", name)
		}
	}
}

func TestLimit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		l       Limit
		valid   bool
		value   int64
		limited bool
	}{
		{"an amount", AtMost(512), true, 512, true},
		{"one", AtMost(1), true, 1, true},
		{"none", NoLimit(), true, 0, false},
		// What is not valid never reads as "no limit".
		{"the zero value", Limit{}, false, 0, true},
		{"zero as an amount", AtMost(0), false, 0, true},
		{"a negative amount", AtMost(-1), false, -1, true},
		{"none with an amount", Limit{Value: 5, None: true}, false, 5, true},
	} {
		v, limited := tc.l.Get()
		if tc.l.Valid() != tc.valid || v != tc.value || limited != tc.limited {
			t.Errorf("%s: Valid %v, Get %d %v; want %v, %d %v", tc.name, tc.l.Valid(), v, limited, tc.valid, tc.value, tc.limited)
		}
	}
	if d, limited := AtMost(int64(90 * time.Second)).Duration(); d != 90*time.Second || !limited {
		t.Errorf("Duration = %v, %v", d, limited)
	}
	if _, limited := NoLimit().Duration(); limited {
		t.Error("no limit reads as a duration")
	}
}

// validSpec is a Spec every backend accepts as well formed.
func validSpec(t *testing.T) Spec {
	t.Helper()
	id, err := ids.New()
	if err != nil {
		t.Fatal(err)
	}
	return Spec{
		ID:     id,
		Dir:    "/var/lib/sandmeter/state/" + id.String(),
		Layers: []string{"/var/lib/sandmeter/images/layers/a", "/var/lib/sandmeter/images/layers/b"},
		Limits: Limits{
			CPUMillis: AtMost(1000), MemoryBytes: AtMost(512 << 20), PIDs: AtMost(256), Wall: AtMost(int64(time.Minute)),
			DiskBytes: NoLimit(), DiskInodes: NoLimit(),
		},
		Storage:        StorageDisk,
		Floor:          Floor{MinFreeBytes: 1 << 30, MinFreeInodes: 10000},
		Network:        Network{Mode: NetworkNone},
		SyscallProfile: policy.ProfileDefault,
		ReadOnlyRoot:   true,
		Env:            []string{"PATH=/usr/bin:/bin", "EMPTY=", "A=b=c"},
		Workdir:        "/workspace",
		Hostname:       "sandbox",
		IDBase:         layout.DefaultIDBase,
	}
}

// TestTheZeroSpecIsNotASandbox is the reason Validate exists: a Spec nobody
// filled in is the weakest sandbox one could describe, and it is refused,
// with every missing protection named.
func TestTheZeroSpecIsNotASandbox(t *testing.T) {
	err := Spec{}.Validate()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Validate of the zero Spec = %v, want ErrInvalid", err)
	}
	for _, want := range []string{
		"no session identifier", "the session directory", "the cpu limit", "the memory limit", "the task limit", "the wall limit",
		"the disk quota", "storage mode", "the free-space floor", "network mode", "syscall profile", "id base 0",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal of the zero Spec does not mention %q:\n%v", want, err)
		}
	}
}

func TestValidate(t *testing.T) {
	if err := validSpec(t).Validate(); err != nil {
		t.Fatalf("a well-formed Spec: %v", err)
	}
	prefix := netip.MustParsePrefix("168.63.129.16/32")
	for name, mutate := range map[string]func(*Spec){
		"every limit lifted": func(s *Spec) { s.Limits = Limits{NoLimit(), NoLimit(), NoLimit(), NoLimit(), NoLimit(), NoLimit()} },
		"a tmpfs layer with quota": func(s *Spec) {
			s.Storage, s.Limits.DiskBytes, s.Limits.DiskInodes = StorageTmpfs, AtMost(64<<20), AtMost(4096)
		},
		"a tmpfs layer without one": func(s *Spec) { s.Storage = StorageTmpfs },
		"the proxy": func(s *Spec) {
			s.Network = Network{Mode: NetworkProxy, Allow: []policy.Dest{{Host: "pypi.org", Port: 443}}, DenyExtra: []netip.Prefix{prefix}}
		},
		"the proxy with nothing allowed": func(s *Spec) { s.Network.Mode = NetworkProxy },
		"no filter":                      func(s *Spec) { s.SyscallProfile = policy.ProfileOff },
		"no project, no layers":          func(s *Spec) { s.Layers, s.Workspace = nil, "" },
		"a project":                      func(s *Spec) { s.Workspace = s.Dir + "/workspace-layer" },
		"defaults of the backend":        func(s *Spec) { s.Workdir, s.Hostname, s.Env = "", "", nil },
		"the lowest id base":             func(s *Spec) { s.IDBase = IDCount },
		"the highest id base":            func(s *Spec) { s.IDBase = 1<<32 - 1 - IDCount },
	} {
		s := validSpec(t)
		mutate(&s)
		if err := s.Validate(); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
	for name, tc := range map[string]struct {
		mutate func(*Spec)
		want   string
	}{
		"no identifier":           {func(s *Spec) { s.ID = ids.ID{} }, "no session identifier"},
		"relative directory":      {func(s *Spec) { s.Dir = "state/x" }, "the session directory"},
		"unclean directory":       {func(s *Spec) { s.Dir = "/var/lib/../lib/x" }, "the session directory"},
		"relative layer":          {func(s *Spec) { s.Layers = []string{"/ok", "layers/b"} }, "image layer 1"},
		"relative workspace":      {func(s *Spec) { s.Workspace = "ws" }, "the workspace layer"},
		"cpu left out":            {func(s *Spec) { s.Limits.CPUMillis = Limit{} }, "the cpu limit"},
		"memory zero":             {func(s *Spec) { s.Limits.MemoryBytes = AtMost(0) }, "the memory limit"},
		"pids negative":           {func(s *Spec) { s.Limits.PIDs = AtMost(-1) }, "the task limit"},
		"wall left out":           {func(s *Spec) { s.Limits.Wall = Limit{} }, "the wall limit"},
		"quota on disk":           {func(s *Spec) { s.Limits.DiskBytes, s.Limits.DiskInodes = AtMost(1<<20), AtMost(4096) }, "a disk quota with storage mode"},
		"bytes without inodes":    {func(s *Spec) { s.Storage, s.Limits.DiskBytes = StorageTmpfs, AtMost(1<<20) }, "without an inode quota"},
		"no storage mode":         {func(s *Spec) { s.Storage = "" }, "storage mode"},
		"unknown storage mode":    {func(s *Spec) { s.Storage = "loop" }, "storage mode"},
		"floor without bytes":     {func(s *Spec) { s.Floor.MinFreeBytes = 0 }, "the free-space floor"},
		"floor without inodes":    {func(s *Spec) { s.Floor.MinFreeInodes = 0 }, "the free-space floor"},
		"no network mode":         {func(s *Spec) { s.Network.Mode = "" }, "network mode"},
		"unknown network mode":    {func(s *Spec) { s.Network.Mode = "host" }, "network mode"},
		"a list without a proxy":  {func(s *Spec) { s.Network.Allow = []policy.Dest{{Host: "pypi.org", Port: 443}} }, "allowed destinations"},
		"an unparsed destination": {func(s *Spec) { s.Network = Network{Mode: NetworkProxy, Allow: []policy.Dest{{}}} }, "allowed destination 0"},
		"an invalid prefix":       {func(s *Spec) { s.Network.DenyExtra = []netip.Prefix{{}} }, "denied prefix 0"},
		"no profile":              {func(s *Spec) { s.SyscallProfile = "" }, "syscall profile"},
		"unknown profile":         {func(s *Spec) { s.SyscallProfile = "relaxed" }, "syscall profile"},
		"env without a name":      {func(s *Spec) { s.Env = []string{"=value"} }, "environment entry 0"},
		"env without a value":     {func(s *Spec) { s.Env = []string{"OK=1", "NAME"} }, "environment entry 1"},
		"env with a NUL":          {func(s *Spec) { s.Env = []string{"A=b\x00c"} }, "environment entry 0"},
		"env not UTF-8":           {func(s *Spec) { s.Env = []string{"A=\xff"} }, "environment entry 0"},
		"relative workdir":        {func(s *Spec) { s.Workdir = "workspace" }, "the working directory"},
		"workdir with a NUL":      {func(s *Spec) { s.Workdir = "/a\x00b" }, "the working directory"},
		"host name too long":      {func(s *Spec) { s.Hostname = strings.Repeat("h", MaxHostnameBytes+1) }, "the host name"},
		"id base zero":            {func(s *Spec) { s.IDBase = 0 }, "id base 0"},
		"id base of an account":   {func(s *Spec) { s.IDBase = 1000 }, "id base 1000"},
		"id base too high":        {func(s *Spec) { s.IDBase = 1<<32 - IDCount }, "do not fit"},
	} {
		s := validSpec(t)
		tc.mutate(&s)
		err := s.Validate()
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: Validate = %v, want ErrInvalid mentioning %q", name, err, tc.want)
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
	got, err := FromPolicy(n)
	if err != nil {
		t.Fatal(err)
	}
	want := Spec{
		Limits: Limits{
			CPUMillis: AtMost(1500), MemoryBytes: AtMost(1 << 30), PIDs: AtMost(512), Wall: AtMost(int64(10 * time.Minute)),
			DiskBytes: AtMost(256 << 20), DiskInodes: AtMost(16384),
		},
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

	// A policy with no limit in force says so in every field, explicitly:
	// nothing is left at a zero that could be read either way.
	wide := policy.Normal{
		Network:  policy.NormalNetwork{Mode: policy.NetworkNone},
		Storage:  policy.Storage{Upper: policy.UpperDisk},
		Syscalls: policy.Syscalls{Profile: policy.ProfileOff},
	}
	open, err := FromPolicy(wide)
	if err != nil {
		t.Fatal(err)
	}
	none := Limits{NoLimit(), NoLimit(), NoLimit(), NoLimit(), NoLimit(), NoLimit()}
	if open.Limits != none || open.Network.Mode != NetworkNone || open.Storage != StorageDisk {
		t.Errorf("a policy without limits gives %+v", open)
	}

	// What FromPolicy returns is the policy's part of a Spec, and is well
	// formed once the engine has added its own.
	full := validSpec(t)
	full.Limits, full.Storage, full.Network, full.SyscallProfile = got.Limits, got.Storage, got.Network, got.SyscallProfile
	if err := full.Validate(); err != nil {
		t.Errorf("the Spec built from a policy: %v", err)
	}
}

// TestFromPolicyNeverTurnsASetLimitIntoNone is the difference between "set
// to zero" and "not limited". A limit that reached the policy in force as
// zero is a fault upstream; it must stop here and not become a sandbox
// without that limit while the record shows one.
func TestFromPolicyNeverTurnsASetLimitIntoNone(t *testing.T) {
	base := func() policy.Normal {
		return policy.Normal{
			Version:  2,
			Limits:   policy.NormalLimits{CPUMillis: p(1000), MemoryBytes: p(512 << 20), PIDs: p(256), WallNanos: p(int64(time.Minute))},
			Storage:  policy.Storage{Upper: policy.UpperDisk},
			Network:  policy.NormalNetwork{Mode: policy.NetworkNone},
			Syscalls: policy.Syscalls{Profile: policy.ProfileDefault},
		}
	}
	if _, err := FromPolicy(base()); err != nil {
		t.Fatalf("the default policy: %v", err)
	}
	for name, tc := range map[string]struct {
		mutate func(*policy.Normal)
		want   string
	}{
		"cpu zero":           {func(n *policy.Normal) { n.Limits.CPUMillis = p(0) }, "limits.cpu is 0"},
		"memory zero":        {func(n *policy.Normal) { n.Limits.MemoryBytes = p(0) }, "limits.memory is 0"},
		"pids zero":          {func(n *policy.Normal) { n.Limits.PIDs = p(0) }, "limits.pids is 0"},
		"wall zero":          {func(n *policy.Normal) { n.Limits.WallNanos = p(0) }, "limits.wall is 0"},
		"disk zero":          {func(n *policy.Normal) { n.Storage.Upper, n.Limits.DiskBytes = policy.UpperTmpfs, p(0) }, "limits.disk is 0"},
		"memory negative":    {func(n *policy.Normal) { n.Limits.MemoryBytes = p(-1) }, "limits.memory is -1"},
		"disk quota on disk": {func(n *policy.Normal) { n.Limits.DiskBytes = p(1 << 20) }, "a disk quota with storage mode"},
		"no storage mode":    {func(n *policy.Normal) { n.Storage.Upper = "" }, "storage.upper"},
		"no network mode":    {func(n *policy.Normal) { n.Network.Mode = "" }, "network.mode"},
		"unknown profile":    {func(n *policy.Normal) { n.Syscalls.Profile = "" }, "syscalls.profile"},
	} {
		n := base()
		tc.mutate(&n)
		spec, err := FromPolicy(n)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: FromPolicy = %v, want ErrInvalid mentioning %q", name, err, tc.want)
		}
		if !reflect.DeepEqual(spec, Spec{}) {
			t.Errorf("%s: a refused policy still gave a Spec: %+v", name, spec)
		}
	}
	// Every limit set to zero at once: the case that used to give a sandbox
	// with no limit at all.
	all := base()
	all.Limits = policy.NormalLimits{CPUMillis: p(0), MemoryBytes: p(0), PIDs: p(0), WallNanos: p(0)}
	if _, err := FromPolicy(all); err == nil {
		t.Error("a policy with every limit set to zero became a Spec")
	}
}
