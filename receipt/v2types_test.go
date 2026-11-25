package receipt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// shapeOf writes one line per field of t and of every struct it reaches:
// the Go name, the Go type and the tag. Two structs with the same lines
// encode to the same JSON for the same values.
func shapeOf(t reflect.Type, seen map[reflect.Type]bool, out *strings.Builder) {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || t.PkgPath() != reflect.TypeFor[RecordV2]().PkgPath() || seen[t] {
		return
	}
	seen[t] = true
	fmt.Fprintf(out, "%s\n", t.Name())
	for i := range t.NumField() {
		f := t.Field(i)
		typ := f.Type.String()
		if f.Type == reflect.TypeFor[json.RawMessage]() {
			// The name the toolchain prints for this type is not stable.
			typ = "json.RawMessage"
		}
		fmt.Fprintf(out, "\t%s %s `%s`\n", f.Name, typ, f.Tag)
	}
	for i := range t.NumField() {
		shapeOf(t.Field(i).Type, seen, out)
	}
}

// TestV2ShapeIsFrozen compares every struct of schema v2 with the list in
// testdata/v2/shape.txt: names, order, types and tags. Within a schema
// version no field is added, removed, renamed or retyped. When this test
// fails, the change under test altered a published format: the change needs
// a new schema, not a new shape.txt.
func TestV2ShapeIsFrozen(t *testing.T) {
	var got strings.Builder
	seen := map[reflect.Type]bool{}
	shapeOf(reflect.TypeFor[RecordV2](), seen, &got)
	shapeOf(reflect.TypeFor[IntentV2](), seen, &got)

	want, err := os.ReadFile(filepath.Join("testdata", "v2", "shape.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != string(want) {
		t.Errorf("the structs of schema v2 are\n%s\nand testdata/v2/shape.txt says\n%s", got.String(), want)
	}
}

// TestV2HasNoOptionalKey checks the rule that lets a reader tell "not
// measured" from "zero": apart from the six blocks of a record, of which
// exactly one is present, no key is ever left out. An absent measurement is
// an explicit null.
func TestV2HasNoOptionalKey(t *testing.T) {
	var shape strings.Builder
	seen := map[reflect.Type]bool{}
	shapeOf(reflect.TypeFor[RecordV2](), seen, &shape)
	shapeOf(reflect.TypeFor[IntentV2](), seen, &shape)
	blocks := map[string]bool{"Command": true, "Snapshot": true, "Restore": true, "Export": true, "Stop": true, "Interrupted": true}
	for typ := range seen {
		for i := range typ.NumField() {
			f := typ.Field(i)
			tag := f.Tag.Get("json")
			name, opts, _ := strings.Cut(tag, ",")
			if name == "" || name == "-" {
				t.Errorf("%s.%s has no JSON key", typ.Name(), f.Name)
			}
			optional := opts != ""
			isBlock := typ == reflect.TypeFor[RecordV2]() && blocks[f.Name]
			if optional != isBlock {
				t.Errorf("%s.%s is tagged %q: only the six blocks of a record may be left out", typ.Name(), f.Name, tag)
			}
		}
	}
}

func intp(v int) *int       { return &v }
func int64p(v int64) *int64 { return &v }
func boolp(v bool) *bool    { return &v }

// TestV2CommandRecordReadsBack encodes a full command record, checks a few
// of its bytes by hand and decodes it strictly to the same value.
func TestV2CommandRecordReadsBack(t *testing.T) {
	t0 := time.Date(2026, 11, 18, 9, 30, 0, 0, time.UTC)
	rec := RecordV2{
		Schema: SchemaV2,
		Kind:   KindCommand,
		ID:     "0123456789abcdef0123456789abcdef",
		Chain:  ChainV2{Session: "00112233445566778899aabbccddeeff", Seq: 3, PrevSHA256: strings.Repeat("ab", 32)},
		UID:    1000,
		Time:   t0.Add(2 * time.Second),
		Host:   HostV2{Kernel: "Linux 6.8.0", Arch: "amd64", SandmeterVersion: "0.1.0", Commit: "abc1234", Backend: "native"},
		Command: &CommandV2{
			Argv:          []string{"go", "test", "./..."},
			EnvNames:      []string{"HOME", "PATH"},
			Workdir:       "/workspace",
			Policy:        json.RawMessage(`{"version":2}`),
			PolicySHA256:  strings.Repeat("cd", 32),
			CeilingSHA256: strings.Repeat("ef", 32),
			Image:         ImageV2{RequestedRef: "example.test/image:1", Digest: "sha256:" + strings.Repeat("0", 64), DiffIDs: []string{"sha256:" + strings.Repeat("7", 64)}},
			Outcome:       OutcomeV2{Status: StatusKilled, Signal: intp(9), KillReason: KillOOM},
			WallLimitMS:   int64p(60000),
			StartedAt:     t0,
			FinishedAt:    t0.Add(time.Second),
			DurationMS:    1000,
			Stdout:        StreamV2{SHA256: strings.Repeat("1", 64), Bytes: 12, Delivered: 12},
			Stderr:        StreamV2{SHA256: strings.Repeat("2", 64)},
			Counters:      CountersV2{Scope: ScopeInitAndWorkload, MemoryPeakBytes: int64p(64 << 20), OOMKills: int64p(1)},
			Network: NetworkV2{Mode: "proxy", Recorded: true, Complete: true, Flows: []FlowV2{
				{Name: "pypi.org", Port: 443, Address: "192.0.2.10", Verdict: VerdictAllowed, BytesUp: 517, BytesDown: 4096},
				{Port: 443, InvalidBytes: 300, InvalidSHA256: strings.Repeat("3", 64), Verdict: VerdictDenied, Reason: FlowBadRequest},
			}},
			Enforcement: EnforcementV2{
				Controls:       []ControlV2{{ID: "limits.memory", Enforced: true}},
				SyscallProfile: "default",
				SeccompSHA256:  strings.Repeat("4", 64),
				Observed: ObservedV2{
					Workload:  PostureV2{Tasks: intp(1), SeccompMode: intp(2), NoNewPrivs: boolp(true), CapInh: "0000000000000000"},
					Init:      PostureV2{Tasks: intp(6), SeccompMode: intp(0)},
					Settings:  []SettingV2{{Name: "user.max_inotify_instances", Value: "40"}, {Name: "user.max_user_namespaces", Value: "0"}},
					MemoryMax: "67108864",
					Runtime:   []RuntimeProcessV2{},
				},
			},
			Storage: StorageV2{Upper: "disk"},
			Workspace: &WorkspaceV2{ManifestSHA256: strings.Repeat("5", 64), Entries: 2, Bytes: 10,
				Superseded:      []SupersededV2{{Path: "src/x.go", Type: TypeFile, SHA256: strings.Repeat("8", 64), Layer: "upper"}},
				SupersededTotal: 12000, SupersededTruncated: true},
			Diff: DiffV2{
				Base:    DiffBaseV2{Kind: BaseImage},
				Status:  DiffTruncated,
				Reasons: []string{DiffReasonHashBudget},
				Counts:  DiffCountsV2{Exact: true, Added: 2},
				Budget:  DiffBudgetV2{Entries: 100000, Bytes: 16 << 20, Depth: 128},
				Entries: []DiffEntryV2{
					{Path: "workspace/big.bin", Op: OpAdd, Type: TypeFile, Mode: 0o644, Nlink: 1, Xattrs: []string{}, Size: 1 << 40, SinceSeq: 3, Skipped: SkipHashBudget},
					{Path: "workspace/out.txt", Op: OpAdd, Type: TypeFile, Mode: 0o644, Nlink: 2, Xattrs: []string{`"user.\xff"`, "security.capability"}, XattrsEscaped: true, Size: 3, SHA256: strings.Repeat("6", 64), SinceSeq: 3},
				},
			},
			Errors: []string{},
		},
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`{"schema":"sandmeter.receipt/v2","kind":"command","id":"0123456789abcdef0123456789abcdef","chain":{"session":"00112233445566778899aabbccddeeff","seq":3,"prev_sha256":"` + strings.Repeat("ab", 32) + `"}`,
		`"outcome":{"status":"killed","exit_code":null,"signal":9,"kill_reason":"oom","error":""}`,
		// A counter that was not measured is null, never zero.
		`"cpu_usage_usec":null,"pids_peak":null,"pids_max_hits":null`,
		`"oom_kills":1`,
		`"uid":1000`,
		`"wall_limit_ms":60000`,
		// The posture of a process that was not read is null, field by field.
		`"init":{"tasks":6,"seccomp_mode":0,"no_new_privs":null,`,
		`"settings":[{"name":"user.max_inotify_instances","value":"40"},{"name":"user.max_user_namespaces","value":"0"}]`,
		`"runtime":[]`,
		`"status":"truncated","reasons":["hash-budget"],"error":""`,
		`"quota_bytes":null`,
		`"policy":{"version":2}`,
		// A list that was cut says so, and says how long it really is.
		`"superseded_total":12000,"superseded_truncated":true`,
		// An attribute name that is not valid UTF-8 keeps its bytes.
		`"xattrs":["\"user.\\xff\"","security.capability"],"xattrs_truncated":false,"xattrs_escaped":true`,
	} {
		if !bytes.Contains(b, []byte(want)) {
			t.Errorf("the record lacks %s:\n%s", want, b)
		}
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"snapshot", "restore", "export", "stop", "interrupted"} {
		if _, ok := top[absent]; ok {
			t.Errorf("a command record holds the block %q", absent)
		}
	}

	var back RecordV2
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, rec) {
		t.Errorf("read back\n %+v\nwant\n %+v", back, rec)
	}
	again, err := json.Marshal(back)
	if err != nil || !bytes.Equal(again, b) {
		t.Errorf("a second encoding differs:\n %s\n %s", again, b)
	}
}

func TestV2ConstantsAreDistinct(t *testing.T) {
	for name, group := range map[string][]string{
		"kinds":    {KindCommand, KindSnapshot, KindRestore, KindExport, KindStop, KindInterrupted},
		"statuses": {StatusExited, StatusSignalled, StatusKilled, StatusExecFailed, StatusSetupFailed},
		"kills":    {KillWallTimeout, KillOOM, KillCancelled, KillStopped, KillDiskFloor, KillSupervisorLost, KillInitLost},
		"scopes":   {ScopeWorkload, ScopeInitAndWorkload, ScopeRuntimeAndWorkload},
		"exports":  {ExportComplete, ExportTruncated},
		"reasons":  {FlowNotAllowed, FlowSpecialAddress, FlowSNIMismatch, FlowNotTLS, FlowBadRequest, FlowResolveFailed, FlowDialFailed, FlowLimit},
		"stops":    {StopRequested, StopClientGone, StopShutdown, StopServiceLost, StopError},
		"types":    {TypeFile, TypeDir, TypeSymlink, TypeOther, TypeWhiteout, TypeOpaque},
		"budgets":  {DiffReasonEntries, DiffReasonBytes, DiffReasonDepth, DiffReasonPath, DiffReasonHashBudget, DiffReasonScan, DiffReasonCancelled},
		"skips":    {SkipUnreadable, SkipTooLarge, SkipHashBudget, SkipTooDeep, SkipPathTooLong},
	} {
		seen := map[string]bool{}
		for _, v := range group {
			if v == "" || seen[v] {
				t.Errorf("%s: %q is empty or used twice", name, v)
			}
			seen[v] = true
		}
	}
	if len(KindCommand) == 0 || SchemaV2 == SchemaV1 {
		t.Error("schema v2 is not told apart from v1")
	}
}

// TestV2ExportRecordSaysWhatItLeftOut: an export record is never complete by
// omission. The status is always there, and a manifest that was cut short
// carries the reasons and a count.
func TestV2ExportRecordSaysWhatItLeftOut(t *testing.T) {
	rec := RecordV2{Schema: SchemaV2, Kind: KindExport, Export: &ExportV2{
		ManifestSHA256: strings.Repeat("a", 64), WorkspaceManifestSHA256: strings.Repeat("b", 64),
		Status: ExportTruncated, Reasons: []string{DiffReasonEntries, DiffReasonPath}, Entries: 200000, Bytes: 4096, Skipped: 3, Omitted: 17,
	}}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if want := `"status":"truncated","reasons":["entries","path"],"entries":200000,"bytes":4096,"skipped":3,"omitted":17}`; !bytes.Contains(b, []byte(want)) {
		t.Errorf("the export block lacks %s:\n%s", want, b)
	}
	var back RecordV2
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&back); err != nil || !reflect.DeepEqual(back, rec) {
		t.Errorf("read back %+v, %v", back.Export, err)
	}
	if MaxSupersededEntries <= 0 || MaxSupersededBytes <= 0 || MaxXattrNames != 64 {
		t.Error("the lists of a record have no bound")
	}
}

// TestNamesChosenInASandbox covers the rules for names that JSON cannot
// carry and for the order of a list of names.
func TestNamesChosenInASandbox(t *testing.T) {
	// A name that is not valid UTF-8 is quoted, byte for byte, and reads
	// back to the same bytes.
	for _, raw := range []string{"abc", "", "dir/été.txt", "a\xffb", "\xfe", "tab\there", `"quoted"`, "a\x00b", "\xed\xa0\x80"} {
		text, escaped := EscapeName(raw)
		if escaped == utf8.ValidString(raw) {
			t.Errorf("EscapeName(%q) escaped = %v", raw, escaped)
		}
		if !utf8.ValidString(text) {
			t.Errorf("EscapeName(%q) = %q, which JSON would rewrite", raw, text)
		}
		back, err := UnescapeName(text, escaped)
		if err != nil || back != raw {
			t.Errorf("EscapeName(%q) = %q, %v, which reads back as %q, %v", raw, text, escaped, back, err)
		}
		b, err := json.Marshal(text)
		var viaJSON string
		if err != nil || json.Unmarshal(b, &viaJSON) != nil || viaJSON != text {
			t.Errorf("the recorded text %q does not survive JSON: %s, %v", text, b, err)
		}
	}

	// The case the flag exists for: a valid name spelled like the quoted
	// form of another name. Their texts are equal and they are two names.
	other := "abc\xff"
	quoted, escaped := EscapeName(other)
	lookalike, plain := EscapeName(quoted)
	if !escaped || plain || quoted != lookalike {
		t.Fatalf("EscapeName gives (%q, %v) and (%q, %v)", quoted, escaped, lookalike, plain)
	}
	if !NameLess(lookalike, false, quoted, true) || NameLess(quoted, true, lookalike, false) {
		t.Error("two names with the same text are not ordered by their flag")
	}

	// The order: plain names first, by bytes; then escaped ones, by bytes.
	type name struct {
		text    string
		escaped bool
	}
	sorted := []name{{"", false}, {`"a"`, false}, {"a", false}, {"a/b", false}, {"b", false}, {"é", false}, {`"\xff"`, true}, {`"a\xff"`, true}, {`"b\xfe"`, true}}
	for i, a := range sorted {
		for j, b := range sorted {
			if got, want := NameLess(a.text, a.escaped, b.text, b.escaped), i < j; got != want {
				t.Errorf("NameLess(%v, %v) = %v, want %v", a, b, got, want)
			}
		}
	}

	// Attribute names: one flag for the list, so the text itself says
	// whether it is quoted.
	for raw, want := range map[string]string{
		"user.comment":   "user.comment",
		"security.ima":   "security.ima",
		"user.\xff":      `"user.\xff"`,
		`"user.x"`:       `"\"user.x\""`,
		`"`:              `"\""`,
		"user.caf\u00e9": "user.caf\u00e9",
		"":               "",
	} {
		text, escaped := EscapeXattr(raw)
		if text != want || escaped != strings.HasPrefix(text, `"`) {
			t.Errorf("EscapeXattr(%q) = %q, %v; want %q", raw, text, escaped, want)
		}
		back, err := UnescapeXattr(text)
		if err != nil || back != raw {
			t.Errorf("the recorded attribute name %q reads back as %q, %v; want %q", text, back, err, raw)
		}
	}
	// Two different attribute names never have the same recorded text.
	seen := map[string]string{}
	for _, raw := range []string{"user.a", `"user.a"`, "user.\xff", `"user.\xff"`, `user."`, `\"user.a\"`, `"\"user.a\""`} {
		text, _ := EscapeXattr(raw)
		if prev, dup := seen[text]; dup {
			t.Errorf("the attribute names %q and %q are both recorded as %q", prev, raw, text)
		}
		seen[text] = raw
	}
	if _, err := UnescapeXattr(`"cut short`); err == nil {
		t.Error("a quoted attribute name that is not closed was read back")
	}
}
