package ctl

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/camilbenameur/sandmeter/internal/exit"
	"github.com/camilbenameur/sandmeter/internal/hostprobe"
	"github.com/camilbenameur/sandmeter/internal/ids"
	"github.com/camilbenameur/sandmeter/policy"
	"github.com/camilbenameur/sandmeter/receipt"
)

func TestFrameBounds(t *testing.T) {
	seen := map[FrameType]bool{}
	for typ, want := range map[FrameType]int{
		FrameMessage: MaxMessage, FrameStdout: MaxChunk, FrameStderr: MaxChunk, FrameData: MaxChunk, FrameEnd: 0,
	} {
		if seen[typ] {
			t.Errorf("frame type %q is used twice", typ)
		}
		seen[typ] = true
		if got, ok := MaxPayload(typ); !ok || got != want {
			t.Errorf("MaxPayload(%q) = %d, %v, want %d", typ, got, ok, want)
		}
	}
	for _, unknown := range []FrameType{0, 'I', 'm', 0xff} {
		if _, ok := MaxPayload(unknown); ok {
			t.Errorf("MaxPayload knows the frame type %q", unknown)
		}
	}
	// A message at every bound at once fits in a message frame even when
	// JSON spends six bytes on each of its bytes, with room for the rest.
	if worst := 6 * (MaxArgvBytes + MaxEnvBytes + MaxPolicyBytes + MaxRefBytes + MaxWorkdirBytes); worst+1<<20 > MaxMessage {
		t.Errorf("a message at its bounds can take %d bytes, more than a frame of %d holds", worst, MaxMessage)
	}
	if FrameHeaderLen != 1+4 {
		t.Error("a frame header is one byte of type and four of length")
	}
}

// TestEveryMessageTypeIsInTheTable reads this package's source: each type
// with a Kind method has one row in Kinds, and the row makes that type.
func TestEveryMessageTypeIsInTheTable(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "messages.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Kind" || fn.Recv == nil {
			continue
		}
		star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
		if !ok {
			t.Errorf("a Kind method has a receiver that is not a pointer")
			continue
		}
		declared[star.X.(*ast.Ident).Name] = true
	}
	if len(declared) < 30 {
		t.Fatalf("found %d message types in the source: the check below would pass on too little", len(declared))
	}
	seenKind, seenType := map[Kind]bool{}, map[string]bool{}
	for _, spec := range Kinds {
		if spec.Kind == "" || seenKind[spec.Kind] {
			t.Errorf("kind %q is empty or listed twice", spec.Kind)
		}
		seenKind[spec.Kind] = true
		m := spec.New()
		if m.Kind() != spec.Kind {
			t.Errorf("the row of %q makes a message of kind %q", spec.Kind, m.Kind())
		}
		name := reflect.TypeOf(m).Elem().Name()
		if seenType[name] {
			t.Errorf("type %s serves two kinds", name)
		}
		seenType[name] = true
		if !declared[name] {
			t.Errorf("the row of %q makes a %s, which has no Kind method in messages.go", spec.Kind, name)
		}
		if reflect.TypeOf(m).Elem().Size() > 0 && spec.New() == m {
			t.Errorf("the row of %q hands out the same message twice", spec.Kind)
		}
		if spec.FromClient != (spec.States != nil) {
			t.Errorf("kind %q: a message of the client has states, a message of the worker has none", spec.Kind)
		}
		if got, ok := SpecOf(spec.Kind); !ok || got.Kind != spec.Kind {
			t.Errorf("SpecOf(%q) = %+v, %v", spec.Kind, got, ok)
		}
	}
	for name := range declared {
		if !seenType[name] {
			t.Errorf("message type %s is not in the table Kinds", name)
		}
	}
	if _, ok := SpecOf("no-such-kind"); ok {
		t.Error("SpecOf knows a kind that does not exist")
	}
}

// TestConversation is the order of the conversation, written out in full:
// for every state, exactly these messages of a client are legal.
func TestConversation(t *testing.T) {
	questions := []Kind{KindInfo, KindProbe, KindCheck, KindImages, KindSessions, KindRecords, KindRecord}
	legal := map[State][]Kind{
		StateHello:   {KindHello},
		StateOpen:    append([]Kind{KindStart}, questions...),
		StateStream:  {KindAbort},
		StateIdle:    append([]Kind{KindRefresh, KindRun, KindSnapshot, KindRestore, KindChanges, KindExport, KindStop}, questions...),
		StateRunning: {KindCancel},
		StateEnded:   questions,
	}
	for state, kinds := range legal {
		want := map[Kind]bool{}
		for _, k := range kinds {
			want[k] = true
		}
		for _, spec := range Kinds {
			if got := Legal(state, spec.Kind); got != want[spec.Kind] {
				t.Errorf("%s: Legal(%q) = %v, want %v", state, spec.Kind, got, want[spec.Kind])
			}
		}
		if state.String() == "unknown state" {
			t.Errorf("state %d has no name", state)
		}
	}
	if len(legal) != 6 || State(6).String() != "unknown state" {
		t.Error("a state was added without this test")
	}
	// At most one session per connection: nothing brings a conversation back
	// to where a start is legal.
	for _, s := range []State{StateHello, StateStream, StateIdle, StateRunning, StateEnded} {
		if Legal(s, KindStart) {
			t.Errorf("a start is legal %s", s)
		}
	}
	// A message only the worker sends is never legal from a client.
	for _, spec := range Kinds {
		if spec.FromClient {
			continue
		}
		for s := StateHello; s <= StateEnded; s++ {
			if Legal(s, spec.Kind) {
				t.Errorf("a client may send %q %s", spec.Kind, s)
			}
		}
	}
	if Legal(StateIdle, "no-such-kind") {
		t.Error("an unknown kind is legal")
	}
}

// stringFieldsOfRequests is the reviewed list of every string a client can
// put in a message, with what it is. None is a path on the host and none
// names a host object. A new string field in a request fails the test below
// until it is added here, which is the moment to ask what it can name.
var stringFieldsOfRequests = map[string]string{
	"Hello.Build.Version": "build identity, shown and logged",
	"Hello.Build.Commit":  "build identity, shown and logged",
	"Check.Policy":        "text of a policy file",
	"Check.Backend":       "backend name, compared with the enabled ones",
	"Check.Image":         "image reference, checked against the operator's list",
	"Start.Policy":        "text of a policy file",
	"Start.Image":         "image reference, checked against the operator's list",
	"Start.Backend":       "backend name, compared with the enabled ones",
	"Start.Env.Name":      "environment variable name",
	"Start.Env.Value":     "environment variable value",
	"Abort.Reason":        "free text for the log",
	"Run.Argv":            "the command, executed inside the sandbox",
	"Run.Workdir":         "a path inside the sandbox",
	"Run.Env.Name":        "environment variable name",
	"Run.Env.Value":       "environment variable value",
}

// walk visits the leaf fields of a message type.
func walk(t *testing.T, typ reflect.Type, prefix string, visit func(path string, f reflect.StructField, leaf reflect.Type)) {
	t.Helper()
	for i := range typ.NumField() {
		f := typ.Field(i)
		path := prefix + "." + f.Name
		if f.Anonymous {
			path = prefix
		}
		leaf := f.Type
		for leaf.Kind() == reflect.Pointer || leaf.Kind() == reflect.Slice || leaf.Kind() == reflect.Array && leaf != reflect.TypeFor[ids.ID]() {
			leaf = leaf.Elem()
		}
		if leaf.Kind() == reflect.Struct && leaf.PkgPath() == typ.PkgPath() {
			walk(t, leaf, path, visit)
			continue
		}
		visit(path, f, leaf)
	}
}

// TestNoRequestNamesAHostPathOrCarriesADescriptor is the boundary of the
// root side stated on the types: what a client can send is numbers, flags,
// identifiers with one parser, and the strings of the reviewed list.
func TestNoRequestNamesAHostPathOrCarriesADescriptor(t *testing.T) {
	seen := map[string]bool{}
	for _, spec := range Kinds {
		if !spec.FromClient {
			continue
		}
		typ := reflect.TypeOf(spec.New()).Elem()
		walk(t, typ, typ.Name(), func(path string, f reflect.StructField, leaf reflect.Type) {
			switch {
			case leaf == reflect.TypeFor[ids.ID]():
				// An identifier: its only text form is 32 hexadecimal digits.
			case leaf.Kind() == reflect.String:
				seen[path] = true
				if _, ok := stringFieldsOfRequests[path]; !ok {
					t.Errorf("%s is a string a client can send and is not in the reviewed list", path)
				}
			case leaf.Kind() == reflect.Bool, leaf.Kind() == reflect.Int, leaf.Kind() == reflect.Int64, leaf.Kind() == reflect.Uint64:
			default:
				t.Errorf("%s has type %s: a request holds numbers, flags, identifiers and reviewed strings only", path, f.Type)
			}
			lower := strings.ToLower(f.Name)
			for _, word := range []string{"path", "dir", "file", "fd", "socket", "home"} {
				if strings.Contains(lower, word) && path != "Run.Workdir" {
					t.Errorf("%s is named like a host path or a descriptor", path)
				}
			}
		})
	}
	for path := range stringFieldsOfRequests {
		if !seen[path] {
			t.Errorf("the reviewed list holds %s, which no request has", path)
		}
	}
}

// TestIdentifiersHaveOneParser checks that every field that names a session
// or a snapshot is an ids.ID, in requests and in answers alike, and that the
// decoder therefore refuses anything that is not 32 hexadecimal digits.
func TestIdentifiersHaveOneParser(t *testing.T) {
	for _, spec := range Kinds {
		typ := reflect.TypeOf(spec.New()).Elem()
		walk(t, typ, typ.Name(), func(path string, f reflect.StructField, leaf reflect.Type) {
			if (f.Name == "Session" || f.Name == "Snapshot" || f.Name == "ID") && leaf != reflect.TypeFor[ids.ID]() {
				t.Errorf("%s names a session or a snapshot and is a %s, not an ids.ID", path, leaf)
			}
		})
	}
	for _, hostile := range []string{
		`"../../etc"`, `"..%2F..%2Fetc"`, `"%2e%2e"`, `"a\u0000b"`, `""`,
		`"00112233445566778899aabbccddeeff0"`, `"00112233445566778899AABBCCDDEEFF"`,
		`"00000000000000000000000000000000"`, `" 00112233445566778899aabbccddeeff"`, `12`, `null`,
	} {
		var rec Record
		if err := json.Unmarshal([]byte(`{"session":`+hostile+`,"seq":1}`), &rec); err == nil && !rec.Session.IsZero() {
			t.Errorf("a record request decoded the session %s", hostile)
		}
		var res Restore
		if err := json.Unmarshal([]byte(`{"snapshot":`+hostile+`}`), &res); err == nil && !res.Snapshot.IsZero() {
			t.Errorf("a restore request decoded the snapshot %s", hostile)
		}
	}
	// The zero identifier has no text form: a request cannot be encoded
	// with one where one is required.
	if _, err := json.Marshal(Record{Seq: 1}); err == nil {
		t.Error("a record request without a session was encoded")
	}
	// A restore to the image leaves the snapshot out.
	if b, err := json.Marshal(Restore{}); err != nil || string(b) != `{}` {
		t.Errorf("Restore{} encodes as %s, %v", b, err)
	}
}

func strict(b []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(into)
}

// TestMessagesReadBack encodes one filled message of each kind in the form a
// message frame carries, and decodes it strictly to the same value.
func TestMessagesReadBack(t *testing.T) {
	id, _ := ids.Parse("00112233445566778899aabbccddeeff")
	snap, _ := ids.Parse("ffeeddccbbaa99887766554433221100")
	code, sig := 137, 9
	hash := strings.Repeat("ab", 32)
	report := hostprobe.Blank()
	samples := []Message{
		&Hello{Protocol: Protocol, Build: Build{Version: "0.1.0", Commit: "abc1234"}},
		&Info{},
		&InfoReply{Mode: ModeService, Build: Build{Version: "0.1.0"}, UID: 1000,
			Backends:     []BackendInfo{{Name: policy.BackendNative, Isolation: "linux namespaces", Scope: receipt.ScopeInitAndWorkload}},
			DefaultImage: "example.test/base@sha256:" + hash, Ceiling: policy.BuiltinCeiling(), CeilingSHA256: hash,
			Budgets: Budgets{Sessions: 8, Commands: 4, WorkspaceBytes: 2 << 30, WorkspaceEntries: 200000, ReceiptBytes: 1 << 30, Connections: 16},
			KeyID:   "k1", PublicKey: "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"},
		&Probe{},
		&ProbeReply{Report: report, Capabilities: []policy.Capabilities{report.Capabilities(policy.BackendNative)}},
		&Check{Policy: "version = 2\n", Backend: policy.BackendNative, Image: "example.test/base:1"},
		&CheckReply{Reasons: []Reason{{Code: CodePolicyRefused, Key: "limits.memory", Text: "8GiB is above the ceiling of 512MiB"}}, Backend: policy.BackendNative, Policy: json.RawMessage("null"), CeilingSHA256: hash},
		&Images{},
		&ImagesReply{Default: "example.test/base@sha256:" + hash, Images: []ImageInfo{{Reference: "example.test/base:1", Digest: "sha256:" + hash}}, Allow: []string{"example.test/*"}, PullAllowed: true},
		&Sessions{},
		&SessionsReply{Sessions: []SessionInfo{{ID: id, Created: time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC), Live: true, LastSeq: 4}}},
		&Records{Session: id, From: 2},
		&RecordsReply{Session: id, Records: []RecordInfo{{Seq: 2, Kind: receipt.KindCommand, Bytes: 4096}}, More: true, Pending: []uint64{3}},
		&Record{Session: id, Seq: 2},
		&RecordReply{RecordInfo: RecordInfo{Seq: 2, Kind: receipt.KindCommand, Bytes: 4096}},
		&Start{Policy: "version = 2\n", Image: "example.test/base:1", Backend: policy.BackendNative, Workspace: true, Env: []EnvVar{{Name: "TOKEN", Value: "s3cret"}}},
		&Accept{MaxBytes: 2 << 30, MaxEntries: 200000},
		&Abort{Reason: "a file changed while it was read"},
		&Started{Session: id, Backend: policy.BackendNative, ImageRequested: "example.test/base:1", ImageDigest: "sha256:" + hash,
			Policy: json.RawMessage(`{"version":2}`), PolicySHA256: hash, CeilingSHA256: hash,
			Workspace: &WorkspaceInfo{ManifestSHA256: hash, Entries: 12, Bytes: 3400}},
		&Refresh{},
		&Refreshed{Workspace: WorkspaceInfo{ManifestSHA256: hash, Entries: 12, Bytes: 3500},
			Superseded: []receipt.SupersededV2{{Path: "src/x.go", Type: receipt.TypeFile, SHA256: hash, Layer: "upper"}}},
		&Run{Argv: []string{"go", "test", "./..."}, TimeoutMS: 30000, Workdir: "/workspace", Env: []EnvVar{{Name: "CI", Value: "1"}}},
		&Cancel{},
		&Result{Seq: 3, Outcome: receipt.OutcomeV2{Status: receipt.StatusKilled, ExitCode: &code, Signal: &sig, KillReason: receipt.KillOOM},
			DurationMS: 1200, Stdout: receipt.StreamV2{SHA256: hash, Bytes: 10, Delivered: 10}, Stderr: receipt.StreamV2{SHA256: hash}},
		&Snapshot{},
		&Snapshotted{Snapshot: snap, Seq: 4},
		&Restore{Snapshot: snap},
		&Restored{Seq: 5},
		&Changes{},
		&ChangesReply{Entries: 3, Bytes: 512},
		&Export{},
		&ExportReply{ManifestSHA256: hash},
		&Exported{Seq: 6, ManifestSHA256: hash, Entries: 3, Skipped: 1, Bytes: 2048},
		&Stop{},
		&Stopped{Seq: 7},
		&Error{Code: CodeBudget, Message: "the session budget of uid 1000 is spent", Reasons: []Reason{{Code: CodeBudget, Key: "sessions", Text: "8 of 8 in use"}}},
	}
	covered := map[Kind]bool{}
	for _, m := range samples {
		covered[m.Kind()] = true
		body, err := json.Marshal(m)
		if err != nil {
			t.Errorf("%s: %v", m.Kind(), err)
			continue
		}
		frame, err := json.Marshal(Envelope{Kind: m.Kind(), Body: body})
		if err != nil {
			t.Fatal(err)
		}
		var env Envelope
		if err := strict(frame, &env); err != nil {
			t.Fatal(err)
		}
		spec, ok := SpecOf(env.Kind)
		if !ok {
			t.Fatalf("kind %q is not in the table", env.Kind)
		}
		back := spec.New()
		if err := strict(env.Body, back); err != nil {
			t.Errorf("%s: strict decoding of %s: %v", m.Kind(), env.Body, err)
			continue
		}
		if !reflect.DeepEqual(back, m) {
			t.Errorf("%s: read back\n %+v\nwant\n %+v", m.Kind(), back, m)
		}
		// A member the type does not have is refused, never skipped.
		if err := strict([]byte(`{"surprise":1}`), spec.New()); err == nil {
			t.Errorf("%s: an unknown member was accepted", m.Kind())
		}
	}
	for _, spec := range Kinds {
		if !covered[spec.Kind] {
			t.Errorf("no sample of kind %q: a new message needs one here", spec.Kind)
		}
	}
}

func TestCodes(t *testing.T) {
	seen := map[Code]bool{}
	for _, c := range Codes {
		if c == "" || seen[c] {
			t.Errorf("code %q is empty or listed twice", c)
		}
		seen[c] = true
	}
	for code, want := range map[Code]int{
		CodeProtocol:      exit.Failure,
		CodeVersion:       exit.HostCannotRun,
		CodeInvalid:       exit.Usage,
		CodeNotFound:      exit.Failed,
		CodePolicyRefused: exit.PolicyRefused,
		CodeHost:          exit.HostCannotRun,
		CodeImage:         exit.Denied,
		CodeBudget:        exit.Denied,
		CodeDiskFloor:     exit.Denied,
		CodeWorkspace:     exit.Denied,
		CodeAborted:       exit.Failed,
		CodeSessionFailed: exit.Failure,
		CodeNotBuilt:      exit.Failure,
		CodeShutdown:      exit.HostCannotRun,
		CodeInternal:      exit.Failure,
		"from-the-future": exit.Failure,
	} {
		if got := code.ExitStatus(); got != want {
			t.Errorf("%q exits with %d, want %d", code, got, want)
		}
		if code != "from-the-future" && !seen[code] {
			t.Errorf("code %q is not in the list Codes", code)
		}
	}
	if len(seen) != 15 {
		t.Errorf("Codes has %d entries: the closed list changed without this test", len(seen))
	}
}
