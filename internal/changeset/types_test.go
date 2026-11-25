package changeset

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/camilbenameur/sandmeter/internal/ids"
	"github.com/camilbenameur/sandmeter/receipt"
)

const (
	hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	sess  = "00112233445566778899aabbccddeeff"
)

func TestCheckPath(t *testing.T) {
	for _, good := range []string{"a", "a/b", "src/x.go", ".git/hooks/pre-commit", "a b", "é/€", "...", "a/...", strings.Repeat("x", MaxNameBytes)} {
		if err := CheckPath(good); err != nil {
			t.Errorf("CheckPath(%q) = %v", good, err)
		}
	}
	deep := strings.TrimSuffix(strings.Repeat("d/", MaxDepth+1), "/")
	for name, bad := range map[string]string{
		"empty":            "",
		"absolute":         "/etc/passwd",
		"dot":              ".",
		"dot dot":          "..",
		"leading dot dot":  "../x",
		"inner dot dot":    "a/../../x",
		"hidden dot dot":   "a/b/..",
		"dot component":    "a/./b",
		"doubled slash":    "a//b",
		"trailing slash":   "a/",
		"nul":              "a\x00b",
		"not utf-8":        "a\xffb",
		"too long":         strings.Repeat("a/", MaxPathBytes/2) + "a",
		"long component":   strings.Repeat("x", MaxNameBytes+1),
		"too deep":         deep,
		"only a separator": "/",
	} {
		if err := CheckPath(bad); err == nil {
			t.Errorf("%s: CheckPath(%q) accepted it", name, bad)
		}
	}
}

func goodImport() Import {
	return Import{Format: ImportFormat, Entries: []ImportEntry{
		{Path: "README.md", Type: TypeFile, Mode: 0o644, Size: 12, SHA256: hashA},
		{Path: "bin", Type: TypeDir, Mode: 0o755},
		{Path: "bin/run", Type: TypeFile, Mode: 0o755, Size: 3, SHA256: hashB},
		{Path: "link", Type: TypeSymlink, Mode: 0o777, Target: "../outside"},
	}}
}

func TestImportCanonicalAndHash(t *testing.T) {
	m := goodImport()
	b, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"format":"sandmeter.import/1","entries":[` +
		`{"path":"README.md","type":"file","mode":420,"size":12,"sha256":"` + hashA + `","target":""},` +
		`{"path":"bin","type":"dir","mode":493,"size":0,"sha256":"","target":""},` +
		`{"path":"bin/run","type":"file","mode":493,"size":3,"sha256":"` + hashB + `","target":""},` +
		`{"path":"link","type":"symlink","mode":511,"size":0,"sha256":"","target":"../outside"}]}`
	if string(b) != want {
		t.Errorf("canonical bytes:\n %s\nwant\n %s", b, want)
	}
	h, err := m.Hash()
	if err != nil || h != HashBytes(b) || len(h) != 64 {
		t.Errorf("Hash = %q, %v", h, err)
	}
	// The bytes read back to the same manifest, strictly.
	var back Import
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&back); err != nil || !reflect.DeepEqual(back, m) {
		t.Errorf("read back %+v, %v", back, err)
	}
	if entries, size := m.Totals(); entries != 4 || size != 15 {
		t.Errorf("Totals = %d, %d", entries, size)
	}

	// An empty project is "entries":[] whether the slice is nil or not, so
	// that both ends hash the same bytes.
	a, _ := Import{Format: ImportFormat}.Canonical()
	c, _ := Import{Format: ImportFormat, Entries: []ImportEntry{}}.Canonical()
	if string(a) != `{"format":"sandmeter.import/1","entries":[]}` || !bytes.Equal(a, c) {
		t.Errorf("empty manifests: %s and %s", a, c)
	}
}

func TestImportLookup(t *testing.T) {
	m := goodImport()
	for _, e := range m.Entries {
		if got, ok := m.Lookup(e.Path); !ok || got != e {
			t.Errorf("Lookup(%q) = %+v, %v", e.Path, got, ok)
		}
	}
	for _, absent := range []string{"", "README", "README.md/x", "bin/", "zzz", "A"} {
		if _, ok := m.Lookup(absent); ok {
			t.Errorf("Lookup(%q) found an entry", absent)
		}
	}
}

func TestImportValidateRefuses(t *testing.T) {
	mutate := func(f func(*Import)) Import {
		m := goodImport()
		f(&m)
		return m
	}
	for name, m := range map[string]Import{
		"another format":      mutate(func(m *Import) { m.Format = "sandmeter.import/2" }),
		"unsorted":            mutate(func(m *Import) { m.Entries[0], m.Entries[1] = m.Entries[1], m.Entries[0] }),
		"a path twice":        mutate(func(m *Import) { m.Entries[2].Path = "bin" }),
		"escaping path":       mutate(func(m *Import) { m.Entries[0].Path = "../README.md" }),
		"absolute path":       mutate(func(m *Import) { m.Entries[0].Path = "/README.md" }),
		"setuid bit":          mutate(func(m *Import) { m.Entries[2].Mode = 0o4755 }),
		"file without hash":   mutate(func(m *Import) { m.Entries[0].SHA256 = "" }),
		"upper-case hash":     mutate(func(m *Import) { m.Entries[0].SHA256 = strings.ToUpper(hashA) }),
		"short hash":          mutate(func(m *Import) { m.Entries[0].SHA256 = hashA[:63] }),
		"negative size":       mutate(func(m *Import) { m.Entries[0].Size = -1 }),
		"file with target":    mutate(func(m *Import) { m.Entries[0].Target = "x" }),
		"dir with size":       mutate(func(m *Import) { m.Entries[1].Size = 1 }),
		"dir with hash":       mutate(func(m *Import) { m.Entries[1].SHA256 = hashA }),
		"link with hash":      mutate(func(m *Import) { m.Entries[3].SHA256 = hashA }),
		"link without target": mutate(func(m *Import) { m.Entries[3].Target = "" }),
		"special file":        mutate(func(m *Import) { m.Entries[0] = ImportEntry{Path: "README.md", Type: TypeOther} }),
		"unknown type":        mutate(func(m *Import) { m.Entries[0].Type = "socket" }),
		"long link target":    mutate(func(m *Import) { m.Entries[3].Target = strings.Repeat("x", MaxPathBytes+1) }),
	} {
		if err := m.Validate(); !errors.Is(err, ErrManifest) {
			t.Errorf("%s: Validate = %v, want ErrManifest", name, err)
		}
		if _, err := m.Hash(); err == nil {
			t.Errorf("%s: a manifest that does not validate was hashed", name)
		}
	}
	big := Import{Format: ImportFormat, Entries: make([]ImportEntry, MaxEntries+1)}
	if err := big.Validate(); !errors.Is(err, ErrManifest) || !strings.Contains(err.Error(), "entries") {
		t.Errorf("too many entries: %v", err)
	}
}

func goodExport() Export {
	return Export{Format: ExportFormat, Session: sess, WorkspaceManifestSHA256: hashA, Status: StatusComplete, Entries: []ExportEntry{
		{Path: "README.md", Op: OpModify, Type: TypeFile, Mode: 0o644, Size: 20, SHA256: hashB, BaseSHA256: hashA},
		{Path: "bin/old", Op: OpDelete, Type: TypeFile, BaseSHA256: hashB},
		{Path: "dev", Op: OpAdd, Type: TypeOther, Skipped: SkippedSpecial},
		{Path: "huge.bin", Op: OpAdd, Type: TypeFile, Mode: 0o644, Size: 1 << 40, Skipped: SkippedUnhashed},
		{Path: "new", Op: OpAdd, Type: TypeDir, Mode: 0o755},
		{Path: "new/link", Op: OpAdd, Type: TypeSymlink, Mode: 0o777, Target: "/etc/passwd"},
		{Path: "new/tool.sh", Op: OpAdd, Type: TypeFile, Mode: 0o755, Size: 7, SHA256: hashA},
	}}
}

func TestExportCanonicalHashAndTotals(t *testing.T) {
	m := goodExport()
	b, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(b, []byte(`{"format":"sandmeter.export/1","session":"`+sess+`","workspace_manifest_sha256":"`+hashA+`","status":"complete","reasons":[],"omitted":0,"entries":[{"path":"README.md","path_escaped":false,"path_bytes":0,"path_sha256":"","op":"modify",`)) {
		t.Errorf("canonical bytes start with %s", b[:300])
	}
	h, err := m.Hash()
	if err != nil || h != HashBytes(b) {
		t.Errorf("Hash = %q, %v", h, err)
	}
	var back Export
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	m.Reasons = []string{} // the canonical form spells the empty list out
	if err := dec.Decode(&back); err != nil || !reflect.DeepEqual(back, m) {
		t.Errorf("read back %+v, %v", back, err)
	}
	entries, skipped, size := m.Totals()
	// A file that is only listed sends no body, whatever size it claims.
	if entries != 7 || skipped != 2 || size != 27 {
		t.Errorf("Totals = %d, %d, %d", entries, skipped, size)
	}
	var bodies []string
	for _, e := range m.Entries {
		if e.HasBody() {
			bodies = append(bodies, e.Path)
		}
	}
	if strings.Join(bodies, " ") != "README.md new/tool.sh" {
		t.Errorf("entries with a body: %v", bodies)
	}
	empty, err := Export{Format: ExportFormat, Session: sess, WorkspaceManifestSHA256: hashA, Status: StatusComplete}.Canonical()
	if err != nil || !bytes.HasSuffix(empty, []byte(`"status":"complete","reasons":[],"omitted":0,"entries":[]}`)) {
		t.Errorf("an export with no change: %s, %v", empty, err)
	}
}

// TestExportSaysWhetherItIsComplete: a manifest is never complete by
// default. A program in a sandbox can always change more paths than a
// manifest holds; what is left out is then said, in the signed bytes.
func TestExportSaysWhetherItIsComplete(t *testing.T) {
	// The zero status is not "complete".
	m := goodExport()
	m.Status = ""
	if err := m.Validate(); !errors.Is(err, ErrManifest) || !strings.Contains(err.Error(), "status") {
		t.Errorf("a manifest without a status: %v", err)
	}

	m = goodExport()
	m.Status, m.Reasons, m.Omitted = StatusTruncated, []string{receipt.DiffReasonEntries, receipt.DiffReasonDepth}, 41
	b, err := m.Canonical()
	if err != nil {
		t.Fatalf("a truncated manifest: %v", err)
	}
	if !bytes.Contains(b, []byte(`"status":"truncated","reasons":["entries","depth"],"omitted":41,`)) {
		t.Errorf("the canonical bytes do not say what was left out: %s", b[:300])
	}
	whole := goodExport()
	if h1, _ := m.Hash(); h1 == "" {
		t.Error("a truncated manifest has no hash")
	} else if h2, _ := whole.Hash(); h1 == h2 {
		t.Error("a truncated manifest and a complete one with the same entries have the same hash")
	}
	// A lower bound of zero is legal: a directory that was not entered was
	// not counted either.
	m.Omitted = 0
	if err := m.Validate(); err != nil {
		t.Errorf("a truncated manifest with nothing counted: %v", err)
	}

	for name, mutate := range map[string]func(*Export){
		"complete with a reason":      func(m *Export) { m.Reasons = []string{receipt.DiffReasonEntries} },
		"complete with omitted paths": func(m *Export) { m.Omitted = 1 },
		"truncated without a reason":  func(m *Export) { m.Status = StatusTruncated },
		"an unknown reason":           func(m *Export) { m.Status, m.Reasons = StatusTruncated, []string{"because"} },
		"a reason that omits nothing": func(m *Export) { m.Status, m.Reasons = StatusTruncated, []string{receipt.DiffReasonHashBudget} },
		"a reason twice": func(m *Export) {
			m.Status, m.Reasons = StatusTruncated, []string{receipt.DiffReasonPath, receipt.DiffReasonPath}
		},
		"reasons out of order": func(m *Export) {
			m.Status, m.Reasons = StatusTruncated, []string{receipt.DiffReasonDepth, receipt.DiffReasonEntries}
		},
		"a negative count": func(m *Export) {
			m.Status, m.Reasons, m.Omitted = StatusTruncated, []string{receipt.DiffReasonScan}, -1
		},
		"an unknown status": func(m *Export) { m.Status = "partial" },
		"the diff's error":  func(m *Export) { m.Status = receipt.DiffError },
	} {
		m := goodExport()
		mutate(&m)
		if err := m.Validate(); !errors.Is(err, ErrManifest) {
			t.Errorf("%s: Validate = %v, want ErrManifest", name, err)
		}
	}
	// Every reason, in order, is accepted, and the list is the record's.
	m = goodExport()
	m.Status, m.Reasons = StatusTruncated, append([]string(nil), Reasons...)
	if err := m.Validate(); err != nil {
		t.Errorf("all reasons at once: %v", err)
	}
	if StatusComplete != receipt.ExportComplete || StatusTruncated != receipt.ExportTruncated || len(Reasons) != 6 {
		t.Error("the words of a manifest are not those of the export record")
	}
}

// TestExportOfMoreChangesThanAManifestHolds is the case of a session that
// creates more paths than MaxEntries: the manifest lists what fits and says
// that the rest is left out. Without that the export of such a session
// could only fail, or lie by omission.
func TestExportOfMoreChangesThanAManifestHolds(t *testing.T) {
	m := Export{Format: ExportFormat, Session: sess, WorkspaceManifestSHA256: hashA, Status: StatusTruncated,
		Reasons: []string{receipt.DiffReasonEntries}, Omitted: 1, Entries: make([]ExportEntry, MaxEntries)}
	for i := range m.Entries {
		m.Entries[i] = ExportEntry{Path: fmt.Sprintf("f%06d", i), Op: OpAdd, Type: TypeFile, Skipped: SkippedBudget}
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("a full manifest that says one path is left out: %v", err)
	}
	if entries, skipped, size := m.Totals(); entries != MaxEntries || skipped != MaxEntries || size != 0 {
		t.Errorf("Totals = %d, %d, %d", entries, skipped, size)
	}
	// The bound itself stands.
	m.Entries = append(m.Entries, ExportEntry{Path: "g", Op: OpAdd, Type: TypeFile, Skipped: SkippedBudget})
	if err := m.Validate(); !errors.Is(err, ErrManifest) {
		t.Errorf("one entry more than the bound: %v", err)
	}
}

// TestExportOfANameTooLongToCarry: twenty nested directories with names of
// 255 bytes make a path of more than MaxPathBytes, with one "mkdir -p". The
// manifest lists it by length and hash, and stays bounded.
func TestExportOfANameTooLongToCarry(t *testing.T) {
	long := strings.TrimSuffix(strings.Repeat(strings.Repeat("d", MaxNameBytes)+"/", 20), "/")
	if len(long) <= MaxPathBytes {
		t.Fatalf("the path is %d bytes long", len(long))
	}
	length, sum := LongName(long)
	want := sha256.Sum256([]byte(long))
	if length != int64(len(long)) || sum != hex.EncodeToString(want[:]) {
		t.Fatalf("LongName = %d, %s", length, sum)
	}

	m := goodExport()
	m.Entries = append(m.Entries, ExportEntry{PathBytes: length, PathSHA256: sum, Op: OpAdd, Type: TypeDir, Mode: 0o755, Skipped: SkippedPathTooLong})
	b, err := m.Canonical()
	if err != nil {
		t.Fatalf("a manifest with a name too long to carry: %v", err)
	}
	if len(b) > 4096 || !bytes.Contains(b, []byte(`"path":"","path_escaped":false,"path_bytes":`+strconv.Itoa(len(long))+`,"path_sha256":"`+sum+`"`)) {
		t.Errorf("the entry is carried as %s", b[len(b)-400:])
	}
	if _, skipped, _ := m.Totals(); skipped != 3 {
		t.Errorf("the entry is not counted as skipped: %d", skipped)
	}
	if m.Entries[len(m.Entries)-1].HasBody() {
		t.Error("an entry without a name has a body")
	}

	// Carried in full, the same name is refused, whatever the entry says.
	for name, e := range map[string]ExportEntry{
		"as a path":          {Path: long, Op: OpAdd, Type: TypeDir},
		"skipped for name":   {Path: long, Op: OpAdd, Type: TypeDir, Skipped: SkippedName},
		"skipped for length": {Path: long, Op: OpAdd, Type: TypeDir, Skipped: SkippedPathTooLong},
		"with both":          {Path: "short", PathBytes: length, PathSHA256: sum, Op: OpAdd, Type: TypeDir, Skipped: SkippedPathTooLong},
		"not skipped":        {PathBytes: length, PathSHA256: sum, Op: OpAdd, Type: TypeDir},
		"another reason":     {PathBytes: length, PathSHA256: sum, Op: OpAdd, Type: TypeDir, Skipped: SkippedName},
		"without a hash":     {PathBytes: length, Op: OpAdd, Type: TypeDir, Skipped: SkippedPathTooLong},
		"without a length":   {PathSHA256: sum, Op: OpAdd, Type: TypeDir, Skipped: SkippedPathTooLong},
		"a length that fits": {PathBytes: MaxPathBytes, PathSHA256: sum, Op: OpAdd, Type: TypeDir, Skipped: SkippedPathTooLong},
		"escaped as well":    {PathEscaped: true, PathBytes: length, PathSHA256: sum, Op: OpAdd, Type: TypeDir, Skipped: SkippedPathTooLong},
		"a short name":       {Path: "ok", PathBytes: 2, Op: OpAdd, Type: TypeDir},
	} {
		m := goodExport()
		m.Entries = append(m.Entries, e)
		if err := m.Validate(); !errors.Is(err, ErrManifest) {
			t.Errorf("%s: Validate = %v, want ErrManifest", name, err)
		}
	}

	// Two such names are two entries, in the order of their hashes; the
	// same one twice is refused.
	_, other := LongName(long + "/x")
	pair := []ExportEntry{
		{PathBytes: length, PathSHA256: sum, Op: OpAdd, Type: TypeDir, Skipped: SkippedPathTooLong},
		{PathBytes: length + 2, PathSHA256: other, Op: OpAdd, Type: TypeFile, Skipped: SkippedPathTooLong},
	}
	sort.Slice(pair, func(i, j int) bool { return ExportLess(pair[i], pair[j]) })
	m = goodExport()
	m.Entries = append(m.Entries, pair...)
	if err := m.Validate(); err != nil {
		t.Errorf("two names too long to carry: %v", err)
	}
	m.Entries = append(m.Entries, pair[1])
	if err := m.Validate(); !errors.Is(err, ErrManifest) {
		t.Errorf("the same name twice: %v", err)
	}
}

// TestALinkTargetIsCarriedExactlyOrNotAtAll: the canonical bytes are JSON,
// which replaces a byte that is not UTF-8. A target with such a byte would
// be signed as another target, and two different targets would hash alike.
func TestALinkTargetIsCarriedExactlyOrNotAtAll(t *testing.T) {
	for name, target := range map[string]string{"not UTF-8": "x\xffy", "a NUL byte": "x\x00y", "both": "x\xffy\x00z"} {
		im := goodImport()
		im.Entries[3].Target = target
		if err := im.Validate(); !errors.Is(err, ErrManifest) {
			t.Errorf("import, %s: Validate = %v, want ErrManifest", name, err)
		}
		if _, err := im.Hash(); err == nil {
			t.Errorf("import, %s: a manifest with a target it cannot carry was hashed", name)
		}
		ex := goodExport()
		ex.Entries[5].Target = target
		if err := ex.Validate(); !errors.Is(err, ErrManifest) {
			t.Errorf("export, %s: Validate = %v, want ErrManifest", name, err)
		}
		// Marking the entry as skipped does not make the target acceptable.
		ex.Entries[5].Skipped = SkippedTarget
		if err := ex.Validate(); !errors.Is(err, ErrManifest) {
			t.Errorf("export, %s, skipped: Validate = %v, want ErrManifest", name, err)
		}
	}

	// How such a link is listed: without its target, and never exported.
	ex := goodExport()
	ex.Entries[5] = ExportEntry{Path: "new/link", Op: OpAdd, Type: TypeSymlink, Mode: 0o777, Skipped: SkippedTarget}
	if err := ex.Validate(); err != nil {
		t.Errorf("a link listed without its target: %v", err)
	}
	if _, skipped, _ := ex.Totals(); skipped != 3 {
		t.Errorf("the link is not counted as skipped: %d", skipped)
	}
	ex.Entries[5].Type = TypeFile
	if err := ex.Validate(); !errors.Is(err, ErrManifest) {
		t.Errorf("a regular file skipped for its link target: %v", err)
	}
}

// TestAPlainNameAndAQuotedNameWithTheSameText: a program in a sandbox can
// name one file with bytes that are not UTF-8 and another with the quoted
// spelling of the first. Both are listed; the manifest must not become
// impossible to build.
func TestAPlainNameAndAQuotedNameWithTheSameText(t *testing.T) {
	raw := "abc\xff"
	quoted := strconv.Quote(raw)
	if err := CheckPath(quoted); err != nil {
		t.Fatalf("the quoted spelling is itself a valid name: %v", err)
	}
	entries := []ExportEntry{
		{Path: quoted, PathEscaped: true, Op: OpAdd, Type: TypeFile, Size: 1, Skipped: SkippedName},
		{Path: quoted, Op: OpAdd, Type: TypeFile, Mode: 0o644, Size: 1, SHA256: hashA},
		{Path: "zzz", Op: OpAdd, Type: TypeDir},
		{Path: "abc", Op: OpAdd, Type: TypeDir},
	}
	sort.Slice(entries, func(i, j int) bool { return ExportLess(entries[i], entries[j]) })
	var order []string
	for _, e := range entries {
		order = append(order, fmt.Sprintf("%s/%v", e.Path, e.PathEscaped))
	}
	if got, want := strings.Join(order, " "), quoted+"/false abc/false zzz/false "+quoted+"/true"; got != want {
		t.Errorf("order %s, want %s", got, want)
	}
	m := goodExport()
	m.Entries = entries
	if err := m.Validate(); err != nil {
		t.Errorf("a plain name and a quoted one with the same text: %v", err)
	}
	// The same name twice is still refused, in each group.
	for _, dup := range []int{1, 3} {
		twice := goodExport()
		twice.Entries = append(append([]ExportEntry(nil), entries[:dup+1]...), entries[dup:]...)
		if err := twice.Validate(); !errors.Is(err, ErrManifest) {
			t.Errorf("entry %d twice: %v", dup, err)
		}
	}
	// An escaped name before a plain one is out of order.
	m.Entries = []ExportEntry{entries[3], entries[1]}
	if err := m.Validate(); !errors.Is(err, ErrManifest) {
		t.Errorf("an escaped name listed first: %v", err)
	}
}

func TestExportAcceptsAnEscapedName(t *testing.T) {
	m := goodExport()
	// Escaped names are listed after the plain ones.
	m.Entries = []ExportEntry{
		{Path: "ok", Op: OpAdd, Type: TypeDir},
		{Path: `"bad\xffname"`, PathEscaped: true, Op: OpAdd, Type: TypeFile, Size: 3, Skipped: SkippedName},
	}
	if err := m.Validate(); err != nil {
		t.Errorf("an escaped, skipped name: %v", err)
	}
}

func TestExportValidateRefuses(t *testing.T) {
	mutate := func(f func(*Export)) Export {
		m := goodExport()
		f(&m)
		return m
	}
	for name, m := range map[string]Export{
		"another format":          mutate(func(m *Export) { m.Format = ImportFormat }),
		"session not an id":       mutate(func(m *Export) { m.Session = "../../etc" }),
		"zero session":            mutate(func(m *Export) { m.Session = strings.Repeat("0", 32) }),
		"no base manifest":        mutate(func(m *Export) { m.WorkspaceManifestSHA256 = "" }),
		"unsorted":                mutate(func(m *Export) { m.Entries[0], m.Entries[1] = m.Entries[1], m.Entries[0] }),
		"a path twice":            mutate(func(m *Export) { m.Entries[1].Path = "README.md" }),
		"escaping path":           mutate(func(m *Export) { m.Entries[0].Path = "../../home/dev/.bashrc" }),
		"absolute path":           mutate(func(m *Export) { m.Entries[0].Path = "/etc/cron.d/x" }),
		"file without hash":       mutate(func(m *Export) { m.Entries[6].SHA256 = "" }),
		"setuid bit":              mutate(func(m *Export) { m.Entries[6].Mode = 0o4755 }),
		"special not skipped":     mutate(func(m *Export) { m.Entries[2].Skipped = "" }),
		"unknown skip reason":     mutate(func(m *Export) { m.Entries[2].Skipped = "because" }),
		"unknown operation":       mutate(func(m *Export) { m.Entries[0].Op = "chmod" }),
		"addition with a base":    mutate(func(m *Export) { m.Entries[6].BaseSHA256 = hashA }),
		"malformed base hash":     mutate(func(m *Export) { m.Entries[0].BaseSHA256 = "abc" }),
		"escaped but not skipped": mutate(func(m *Export) { m.Entries[4] = ExportEntry{Path: `"x"`, PathEscaped: true, Op: OpAdd, Type: TypeDir} }),
		"escaped and unquotable": mutate(func(m *Export) {
			m.Entries[4] = ExportEntry{Path: `not quoted`, PathEscaped: true, Op: OpAdd, Type: TypeDir, Skipped: SkippedName}
		}),
		"link without target": mutate(func(m *Export) { m.Entries[5].Target = "" }),
		"long link target":    mutate(func(m *Export) { m.Entries[5].Target = strings.Repeat("x", MaxPathBytes+1) }),
	} {
		if err := m.Validate(); !errors.Is(err, ErrManifest) {
			t.Errorf("%s: Validate = %v, want ErrManifest", name, err)
		}
	}
}

func TestClassify(t *testing.T) {
	for _, tc := range []struct {
		path string
		want Tier
	}{
		// Version-control internals: any depth, any case, directory or file.
		{".git/hooks/pre-commit", TierRefused},
		{".git", TierRefused},
		{".GIT/config", TierRefused},
		{".Git/hooks/post-checkout", TierRefused},
		{"vendor/lib/.git", TierRefused},
		{"a/b/.hg/hgrc", TierRefused},
		{"x/.svn/entries", TierRefused},
		{".gitmodules", TierRefused},
		{"sub/.gitattributes", TierRefused},
		// Auto-run configuration of agents, editors and CI.
		{".github/workflows/ci.yml", TierRefused},
		{".gitlab-ci.yml", TierRefused},
		{"Jenkinsfile", TierRefused},
		{".vscode/tasks.json", TierRefused},
		{"packages/app/.vscode/settings.json", TierRefused},
		{".idea/workspace.xml", TierRefused},
		{".devcontainer/devcontainer.json", TierRefused},
		{".husky/pre-commit", TierRefused},
		{".envrc", TierRefused},
		{".mcp.json", TierRefused},
		{"AGENTS.md", TierRefused},
		{"docs/agents.md", TierRefused},
		{".cursor/rules/x.mdc", TierRefused},
		{".pre-commit-config.yaml", TierRefused},
		// Build manifests.
		{"Makefile", TierHighlighted},
		{"makefile", TierHighlighted},
		{"sub/dir/package.json", TierHighlighted},
		{"go.mod", TierHighlighted},
		{"Cargo.toml", TierHighlighted},
		{".cargo/config.toml", TierHighlighted},
		{"pyproject.toml", TierHighlighted},
		{"tests/conftest.py", TierHighlighted},
		{"requirements-dev.txt", TierHighlighted},
		{"Dockerfile.prod", TierHighlighted},
		{"rules.mk", TierHighlighted},
		{"mise.toml", TierRefused},
		{".mise.toml", TierRefused},
		{"mise.local.toml", TierRefused},
		{".mise/config.toml", TierRefused},
		{"lefthook.yml", TierRefused},
		{"lefthook.yaml", TierRefused},
		{".lefthook.toml", TierRefused},
		{".zed/tasks.json", TierRefused},
		{".gitlab/ci/build.yml", TierRefused},
		{".windsurf/rules/style.md", TierRefused},
		{".clinerules", TierRefused},
		{".clinerules/01-style.md", TierRefused},
		// The same names as a filesystem that is less discerning than Linux
		// reads them: trailing dots and spaces dropped, a stream after a
		// colon dropped, letters folded, a backslash as a separator.
		{".git./hooks/pre-commit", TierRefused},
		{".git /hooks/pre-commit", TierRefused},
		{".git. . ./config", TierRefused},
		{".git::$INDEX_ALLOCATION/hooks/pre-commit", TierRefused},
		{".git:stream", TierRefused},
		{"sub/.GIT ./config", TierRefused},
		{".g\u0131t/hooks/pre-commit", TierRefused},
		{".\u212aeep/.hu\u017fky/pre-commit", TierRefused},
		{".github./workflows/ci.yml", TierRefused},
		{".vscode /tasks.json", TierRefused},
		{"AGENTS.md.", TierRefused},
		{"agents.md::$DATA", TierRefused},
		{".git\\hooks\\pre-commit", TierRefused},
		{"sub\\.vscode\\tasks.json", TierRefused},
		{"Makefile.", TierHighlighted},
		{"package.json ", TierHighlighted},
		// Short names: whatever they stand for is not in the name.
		{"git~1/hooks/pre-commit", TierRefused},
		{"GIT~1/config", TierRefused},
		{"git~2/config", TierRefused},
		{"git~12/config", TierRefused},
		{"gitmod~1", TierRefused},
		{"github~1/workflows/ci.yml", TierRefused},
		{"vscode~1/tasks.json", TierRefused},
		{"pre-co~1.yam", TierRefused},
		{"src/claude~1/settings.json", TierRefused},
		{"git~1.", TierRefused},
		// Characters that are not shown, and that some filesystems ignore.
		{".g\u200cit/hooks/pre-commit", TierRefused},
		{".git\u200d/config", TierRefused},
		{"\ufeff.git/config", TierRefused},
		{"src/ma\u00adin.go", TierRefused},
		{"a\u202eb.txt", TierRefused},
		// Names that are nothing but dots and spaces.
		{"...", TierRefused},
		{"a/. ./b", TierRefused},
		{"a/ /b", TierRefused},
		{":stream", TierRefused},
		// Ordinary files, including names that merely contain a sensitive one.
		{"src/main.go", TierOrdinary},
		{"notes.", TierOrdinary},
		{"a b/c d.txt", TierOrdinary},
		{"caf\u00e9/menu.txt", TierOrdinary},
		{"backup~", TierOrdinary},
		{"~", TierOrdinary},
		{"~1", TierOrdinary},
		{"file~x.txt", TierOrdinary},
		{"longername~1.txt", TierOrdinary},
		{"report~1.json5", TierOrdinary},
		{"mise.tomlx", TierOrdinary},
		{"promise.toml", TierOrdinary},
		{"README.md", TierOrdinary},
		{"gitignore", TierOrdinary},
		{".gitignore", TierOrdinary},
		{"docs/git/hooks.md", TierOrdinary},
		{"x.git", TierOrdinary},
		{".github.md", TierOrdinary},
		{"Makefile.bak", TierOrdinary},
		{"my-package.json", TierOrdinary},
		{"config.toml", TierOrdinary},
	} {
		got, rule := Classify(tc.path)
		if got != tc.want {
			t.Errorf("Classify(%q) = %v (rule %+v), want %v", tc.path, got, rule, tc.want)
		}
		if (got == TierOrdinary) != (rule == Rule{}) {
			t.Errorf("Classify(%q): tier %v with rule %+v", tc.path, got, rule)
		}
		if got != TierOrdinary && rule.Tier != got {
			t.Errorf("Classify(%q): tier %v from a rule of tier %v", tc.path, got, rule.Tier)
		}
	}
	// The strictest rule wins: a build manifest inside version-control data
	// is refused, not highlighted.
	if got, _ := Classify(".git/Makefile"); got != TierRefused {
		t.Errorf("a build manifest under .git is %v", got)
	}
}

func TestRulesTable(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Rules {
		key := r.Pattern
		if seen[strings.ToLower(key)] {
			t.Errorf("pattern %q is listed twice", r.Pattern)
		}
		seen[strings.ToLower(key)] = true
		if r.Tier != TierRefused && r.Tier != TierHighlighted {
			t.Errorf("rule %q has tier %v", r.Pattern, r.Tier)
		}
		if r.Why == "" || r.Pattern == "" || strings.Contains(r.Pattern, "/") {
			t.Errorf("rule %+v: a pattern without a slash and a reason are required", r)
		}
		switch r.Match {
		case MatchComponent, MatchBase:
			// A pattern is compared with normalised names: one that
			// normalisation would change, apart from its case, matches
			// nothing.
			if !strings.EqualFold(Normalise(r.Pattern), r.Pattern) {
				t.Errorf("rule %q can never match: names are compared as %q", r.Pattern, Normalise(r.Pattern))
			}
		case MatchForm:
			if r.Pattern != FormShortName && r.Pattern != FormIgnorable && r.Pattern != FormBlank {
				t.Errorf("rule %q names no form", r.Pattern)
			}
			if r.Tier != TierRefused {
				t.Errorf("rule %q: a name that may stand for another is refused, not highlighted", r.Pattern)
			}
		default:
			t.Errorf("rule %q has no way to match", r.Pattern)
		}
		if _, err := path.Match(r.Pattern, "x"); err != nil {
			t.Errorf("rule %q is not a valid pattern: %v", r.Pattern, err)
		}
		if r.Match == MatchComponent && strings.ContainsAny(r.Pattern, "*?[") {
			t.Errorf("rule %q: a component is compared for equality, not as a pattern", r.Pattern)
		}
	}
	// The three the product promises, whatever else the table holds.
	for _, vcs := range []string{".git", ".hg", ".svn"} {
		if tier, _ := Classify("deep/down/" + vcs + "/x"); tier != TierRefused {
			t.Errorf("%s is not refused at depth", vcs)
		}
	}
	for tier, want := range map[Tier]string{TierOrdinary: "ordinary", TierHighlighted: "highlighted", TierRefused: "refused"} {
		if tier.String() != want {
			t.Errorf("Tier(%d).String() = %q", tier, tier.String())
		}
	}
}

func TestSpoolNames(t *testing.T) {
	id, err := ids.Parse(sess)
	if err != nil {
		t.Fatal(err)
	}
	if got := SpoolSessionDir("/home/dev/.local/state/sandmeter/spool", id); got != "/home/dev/.local/state/sandmeter/spool/"+sess {
		t.Errorf("SpoolSessionDir = %q", got)
	}
	if SpoolRecordFile(7) != "0000000007.record.json" || SpoolStreamFile(7) != "0000000007.changeset" {
		t.Errorf("spool names: %q, %q", SpoolRecordFile(7), SpoolStreamFile(7))
	}
	if seq, stream, ok := ParseSpoolFile(SpoolRecordFile(12)); !ok || stream || seq != 12 {
		t.Errorf("record name read back as %d, %v, %v", seq, stream, ok)
	}
	if seq, stream, ok := ParseSpoolFile(SpoolStreamFile(12)); !ok || !stream || seq != 12 {
		t.Errorf("stream name read back as %d, %v, %v", seq, stream, ok)
	}
	for _, bad := range []string{"", SpoolImportFile, "7.changeset", "0000000000.changeset", "000000000x.record.json", "0000000007.changeset.tmp", "../0000000007.changeset", "0000000007.record"} {
		if _, _, ok := ParseSpoolFile(bad); ok {
			t.Errorf("ParseSpoolFile accepted %q", bad)
		}
	}
}

func TestNormalise(t *testing.T) {
	for in, want := range map[string]string{
		".git":                    ".git",
		".GIT":                    ".git",
		".git.":                   ".git",
		".git ":                   ".git",
		".git. . .":               ".git",
		".git::$INDEX_ALLOCATION": ".git",
		".git:x:y":                ".git",
		".git .:x":                ".git",
		"Makefile":                "makefile",
		"README.md":               "readme.md",
		".g\u0131t":               ".git",
		".\u017fvn":               ".svn",
		"\u212aube":               "kube",
		"\u00c9t\u00e9":           "\u00c9t\u00e9",
		"a.b.c":                   "a.b.c",
		" lead":                   " lead",
		"...":                     "",
		" ":                       "",
		":":                       "",
		"":                        "",
	} {
		if got := Normalise(in); got != want {
			t.Errorf("Normalise(%q) = %q, want %q", in, got, want)
		}
	}
}
