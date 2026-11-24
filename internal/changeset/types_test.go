package changeset

import (
	"bytes"
	"encoding/json"
	"errors"
	"path"
	"reflect"
	"strings"
	"testing"

	"github.com/camilbenameur/sandmeter/internal/ids"
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
	return Export{Format: ExportFormat, Session: sess, WorkspaceManifestSHA256: hashA, Entries: []ExportEntry{
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
	if !bytes.HasPrefix(b, []byte(`{"format":"sandmeter.export/1","session":"`+sess+`","workspace_manifest_sha256":"`+hashA+`","entries":[{"path":"README.md","path_escaped":false,"op":"modify",`)) {
		t.Errorf("canonical bytes start with %s", b[:200])
	}
	h, err := m.Hash()
	if err != nil || h != HashBytes(b) {
		t.Errorf("Hash = %q, %v", h, err)
	}
	var back Export
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
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
	empty, _ := Export{Format: ExportFormat, Session: sess, WorkspaceManifestSHA256: hashA}.Canonical()
	if !bytes.HasSuffix(empty, []byte(`"entries":[]}`)) {
		t.Errorf("an export with no change: %s", empty)
	}
}

func TestExportAcceptsAnEscapedName(t *testing.T) {
	m := goodExport()
	m.Entries = []ExportEntry{
		{Path: `"bad\xffname"`, PathEscaped: true, Op: OpAdd, Type: TypeFile, Size: 3, Skipped: SkippedName},
		{Path: "ok", Op: OpAdd, Type: TypeDir},
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
		// Ordinary files, including names that merely contain a sensitive one.
		{"src/main.go", TierOrdinary},
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
