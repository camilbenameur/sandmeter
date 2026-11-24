// Package changeset defines how a project goes into a sandbox and how what
// the sandbox changed comes back out: the manifest of an import, the manifest
// of an exported change set, which paths are too sensitive to apply without
// being asked, and where the client keeps a change set until a person applies
// or discards it.
//
// This file is the contract: types, the canonical bytes that get hashed and
// signed, and pure helpers. It opens no file and writes nothing. The code
// that streams, spools, verifies, plans and applies lives beside it.
//
// # The two manifests
//
// An import manifest (Import) lists the project as the sandbox was given it:
// one entry per file, directory and symbolic link, with the hash of every
// regular file. The client computes one while it packs the project, and the
// service computes one from what it extracted; the service's hash is the one
// that is signed, in every command record, and the client compares.
//
// An export manifest (Export) lists what the session changed under the
// project directory, relative to an import manifest that it names by hash.
// Its own hash is what the signed export record carries. Applying a change
// set means: check the record's signature against a pinned key, check the
// manifest against the record, check every body against the manifest, and
// only then touch the project.
//
// # Who is trusted
//
// Every name, every link target and every byte of content in an export was
// chosen by a program in a sandbox. The manifests carry them as data. Nothing
// here makes a path safe to write: the code that applies a change set
// resolves each path under the project directory itself, one component at a
// time, and follows no link. CheckPath is a first filter, not that
// protection.
//
// # Sensitive paths
//
// Some files are executed or obeyed without anyone asking: version-control
// hooks, the configuration of editors, agents and CI. A change to one of them
// is how a contained program gets to run outside. Classify sorts a path into
// one of three tiers from a fixed table. The table is an aid to a reviewer
// and not a guarantee: no list of such files is complete, and whether a
// change is safe to build or run remains the reviewer's decision.
package changeset

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/camilbenameur/sandmeter/internal/ids"
)

// Formats of the two manifests. A manifest with another format is refused,
// never read as if it were this one.
const (
	ImportFormat = "sandmeter.import/1"
	ExportFormat = "sandmeter.export/1"
)

// StreamMagic is the first line of a change-set stream: the bytes that go
// from the service to the client's spool. After it come the length of the
// export manifest as four big-endian bytes, the canonical bytes of the
// manifest, and a tar archive of the bodies in the order of the manifest.
const StreamMagic = "sandmeter-changeset/1\n"

// Bounds that both ends of an import or an export hold. A manifest or a
// stream beyond one of them is refused whole.
const (
	// MaxEntries is the largest number of entries of a manifest.
	MaxEntries = 200_000
	// MaxManifestBytes is the largest size of the canonical bytes of a
	// manifest.
	MaxManifestBytes = 32 << 20
	// MaxPathBytes is the largest length of a path and of a link target, and
	// MaxNameBytes that of one component of a path.
	MaxPathBytes = 4096
	MaxNameBytes = 255
	// MaxDepth is the largest number of components of a path.
	MaxDepth = 256
)

// Types of an entry.
const (
	TypeFile    = "file"
	TypeDir     = "dir"
	TypeSymlink = "symlink"
	// TypeOther is anything else: a device, a FIFO, a socket. It occurs only
	// in an export, on an entry that is listed and never exported.
	TypeOther = "other"
)

// Operations of an export entry.
const (
	// OpAdd: the path is not in the import manifest.
	OpAdd = "add"
	// OpModify: the path is in the import manifest and differs from it.
	OpModify = "modify"
	// OpDelete: the path is in the import manifest and is gone.
	OpDelete = "delete"
)

// Reasons an export entry is listed without being exported, the values of
// ExportEntry.Skipped. Such an entry has no body in the stream and is never
// applied.
const (
	// SkippedSpecial: not a regular file, a directory or a symbolic link.
	SkippedSpecial = "special"
	// SkippedUnhashed: the signed diff holds no content hash for the file
	// (unreadable, or beyond a hashing budget), so nothing could vouch for
	// its content.
	SkippedUnhashed = "unhashed"
	// SkippedName: the name is not valid UTF-8, or is not a path CheckPath
	// accepts.
	SkippedName = "name"
	// SkippedBudget: the export reached its budget of entries or of bytes.
	// Sizes count as the file's apparent size: a sparse file costs what it
	// claims to hold.
	SkippedBudget = "budget"
)

// ErrManifest is the error of the validation of a manifest, wrapped with
// what was wrong.
var ErrManifest = errors.New("invalid manifest")

// CheckPath reports whether p may appear in a manifest: a relative path with
// "/" between components, already clean (no empty, "." or ".." component, no
// trailing slash), in valid UTF-8, without a NUL byte, within the length
// bounds. It is a filter on the form of a name and decides nothing about
// where the name leads on a real filesystem.
func CheckPath(p string) error {
	switch {
	case p == "":
		return errors.New("the path is empty")
	case len(p) > MaxPathBytes:
		return fmt.Errorf("the path is %d bytes long, more than %d", len(p), MaxPathBytes)
	case !utf8.ValidString(p):
		return errors.New("the path is not valid UTF-8")
	case strings.ContainsRune(p, 0):
		return errors.New("the path holds a NUL byte")
	case p[0] == '/':
		return errors.New("the path is absolute")
	case path.Clean(p) != p || p == "." || p == ".." || strings.HasPrefix(p, "../"):
		return errors.New("the path is not clean: it has an empty, \".\" or \"..\" component or a trailing slash")
	}
	parts := strings.Split(p, "/")
	if len(parts) > MaxDepth {
		return fmt.Errorf("the path has %d components, more than %d", len(parts), MaxDepth)
	}
	for _, c := range parts {
		if len(c) > MaxNameBytes {
			return fmt.Errorf("a component of the path is %d bytes long, more than %d", len(c), MaxNameBytes)
		}
	}
	return nil
}

// ImportEntry is one file, directory or symbolic link of an imported
// project.
type ImportEntry struct {
	// Path is relative to the project directory and passes CheckPath.
	Path string `json:"path"`
	// Type is TypeFile, TypeDir or TypeSymlink. Nothing else is imported.
	Type string `json:"type"`
	// Mode holds the permission bits, nothing above 0777.
	Mode uint32 `json:"mode"`
	// Size is the size of a regular file, and 0 otherwise.
	Size int64 `json:"size"`
	// SHA256 is the lower-case hexadecimal SHA-256 of a regular file's
	// content, and empty otherwise.
	SHA256 string `json:"sha256"`
	// Target is the text of a symbolic link, verbatim, and empty otherwise.
	// It is never resolved.
	Target string `json:"target"`
}

// Import is the manifest of an imported project: every entry, sorted by Path
// compared as bytes, each path once. It records no time, owner or attribute:
// two packings of the same tree have the same manifest.
type Import struct {
	// Format is ImportFormat.
	Format string `json:"format"`
	// Entries is sorted by Path. It is empty, never nil, for an empty
	// project.
	Entries []ImportEntry `json:"entries"`
}

// Validate reports whether m is a well-formed import manifest: the format,
// the bounds, the order, and for each entry a valid path, a known type and
// the fields that go with it.
func (m Import) Validate() error {
	if m.Format != ImportFormat {
		return fmt.Errorf("%w: format %s, want %s", ErrManifest, strconv.Quote(m.Format), ImportFormat)
	}
	if len(m.Entries) > MaxEntries {
		return fmt.Errorf("%w: %d entries, more than %d", ErrManifest, len(m.Entries), MaxEntries)
	}
	for i, e := range m.Entries {
		if err := CheckPath(e.Path); err != nil {
			return fmt.Errorf("%w: entry %d: %v", ErrManifest, i, err)
		}
		if i > 0 && m.Entries[i-1].Path >= e.Path {
			return fmt.Errorf("%w: entry %d is not after entry %d in the order of paths", ErrManifest, i, i-1)
		}
		if e.Mode > 0o777 {
			return fmt.Errorf("%w: entry %d has mode bits above 0777", ErrManifest, i)
		}
		if err := checkContent(e.Type, e.Size, e.SHA256, e.Target, false); err != nil {
			return fmt.Errorf("%w: entry %d: %v", ErrManifest, i, err)
		}
	}
	return nil
}

// checkContent checks the fields that depend on the type of an entry.
// withoutBody is true for an entry that carries no content: a deletion, or
// an entry that is listed and not exported.
func checkContent(typ string, size int64, sum, target string, withoutBody bool) error {
	if size < 0 {
		return errors.New("negative size")
	}
	if len(target) > MaxPathBytes {
		return fmt.Errorf("a link target of %d bytes, more than %d", len(target), MaxPathBytes)
	}
	switch typ {
	case TypeFile:
		if target != "" {
			return errors.New("a regular file with a link target")
		}
		if withoutBody && sum == "" {
			return nil
		}
		if !isSHA256(sum) {
			return errors.New("a regular file without a SHA-256 of 64 lower-case hexadecimal digits")
		}
	case TypeDir:
		if size != 0 || sum != "" || target != "" {
			return errors.New("a directory with a size, a hash or a link target")
		}
	case TypeSymlink:
		if size != 0 || sum != "" {
			return errors.New("a symbolic link with a size or a hash")
		}
		if target == "" && !withoutBody {
			return errors.New("a symbolic link without a target")
		}
	case TypeOther:
		if !withoutBody {
			return errors.New("a special file with content")
		}
	default:
		return fmt.Errorf("unknown type %s", strconv.Quote(typ))
	}
	return nil
}

func isSHA256(s string) bool {
	if len(s) != 2*sha256.Size {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Canonical returns the canonical bytes of m after validating it: its
// encoding/json form without indentation, which is deterministic because the
// manifest holds no map and its entries are sorted. These are the bytes that
// are hashed; both ends produce them with this function and nobody re-encodes
// a manifest that was received in order to check it.
func (m Import) Canonical() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if m.Entries == nil {
		m.Entries = []ImportEntry{}
	}
	return marshalBounded(m)
}

// Hash returns the hash of the import manifest: the lower-case hexadecimal
// SHA-256 of Canonical.
func (m Import) Hash() (string, error) {
	b, err := m.Canonical()
	if err != nil {
		return "", err
	}
	return HashBytes(b), nil
}

// Totals returns the number of entries and the sum of the sizes of the
// regular files.
func (m Import) Totals() (entries, bytes int64) {
	for _, e := range m.Entries {
		bytes += e.Size
	}
	return int64(len(m.Entries)), bytes
}

// Lookup returns the entry at a path, by binary search in a manifest that
// passed Validate.
func (m Import) Lookup(p string) (ImportEntry, bool) {
	lo, hi := 0, len(m.Entries)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if m.Entries[mid].Path < p {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo < len(m.Entries) && m.Entries[lo].Path == p {
		return m.Entries[lo], true
	}
	return ImportEntry{}, false
}

// HashBytes returns the hash of the canonical bytes of a manifest as they
// were received: their lower-case hexadecimal SHA-256. This is the function
// a verifier uses.
func HashBytes(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

func marshalBounded(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(b) > MaxManifestBytes {
		return nil, fmt.Errorf("%w: %d bytes once encoded, more than %d", ErrManifest, len(b), MaxManifestBytes)
	}
	return b, nil
}

// ExportEntry is one path the session changed under the project directory.
type ExportEntry struct {
	// Path is relative to the project directory. It passes CheckPath unless
	// PathEscaped is set.
	Path string `json:"path"`
	// PathEscaped is set when the name the sandbox chose is not valid UTF-8.
	// Path then holds its strconv.Quote form, quotes included, and the entry
	// is Skipped with SkippedName.
	PathEscaped bool `json:"path_escaped"`
	// Op is OpAdd, OpModify or OpDelete.
	Op string `json:"op"`
	// Type is the type of the entry as the session left it; for a deletion,
	// the type of what the import manifest holds at the path.
	Type string `json:"type"`
	// Mode holds the permission bits the sandbox set, nothing above 0777.
	// Whoever applies the entry does not reproduce them: a file becomes 0755
	// when any execute bit is set here and 0644 otherwise.
	Mode uint32 `json:"mode"`
	// Size is the apparent size of a regular file.
	Size int64 `json:"size"`
	// SHA256 is the hash of a regular file's content. Every regular file that
	// is exported has one, and its body in the stream must match it.
	SHA256 string `json:"sha256"`
	// Target is the text of a symbolic link, verbatim. It is never resolved
	// here.
	Target string `json:"target"`
	// BaseSHA256 is, for OpModify and OpDelete of a path that is a regular
	// file in the import manifest, the hash that manifest holds for it. A
	// modification or a deletion is applied only where the project still has
	// that content: anything else is a conflict, and is left alone.
	BaseSHA256 string `json:"base_sha256"`
	// Skipped is empty for an exported entry and one of the Skipped
	// constants for an entry that is only listed.
	Skipped string `json:"skipped"`
}

// Export is the manifest of an exported change set.
type Export struct {
	// Format is ExportFormat.
	Format string `json:"format"`
	// Session is the identifier of the session the changes come from, in its
	// text form.
	Session string `json:"session"`
	// WorkspaceManifestSHA256 is the hash of the import manifest the changes
	// are relative to: the project as the session last saw it.
	WorkspaceManifestSHA256 string `json:"workspace_manifest_sha256"`
	// Entries is sorted by Path compared as bytes, each path once. It is
	// empty, never nil, when the session changed nothing.
	Entries []ExportEntry `json:"entries"`
}

// Validate reports whether m is a well-formed export manifest.
func (m Export) Validate() error {
	if m.Format != ExportFormat {
		return fmt.Errorf("%w: format %s, want %s", ErrManifest, strconv.Quote(m.Format), ExportFormat)
	}
	if _, err := ids.Parse(m.Session); err != nil {
		return fmt.Errorf("%w: session: %v", ErrManifest, err)
	}
	if !isSHA256(m.WorkspaceManifestSHA256) {
		return fmt.Errorf("%w: the hash of the import manifest is not 64 lower-case hexadecimal digits", ErrManifest)
	}
	if len(m.Entries) > MaxEntries {
		return fmt.Errorf("%w: %d entries, more than %d", ErrManifest, len(m.Entries), MaxEntries)
	}
	for i, e := range m.Entries {
		if err := e.validate(); err != nil {
			return fmt.Errorf("%w: entry %d: %v", ErrManifest, i, err)
		}
		if i > 0 && m.Entries[i-1].Path >= e.Path {
			return fmt.Errorf("%w: entry %d is not after entry %d in the order of paths", ErrManifest, i, i-1)
		}
	}
	return nil
}

func (e ExportEntry) validate() error {
	if e.PathEscaped {
		if e.Skipped != SkippedName {
			return errors.New("an escaped name on an entry that is not skipped for its name")
		}
		if _, err := strconv.Unquote(e.Path); err != nil || len(e.Path) > 4*MaxPathBytes+2 {
			return errors.New("an escaped name that is not a quoted string of bounded length")
		}
	} else if err := CheckPath(e.Path); err != nil {
		if e.Skipped != SkippedName || !utf8.ValidString(e.Path) || len(e.Path) > MaxPathBytes || strings.ContainsRune(e.Path, 0) {
			return err
		}
	}
	if e.Mode > 0o777 {
		return errors.New("mode bits above 0777")
	}
	switch e.Skipped {
	case "", SkippedSpecial, SkippedUnhashed, SkippedName, SkippedBudget:
	default:
		return fmt.Errorf("unknown skip reason %s", strconv.Quote(e.Skipped))
	}
	switch e.Op {
	case OpAdd:
		if e.BaseSHA256 != "" {
			return errors.New("an addition with a base hash")
		}
	case OpModify, OpDelete:
		if e.BaseSHA256 != "" && !isSHA256(e.BaseSHA256) {
			return errors.New("a base hash that is not 64 lower-case hexadecimal digits")
		}
	default:
		return fmt.Errorf("unknown operation %s", strconv.Quote(e.Op))
	}
	if e.Type == TypeOther && e.Skipped == "" {
		return errors.New("a special file that is not skipped")
	}
	return checkContent(e.Type, e.Size, e.SHA256, e.Target, e.Op == OpDelete || e.Skipped != "")
}

// HasBody reports whether the stream carries a body for the entry: an added
// or modified regular file that is exported.
func (e ExportEntry) HasBody() bool {
	return e.Skipped == "" && e.Type == TypeFile && e.Op != OpDelete
}

// Canonical returns the canonical bytes of m after validating it, under the
// same rule as Import.Canonical. The stream carries exactly these bytes and
// the signed export record carries their hash.
func (m Export) Canonical() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if m.Entries == nil {
		m.Entries = []ExportEntry{}
	}
	return marshalBounded(m)
}

// Hash returns the hash of the export manifest: the lower-case hexadecimal
// SHA-256 of Canonical.
func (m Export) Hash() (string, error) {
	b, err := m.Canonical()
	if err != nil {
		return "", err
	}
	return HashBytes(b), nil
}

// Totals returns the number of entries, the number of those that are only
// listed, and the sum of the sizes of the bodies in the stream.
func (m Export) Totals() (entries, skipped, bytes int64) {
	for _, e := range m.Entries {
		if e.Skipped != "" {
			skipped++
		}
		if e.HasBody() {
			bytes += e.Size
		}
	}
	return int64(len(m.Entries)), skipped, bytes
}

// Tier says how careful to be with a change to a path.
type Tier int

const (
	// TierOrdinary: no rule of the table names the path.
	TierOrdinary Tier = iota
	// TierHighlighted: the file is run or obeyed when the project is built
	// or tested. A change to it is applied like any other and shown apart in
	// the plan, so that the reviewer reads it.
	TierHighlighted
	// TierRefused: the file is run or obeyed without anyone asking. A change
	// to it is not applied unless the person applying names the path, or a
	// directory above it, explicitly.
	TierRefused
)

// String returns "ordinary", "highlighted" or "refused".
func (t Tier) String() string {
	switch t {
	case TierHighlighted:
		return "highlighted"
	case TierRefused:
		return "refused"
	}
	return "ordinary"
}

// Match says how a Rule is compared with a path. Every comparison ignores
// the case of ASCII letters: a project may sit on a filesystem that does.
type Match int

const (
	// MatchComponent: some component of the path, at any depth, equals the
	// pattern. It covers the entry of that name and everything beneath it.
	MatchComponent Match = iota
	// MatchBase: the last component of the path matches the pattern, in the
	// syntax of path.Match.
	MatchBase
)

// Rule is one row of the table of sensitive paths.
type Rule struct {
	Tier    Tier
	Match   Match
	Pattern string
	// Why says in a few words what runs or obeys the file.
	Why string
}

// Rules is the table of sensitive paths. It is data: the plan of an apply,
// the listing of a change set and the documentation are all produced from
// it.
//
// It is an aid and it is not complete. It cannot be: any file a tool reads
// is configuration for that tool.
var Rules = []Rule{
	// Version-control internals, at any depth, as a directory or as a file
	// (a ".git" file redirects a work tree to a directory of its choice).
	{TierRefused, MatchComponent, ".git", "version-control data and hooks"},
	{TierRefused, MatchComponent, ".hg", "version-control data and hooks"},
	{TierRefused, MatchComponent, ".svn", "version-control data"},
	{TierRefused, MatchBase, ".gitmodules", "where submodules are fetched from"},
	{TierRefused, MatchBase, ".gitattributes", "filters and drivers version control runs on files"},
	// Hook managers and shell hooks.
	{TierRefused, MatchComponent, ".husky", "version-control hooks"},
	{TierRefused, MatchBase, ".pre-commit-config.yaml", "version-control hooks"},
	{TierRefused, MatchBase, "lefthook.yml", "version-control hooks"},
	{TierRefused, MatchBase, ".lefthook.yml", "version-control hooks"},
	{TierRefused, MatchBase, ".envrc", "shell code run on entering the directory"},
	// Continuous integration.
	{TierRefused, MatchComponent, ".github", "CI workflows and repository automation"},
	{TierRefused, MatchComponent, ".circleci", "CI configuration"},
	{TierRefused, MatchComponent, ".buildkite", "CI configuration"},
	{TierRefused, MatchBase, ".gitlab-ci.yml", "CI configuration"},
	{TierRefused, MatchBase, ".travis.yml", "CI configuration"},
	{TierRefused, MatchBase, ".drone.yml", "CI configuration"},
	{TierRefused, MatchBase, "azure-pipelines.yml", "CI configuration"},
	{TierRefused, MatchBase, "bitbucket-pipelines.yml", "CI configuration"},
	{TierRefused, MatchBase, "Jenkinsfile", "CI configuration"},
	// Editors and development containers.
	{TierRefused, MatchComponent, ".vscode", "editor tasks and settings"},
	{TierRefused, MatchComponent, ".idea", "editor run configurations"},
	{TierRefused, MatchComponent, ".devcontainer", "commands run when a development container starts"},
	// Coding agents: their settings, their tool servers and the instruction
	// files they read as part of their prompt.
	{TierRefused, MatchComponent, ".claude", "agent settings, hooks and commands"},
	{TierRefused, MatchComponent, ".cursor", "agent settings and rules"},
	{TierRefused, MatchComponent, ".codex", "agent settings"},
	{TierRefused, MatchComponent, ".gemini", "agent settings"},
	{TierRefused, MatchComponent, ".continue", "agent settings"},
	{TierRefused, MatchBase, ".mcp.json", "tool servers an agent starts"},
	{TierRefused, MatchBase, "AGENTS.md", "instructions an agent obeys"},
	{TierRefused, MatchBase, "CLAUDE.md", "instructions an agent obeys"},
	{TierRefused, MatchBase, "GEMINI.md", "instructions an agent obeys"},
	{TierRefused, MatchBase, ".cursorrules", "instructions an agent obeys"},
	{TierRefused, MatchBase, ".windsurfrules", "instructions an agent obeys"},
	{TierRefused, MatchBase, ".aider.conf.yml", "agent settings"},

	// Build manifests: they run when the project is built or tested.
	{TierHighlighted, MatchBase, "Makefile", "build recipe"},
	{TierHighlighted, MatchBase, "GNUmakefile", "build recipe"},
	{TierHighlighted, MatchBase, "*.mk", "build recipe"},
	{TierHighlighted, MatchBase, "justfile", "build recipe"},
	{TierHighlighted, MatchBase, "Taskfile.yml", "build recipe"},
	{TierHighlighted, MatchBase, "CMakeLists.txt", "build recipe"},
	{TierHighlighted, MatchBase, "meson.build", "build recipe"},
	{TierHighlighted, MatchBase, "BUILD", "build recipe"},
	{TierHighlighted, MatchBase, "BUILD.bazel", "build recipe"},
	{TierHighlighted, MatchBase, "WORKSPACE", "build recipe"},
	{TierHighlighted, MatchBase, "Dockerfile", "image build recipe"},
	{TierHighlighted, MatchBase, "Dockerfile.*", "image build recipe"},
	{TierHighlighted, MatchBase, "docker-compose.yml", "services started for development"},
	{TierHighlighted, MatchBase, "compose.yaml", "services started for development"},
	{TierHighlighted, MatchBase, "package.json", "scripts run by the package manager"},
	{TierHighlighted, MatchBase, ".npmrc", "package manager configuration"},
	{TierHighlighted, MatchBase, ".yarnrc.yml", "package manager configuration"},
	{TierHighlighted, MatchBase, ".pnpmfile.cjs", "code run by the package manager"},
	{TierHighlighted, MatchBase, "go.mod", "module dependencies"},
	{TierHighlighted, MatchBase, "go.work", "module dependencies"},
	{TierHighlighted, MatchBase, "Cargo.toml", "build dependencies and scripts"},
	{TierHighlighted, MatchBase, "build.rs", "code run at build time"},
	{TierHighlighted, MatchComponent, ".cargo", "build configuration and command aliases"},
	{TierHighlighted, MatchBase, "pyproject.toml", "build backend and dependencies"},
	{TierHighlighted, MatchBase, "setup.py", "code run at install time"},
	{TierHighlighted, MatchBase, "setup.cfg", "build configuration"},
	{TierHighlighted, MatchBase, "conftest.py", "code run by the test runner"},
	{TierHighlighted, MatchBase, "tox.ini", "commands run by the test runner"},
	{TierHighlighted, MatchBase, "noxfile.py", "code run by the test runner"},
	{TierHighlighted, MatchBase, "requirements*.txt", "dependencies"},
	{TierHighlighted, MatchBase, "Gemfile", "dependencies and code run by the package manager"},
	{TierHighlighted, MatchBase, "Rakefile", "build recipe"},
	{TierHighlighted, MatchBase, "build.gradle", "build recipe"},
	{TierHighlighted, MatchBase, "build.gradle.kts", "build recipe"},
	{TierHighlighted, MatchBase, "settings.gradle", "build recipe"},
	{TierHighlighted, MatchBase, "pom.xml", "build recipe"},
	{TierHighlighted, MatchBase, "*.csproj", "build recipe"},
	{TierHighlighted, MatchBase, "composer.json", "scripts run by the package manager"},
	{TierHighlighted, MatchBase, "flake.nix", "build recipe"},
	{TierHighlighted, MatchBase, "shell.nix", "build recipe"},
}

// Classify returns the tier of a path and the rule that put it there. The
// strictest rule that matches wins, and among those the first of the table.
// A path no rule names is TierOrdinary, with the zero Rule.
//
// The path is one from a manifest, relative with "/" between components. An
// escaped name (ExportEntry.PathEscaped) is classified in its quoted form
// and is never applied anyway.
func Classify(p string) (Tier, Rule) {
	lower := asciiLower(p)
	parts := strings.Split(lower, "/")
	base := parts[len(parts)-1]
	best, bestRule := TierOrdinary, Rule{}
	for _, r := range Rules {
		if r.Tier <= best {
			continue
		}
		pattern := asciiLower(r.Pattern)
		matched := false
		switch r.Match {
		case MatchComponent:
			for _, c := range parts {
				if c == pattern {
					matched = true
					break
				}
			}
		case MatchBase:
			matched, _ = path.Match(pattern, base)
		}
		if matched {
			best, bestRule = r.Tier, r
		}
	}
	return best, bestRule
}

// asciiLower lowers ASCII letters and leaves every other byte alone, so that
// the comparison cannot be confused by the case rules of other scripts.
func asciiLower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// Names of the files of the client's spool. The spool is a directory of the
// user (layout.User.Spool), mode 0700; each session has a directory in it,
// named after its identifier, and nothing in a spool is ever written by
// root.
const (
	// SpoolImportFile holds the canonical bytes of the import manifest the
	// client computed when it packed the project, replaced after each
	// refresh.
	SpoolImportFile = "import.json"
	// spoolRecordSuffix and spoolStreamSuffix follow the sequence number of
	// an export record in the names of its two files.
	spoolRecordSuffix = ".record.json"
	spoolStreamSuffix = ".changeset"
	// spoolSeqWidth pads sequence numbers so that names sort in chain order.
	spoolSeqWidth = 10
)

// SpoolSessionDir returns the directory of one session inside a spool.
func SpoolSessionDir(spool string, session ids.ID) string {
	return filepath.Join(spool, session.String())
}

// SpoolRecordFile returns the name, inside a session's spool directory, of
// the file that holds the signed export record with the given sequence
// number, as the envelope the service sent.
func SpoolRecordFile(seq uint64) string {
	return fmt.Sprintf("%0*d%s", spoolSeqWidth, seq, spoolRecordSuffix)
}

// SpoolStreamFile returns the name of the file that holds the change-set
// stream of that export.
func SpoolStreamFile(seq uint64) string {
	return fmt.Sprintf("%0*d%s", spoolSeqWidth, seq, spoolStreamSuffix)
}

// ParseSpoolFile reads back a name made by SpoolRecordFile or
// SpoolStreamFile. ok is false for any other name.
func ParseSpoolFile(name string) (seq uint64, stream bool, ok bool) {
	rest, isRecord := strings.CutSuffix(name, spoolRecordSuffix)
	if !isRecord {
		rest, stream = strings.CutSuffix(name, spoolStreamSuffix)
		if !stream {
			return 0, false, false
		}
	}
	if len(rest) != spoolSeqWidth {
		return 0, false, false
	}
	for i := 0; i < len(rest); i++ {
		if rest[i] < '0' || rest[i] > '9' {
			return 0, false, false
		}
	}
	seq, err := strconv.ParseUint(rest, 10, 64)
	return seq, stream, err == nil && seq > 0
}
