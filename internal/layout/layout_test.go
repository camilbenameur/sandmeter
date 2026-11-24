package layout

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/camilbenameur/sandmeter/internal/ids"
)

func TestHomePaths(t *testing.T) {
	h, err := NewHome(DefaultHome, "")
	if err != nil {
		t.Fatal(err)
	}
	id, err := ids.Parse("00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	for got, want := range map[string]string{
		h.Images():                 "/var/lib/sandmeter/images",
		h.State():                  "/var/lib/sandmeter/state",
		h.Receipts():               "/var/lib/sandmeter/receipts",
		h.Keys():                   "/var/lib/sandmeter/keys",
		h.Session(id):              "/var/lib/sandmeter/state/00112233445566778899aabbccddeeff",
		h.UserReceipts(1000):       "/var/lib/sandmeter/receipts/1000",
		h.SessionReceipts(0, id):   "/var/lib/sandmeter/receipts/0/00112233445566778899aabbccddeeff",
		h.StoreDir(StoreImages):    "/var/lib/sandmeter/images",
		h.StoreDir(StoreState):     "/var/lib/sandmeter/state",
		h.StoreDir(StoreReceipts):  "/var/lib/sandmeter/receipts",
		h.StoreDir(StoreKeys):      "/var/lib/sandmeter/keys",
		filepath.Dir(Socket):       SocketDir,
		filepath.Dir(ConfigFile):   "/etc/sandmeter",
		filepath.Base(DefaultHome): "sandmeter",
	} {
		if got != want {
			t.Errorf("got %s, want %s", got, want)
		}
	}
	// Nothing persistent is kept on /run: only the socket lives there.
	for _, s := range Stores {
		if strings.HasPrefix(h.StoreDir(s), "/run") {
			t.Errorf("the %s store is on /run", s)
		}
	}

	moved, err := NewHome("/srv/sandmeter", "/mnt/fast/sandmeter-state")
	if err != nil || moved.State() != "/mnt/fast/sandmeter-state" || moved.Session(id) != "/mnt/fast/sandmeter-state/"+id.String() {
		t.Errorf("a state directory of its own: %+v, %v", moved, err)
	}
}

func TestNewHomeRefusesPathsThatBreakMountOptions(t *testing.T) {
	for name, dirs := range map[string][2]string{
		"relative home":   {"var/lib/sandmeter", ""},
		"relative state":  {"/var/lib/sandmeter", "state"},
		"colon":           {"/var/lib/sand:meter", ""},
		"comma in state":  {"/var/lib/sandmeter", "/var/lib/a,b"},
		"trailing slash":  {"/var/lib/sandmeter/", ""},
		"dot segment":     {"/var/lib/../sandmeter", ""},
		"doubled slash":   {"/var//lib/sandmeter", ""},
		"root directory":  {"/", ""},
		"empty":           {"", ""},
		"nul":             {"/var/lib/sand\x00meter", ""},
		"state is a root": {"/var/lib/sandmeter", "/"},
	} {
		if _, err := NewHome(dirs[0], dirs[1]); err == nil {
			t.Errorf("%s: NewHome(%q, %q) was accepted", name, dirs[0], dirs[1])
		}
	}
}

func TestIDRange(t *testing.T) {
	// The whole reservation stays below the largest id a kernel accepts
	// (2^32-2: the last value is "no id").
	if uint64(DefaultIDBase)+ReservedIDs > 1<<32-1 {
		t.Error("the default id range does not fit in 32 bits")
	}
	if FetchIDOffset < IDCount || EgressIDOffset < IDCount || FetchIDOffset == EgressIDOffset || EgressIDOffset >= ReservedIDs {
		t.Error("the service ids must be two distinct ids just above the sandbox ids")
	}
}

func TestRecordFileNames(t *testing.T) {
	if got := RecordFile(3, "command"); got != "0000000003-command.json" {
		t.Errorf("RecordFile = %q", got)
	}
	if got := IntentFile(3); got != "0000000003.intent" {
		t.Errorf("IntentFile = %q", got)
	}
	// Names sort in the order of the chain, across a change of width in the
	// number.
	names := []string{RecordFile(10, "stop"), RecordFile(9, "command"), RecordFile(100, "export"), RecordFile(1, "command")}
	sort.Strings(names)
	for i, want := range []uint64{1, 9, 10, 100} {
		if seq, _, ok := ParseRecordFile(names[i]); !ok || seq != want {
			t.Errorf("position %d holds %q", i, names[i])
		}
	}
	if seq, kind, ok := ParseRecordFile(RecordFile(42, "interrupted")); !ok || seq != 42 || kind != "interrupted" {
		t.Errorf("round trip: %d %q %v", seq, kind, ok)
	}
	if seq, ok := ParseIntentFile(IntentFile(42)); !ok || seq != 42 {
		t.Errorf("intent round trip: %d %v", seq, ok)
	}
	for _, bad := range []string{
		"", "format", "3-command.json", "0000000003-command", "0000000003-.json", "0000000003_command.json",
		"0000000000-command.json", "000000003a-command.json", "0000000003-Command.json", "0000000003-a/b.json",
		"0000000003-command.json.tmp", "../0000000003-command.json", "00000000003-command.json",
	} {
		if _, _, ok := ParseRecordFile(bad); ok {
			t.Errorf("ParseRecordFile accepted %q", bad)
		}
	}
	for _, bad := range []string{"", "3.intent", "0000000003.intent.tmp", "0000000000.intent", "000000000x.intent", "0000000003-command.json"} {
		if _, ok := ParseIntentFile(bad); ok {
			t.Errorf("ParseIntentFile accepted %q", bad)
		}
	}
}

func writeFormat(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, FormatFile), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureFreshStore(t *testing.T) {
	// A directory that does not exist yet, below one that does not either.
	dir := filepath.Join(t.TempDir(), "home", "images")
	if err := Ensure(dir, StoreImages, nil); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, FormatFile))
	if err != nil || string(b) != "images 1\n" {
		t.Fatalf("format file: %q, %v", b, err)
	}
	for _, p := range []string{dir, filepath.Dir(dir)} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != DirMode {
			t.Errorf("%s: %v, %v, want mode %v", p, fi.Mode(), err, DirMode)
		}
	}
	if fi, err := os.Stat(filepath.Join(dir, FormatFile)); err != nil || fi.Mode().Perm() != FileMode {
		t.Errorf("format file mode: %v, %v", fi.Mode(), err)
	}
	// A second start finds the current format and changes nothing.
	if err := Ensure(dir, StoreImages, func(int) error { t.Error("upgrade called on a current store"); return nil }); err != nil {
		t.Fatal(err)
	}
	if v, err := ReadFormat(dir, StoreImages); v != 1 || err != nil {
		t.Errorf("ReadFormat = %d, %v", v, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("the store holds %d entries after two starts, want the format file alone", len(entries))
	}

	// An existing, empty directory is a fresh store too.
	empty := t.TempDir()
	if v, err := ReadFormat(empty, StoreState); v != -1 || err != nil {
		t.Errorf("ReadFormat of an empty directory = %d, %v", v, err)
	}
	if err := Ensure(empty, StoreState, nil); err != nil {
		t.Fatal(err)
	}
	if v, _ := ReadFormat(empty, StoreState); v != CurrentFormat(StoreState) {
		t.Errorf("an empty directory was not marked: %d", v)
	}
}

func TestEnsureRefusesANewerStore(t *testing.T) {
	dir := t.TempDir()
	writeFormat(t, dir, "state 7\n")
	if err := os.WriteFile(filepath.Join(dir, "data"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Ensure(dir, StoreState, func(int) error { t.Error("upgrade called on a newer store"); return nil })
	if !errors.Is(err, ErrNewerFormat) {
		t.Fatalf("Ensure = %v, want ErrNewerFormat", err)
	}
	// The message says what was found, what this build reads and what to do.
	for _, want := range []string{"format 7", "reads up to 1", "upgrade sandmeter", dir} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message lacks %q: %v", want, err)
		}
	}
	// Nothing was touched.
	if b, _ := os.ReadFile(filepath.Join(dir, FormatFile)); string(b) != "state 7\n" {
		t.Errorf("the format file of a refused store was rewritten: %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "data")); err != nil {
		t.Errorf("the content of a refused store changed: %v", err)
	}
}

func TestEnsureHandsAnOlderStoreToItsOwner(t *testing.T) {
	// A directory with content and no format file is what builds before the
	// format files wrote: version 0.
	dir := t.TempDir()
	old := filepath.Join(dir, "sha256-abc")
	if err := os.Mkdir(old, 0o700); err != nil {
		t.Fatal(err)
	}

	// Without an owner's decision the store is refused and left alone.
	err := Ensure(dir, StoreImages, nil)
	if !errors.Is(err, ErrOlderFormat) || !strings.Contains(err.Error(), "format 0") || !strings.Contains(err.Error(), "move the directory away") {
		t.Fatalf("Ensure without upgrade = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, FormatFile)); !errors.Is(err, os.ErrNotExist) {
		t.Error("a refused store was marked as current")
	}

	// An owner that fails leaves it unmarked too, and its reason is kept.
	boom := errors.New("the layer index is damaged")
	if err := Ensure(dir, StoreImages, func(int) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("Ensure with a failing upgrade = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, FormatFile)); !errors.Is(err, os.ErrNotExist) {
		t.Error("a store whose upgrade failed was marked as current")
	}

	// An owner that discards the old content gets a current store.
	var found []int
	discard := func(v int) error {
		found = append(found, v)
		return os.Remove(old)
	}
	if err := Ensure(dir, StoreImages, discard); err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0] != 0 {
		t.Errorf("upgrade was called with %v, want one call with 0", found)
	}
	if v, err := ReadFormat(dir, StoreImages); v != 1 || err != nil {
		t.Errorf("after the upgrade: %d, %v", v, err)
	}
}

func TestReadFormatRefusesWhatItDoesNotUnderstand(t *testing.T) {
	for name, content := range map[string]string{
		"empty":            "",
		"no newline":       "images 1",
		"another store":    "state 1\n",
		"no number":        "images\n",
		"zero":             "images 0\n",
		"negative":         "images -1\n",
		"leading zero":     "images 01\n",
		"plus sign":        "images +1\n",
		"trailing text":    "images 1 extra\n",
		"two lines":        "images 1\nimages 2\n",
		"windows newline":  "images 1\r\n",
		"leading space":    " images 1\n",
		"not a number":     "images one\n",
		"very long":        "images 1" + strings.Repeat("0", 200) + "\n",
		"number too large": "images 99999999999999999999\n",
	} {
		dir := t.TempDir()
		writeFormat(t, dir, content)
		if v, err := ReadFormat(dir, StoreImages); err == nil {
			t.Errorf("%s: ReadFormat = %d, want an error", name, v)
		}
		if err := Ensure(dir, StoreImages, func(int) error { return nil }); err == nil {
			t.Errorf("%s: Ensure accepted the directory", name)
		}
	}
}

func TestReadFormatDoesNotFollowALink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, []byte("images 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, FormatFile)); err != nil {
		t.Fatal(err)
	}
	if v, err := ReadFormat(dir, StoreImages); err == nil {
		t.Errorf("ReadFormat followed a link and read %d", v)
	}
}

func TestEveryStoreHasAFormat(t *testing.T) {
	for _, s := range Stores {
		if CurrentFormat(s) < 1 {
			t.Errorf("store %s has no format version", s)
		}
	}
}

func TestUserDirs(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

	u, err := UserDirs(env(map[string]string{"HOME": "/home/dev"}))
	if err != nil {
		t.Fatal(err)
	}
	want := User{
		Spool:     "/home/dev/.local/state/sandmeter/spool",
		Receipts:  "/home/dev/.local/state/sandmeter/receipts",
		KnownKeys: "/home/dev/.config/sandmeter/known-keys",
	}
	if u != want {
		t.Errorf("defaults: %+v, want %+v", u, want)
	}

	u, err = UserDirs(env(map[string]string{"HOME": "/home/dev", "XDG_STATE_HOME": "/data/state/", "XDG_CONFIG_HOME": "/data/config"}))
	if err != nil || u.Spool != "/data/state/sandmeter/spool" || u.KnownKeys != "/data/config/sandmeter/known-keys" {
		t.Errorf("with XDG variables: %+v, %v", u, err)
	}

	// A relative XDG value is ignored, as the convention says.
	u, err = UserDirs(env(map[string]string{"HOME": "/home/dev", "XDG_STATE_HOME": "state", "XDG_CONFIG_HOME": "./config"}))
	if err != nil || u != want {
		t.Errorf("with relative XDG variables: %+v, %v", u, err)
	}

	// XDG variables are enough when HOME is missing.
	if _, err := UserDirs(env(map[string]string{"XDG_STATE_HOME": "/s", "XDG_CONFIG_HOME": "/c"})); err != nil {
		t.Errorf("without HOME, with both XDG variables: %v", err)
	}
	for name, m := range map[string]map[string]string{
		"nothing":         {},
		"relative HOME":   {"HOME": "home/dev"},
		"only one of two": {"XDG_STATE_HOME": "/s"},
	} {
		if u, err := UserDirs(env(m)); err == nil {
			t.Errorf("%s: UserDirs = %+v, want an error", name, u)
		}
	}
}
