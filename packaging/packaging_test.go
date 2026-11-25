package packaging

import (
	"net/netip"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/camilbenameur/sandmeter/internal/layout"
	"github.com/camilbenameur/sandmeter/policy"
)

// operatorKeys is every key of the operator file, in dotted form. The
// default file must hold exactly these, each written out: it is the
// reference an operator reads, and the list the parser accepts.
var operatorKeys = []string{
	"version",
	"paths.home",
	"paths.state",
	"ids.base",
	"backends.enabled",
	"backends.gvisor.runsc",
	"backends.gvisor.platform",
	"images.default",
	"images.allow",
	"images.pull",
	"budgets.sessions",
	"budgets.commands",
	"budgets.connections",
	"budgets.workspace_bytes",
	"budgets.workspace_entries",
	"budgets.receipt_bytes",
	"floor.min_free_bytes",
	"floor.min_free_inodes",
	"network.deny_extra",
	"ceiling.limits.cpu",
	"ceiling.limits.memory",
	"ceiling.limits.pids",
	"ceiling.limits.wall",
	"ceiling.limits.disk",
	"ceiling.storage.upper",
	"ceiling.network.mode",
	"ceiling.network.allow",
	"ceiling.filesystem.read_only_root",
	"ceiling.syscalls.profile",
	"ceiling.process.env_pass",
}

// operatorFile is the default file decoded just far enough for this test.
// The real parser belongs to the configuration package.
type operatorFile struct {
	Version int `toml:"version"`
	Paths   struct {
		Home  string `toml:"home"`
		State string `toml:"state"`
	} `toml:"paths"`
	IDs struct {
		Base uint32 `toml:"base"`
	} `toml:"ids"`
	Backends struct {
		Enabled []string `toml:"enabled"`
		GVisor  struct {
			Runsc    string `toml:"runsc"`
			Platform string `toml:"platform"`
		} `toml:"gvisor"`
	} `toml:"backends"`
	Images struct {
		Default string   `toml:"default"`
		Allow   []string `toml:"allow"`
		Pull    bool     `toml:"pull"`
	} `toml:"images"`
	Budgets struct {
		Sessions         int    `toml:"sessions"`
		Commands         int    `toml:"commands"`
		Connections      int    `toml:"connections"`
		WorkspaceBytes   string `toml:"workspace_bytes"`
		WorkspaceEntries int64  `toml:"workspace_entries"`
		ReceiptBytes     string `toml:"receipt_bytes"`
	} `toml:"budgets"`
	Floor struct {
		MinFreeBytes  string `toml:"min_free_bytes"`
		MinFreeInodes int64  `toml:"min_free_inodes"`
	} `toml:"floor"`
	Network struct {
		DenyExtra []string `toml:"deny_extra"`
	} `toml:"network"`
	Ceiling policy.Ceiling `toml:"ceiling"`
}

func decode(t *testing.T) (operatorFile, toml.MetaData) {
	t.Helper()
	var f operatorFile
	md, err := toml.DecodeFile("config.toml", &f)
	if err != nil {
		t.Fatalf("the default operator file does not parse: %v", err)
	}
	return f, md
}

// TestDefaultOperatorFileWritesOutEveryKey holds the file to the list: no
// key missing, none unknown, none commented out.
func TestDefaultOperatorFileWritesOutEveryKey(t *testing.T) {
	_, md := decode(t)
	if extra := md.Undecoded(); len(extra) != 0 {
		t.Errorf("the file has keys this test does not decode: %v", extra)
	}
	var got []string
	for _, key := range md.Keys() {
		// Tables are listed too; only the keys that hold a value count.
		if typ := md.Type(key...); typ != "Hash" {
			got = append(got, key.String())
		}
	}
	want := append([]string(nil), operatorKeys...)
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("keys of config.toml:\n %v\nwant\n %v", got, want)
	}
}

// TestDefaultOperatorFileIsTheBuiltinConfiguration checks the values that
// other packages hold as constants: installing the file changes nothing.
func TestDefaultOperatorFileIsTheBuiltinConfiguration(t *testing.T) {
	f, _ := decode(t)
	if f.Version != 1 {
		t.Errorf("version = %d", f.Version)
	}
	home, err := layout.NewHome(f.Paths.Home, f.Paths.State)
	if err != nil {
		t.Fatalf("paths: %v", err)
	}
	def, _ := layout.NewHome(layout.DefaultHome, "")
	if home != def {
		t.Errorf("paths = %+v, want the layout's defaults %+v", home, def)
	}
	if f.IDs.Base != layout.DefaultIDBase {
		t.Errorf("ids.base = %d, want %d", f.IDs.Base, layout.DefaultIDBase)
	}
	if !reflect.DeepEqual(f.Backends.Enabled, []string{policy.BackendNative}) {
		t.Errorf("backends.enabled = %v: the native backend alone is enabled by default", f.Backends.Enabled)
	}
	if !strings.HasPrefix(f.Backends.GVisor.Runsc, "/") {
		t.Errorf("backends.gvisor.runsc = %q: the path must be absolute", f.Backends.GVisor.Runsc)
	}
	if f.Images.Default != layout.DefaultImage || !strings.Contains(f.Images.Default, "@sha256:") {
		t.Errorf("images.default = %q, want the pinned default %q", f.Images.Default, layout.DefaultImage)
	}
	if len(f.Images.Allow) != 0 || f.Images.Pull {
		t.Errorf("images: allow %v, pull %v: by default members use the default image only and trigger no other pull", f.Images.Allow, f.Images.Pull)
	}
	b := f.Budgets
	if b.Sessions <= 0 || b.Commands <= 0 || b.Connections <= 0 || b.WorkspaceEntries <= 0 || b.WorkspaceBytes == "" || b.ReceiptBytes == "" {
		t.Errorf("budgets = %+v: every budget is finite by default", b)
	}
	if f.Floor.MinFreeBytes == "" || f.Floor.MinFreeInodes <= 0 {
		t.Errorf("floor = %+v: the free-space guard is on by default", f.Floor)
	}
	if len(f.Network.DenyExtra) != 0 {
		t.Errorf("network.deny_extra = %v", f.Network.DenyExtra)
	}
	// The ceiling of the file is the ceiling in force without a file.
	if want := policy.BuiltinCeiling(); !reflect.DeepEqual(normalise(f.Ceiling), normalise(want)) {
		t.Errorf("ceiling =\n %+v\nwant the built-in ceiling\n %+v", f.Ceiling, want)
	}
	// With it a member gets no network, no passed variable and no profile
	// weaker than compat.
	c := f.Ceiling
	if c.Network.Mode != policy.NetworkNone || len(c.Network.Allow) != 0 || len(c.Process.EnvPass) != 0 || c.Syscalls.Profile == policy.ProfileOff {
		t.Errorf("the default ceiling grants more than the built-in one: %+v", c)
	}
}

// normalise makes an empty list and an absent one compare equal: the file
// writes empty lists out, the built-in ceiling leaves them nil.
func normalise(c policy.Ceiling) policy.Ceiling {
	if len(c.Network.Allow) == 0 {
		c.Network.Allow = nil
	}
	if len(c.Process.EnvPass) == 0 {
		c.Process.EnvPass = nil
	}
	return c
}

// TestExamplesInCommentsAreValid checks the values the comments suggest: a
// reader who copies one gets something the parsers accept.
func TestExamplesInCommentsAreValid(t *testing.T) {
	if _, err := netip.ParsePrefix("168.63.129.16/32"); err != nil {
		t.Error(err)
	}
	for _, dest := range []string{"pypi.org", "files.pythonhosted.org:443", "*.example.org:443"} {
		if _, err := policy.ParseDest(dest); err != nil {
			t.Errorf("the example destination %q: %v", dest, err)
		}
	}
	b, err := os.ReadFile("config.toml")
	if err != nil {
		t.Fatal(err)
	}
	for _, example := range []string{"168.63.129.16/32", `"pypi.org"`, `"files.pythonhosted.org:443"`, `"*.example.org:443"`} {
		if !strings.Contains(string(b), example) {
			t.Errorf("config.toml no longer shows the example %s that this test checks", example)
		}
	}
}

// unit reads a unit file into "Section.Key" -> values, ignoring comments.
func unit(t *testing.T, name string) map[string][]string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	section := ""
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			section = line[1 : len(line)-1]
		default:
			key, value, ok := strings.Cut(line, "=")
			if !ok || section == "" {
				t.Errorf("%s: cannot read the line %q", name, line)
				continue
			}
			out[section+"."+key] = append(out[section+"."+key], value)
		}
	}
	return out
}

func one(t *testing.T, u map[string][]string, key string) string {
	t.Helper()
	if len(u[key]) != 1 {
		t.Errorf("%s is set %d times, want once", key, len(u[key]))
		return ""
	}
	return u[key][0]
}

func TestSocketUnit(t *testing.T) {
	u := unit(t, "sandmeter.socket")
	if got := one(t, u, "Socket.ListenStream"); got != layout.Socket {
		t.Errorf("the unit listens on %q and the client dials %q", got, layout.Socket)
	}
	if got := one(t, u, "Socket.SocketGroup"); got != layout.Group {
		t.Errorf("SocketGroup = %q, want %q", got, layout.Group)
	}
	// Group members and root, nobody else, from the moment the socket exists.
	if one(t, u, "Socket.SocketMode") != "0660" || one(t, u, "Socket.SocketUser") != "root" {
		t.Errorf("the socket must be root:%s 0660", layout.Group)
	}
	if one(t, u, "Socket.Accept") != "no" {
		t.Error("one service accepts every connection and starts a worker for each")
	}
	if one(t, u, "Install.WantedBy") != "sockets.target" {
		t.Error("the socket unit is what gets enabled")
	}
}

func TestServiceUnit(t *testing.T) {
	u := unit(t, "sandmeter.service")
	if got := one(t, u, "Service.ExecStart"); got != "/usr/bin/sandmeterd serve" {
		t.Errorf("ExecStart = %q", got)
	}
	if one(t, u, "Service.Delegate") != "yes" {
		t.Error("the service needs its cgroup subtree: Delegate=yes")
	}
	if one(t, u, "Service.OOMPolicy") != "continue" {
		t.Error("an out-of-memory kill inside one sandbox must not stop the service")
	}
	if one(t, u, "Service.StateDirectory") != "sandmeter" || one(t, u, "Service.StateDirectoryMode") != "0700" {
		t.Error("the state directory is created by systemd, for root only")
	}
	if got := one(t, u, "Service.ReadWritePaths"); got != layout.DefaultHome {
		t.Errorf("ReadWritePaths = %q, want the home %q", got, layout.DefaultHome)
	}
	// A core limit of 0 does not keep a piped core handler from starting,
	// and as a hard limit it would keep the first process of a sandbox from
	// setting the one value that does: 1. The unit sets that value, for the
	// service and for everything it starts.
	if got := one(t, u, "Service.LimitCORE"); got != "1" {
		t.Errorf("LimitCORE = %q, want 1: 0 neither stops a piped core handler nor lets a sandbox set the limit that does", got)
	}
	// Invariant: no directive that works through seccomp. A filter on the
	// service is inherited by every sandbox it starts, and the profile a
	// receipt records would no longer be the one in force.
	for key := range u {
		for _, banned := range []string{"SystemCallFilter", "SystemCallArchitectures", "RestrictAddressFamilies", "RestrictNamespaces", "MemoryDenyWriteExecute", "RestrictRealtime", "RestrictSUIDSGID", "LockPersonality", "ProtectKernelModules", "ProtectKernelLogs", "ProtectClock", "ProtectHostname", "PrivateDevices", "SystemCallLog"} {
			if key == "Service."+banned {
				t.Errorf("the unit sets %s, which installs a seccomp filter that sandboxes would inherit", banned)
			}
		}
		// A setuid bit or a file capability is how a root program becomes a
		// tool for others; no unit option may bring one.
		if strings.Contains(key, "Ambient") {
			t.Errorf("the unit sets %s", key)
		}
	}
}

func TestSysusers(t *testing.T) {
	b, err := os.ReadFile("sysusers.d/sandmeter.conf")
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	// The group, and nothing else: no account is created.
	if len(lines) != 1 || lines[0] != "g "+layout.Group+" - -" {
		t.Errorf("sysusers lines: %q", lines)
	}
}
