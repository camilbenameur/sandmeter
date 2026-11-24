package importrules

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"testing"
)

// module is the import path of this module, with a trailing slash.
const module = "github.com/camilbenameur/sandmeter/"

// pkg is what the go command says about one package of the module.
type pkg struct {
	ImportPath   string
	Imports      []string
	Deps         []string
	TestImports  []string
	XTestImports []string
}

var (
	loadOnce sync.Once
	loaded   map[string]pkg
	loadErr  error
)

// graph returns every package of the module, keyed by its path below the
// module root, as the go command resolves it for this platform.
func graph(t *testing.T) map[string]pkg {
	t.Helper()
	loadOnce.Do(func() {
		cmd := exec.Command("go", "list", "-json=ImportPath,Imports,Deps,TestImports,XTestImports", "./...")
		cmd.Dir = "../.."
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			loadErr = errors.New("go list: " + err.Error() + ": " + stderr.String())
			return
		}
		loaded = map[string]pkg{}
		dec := json.NewDecoder(bytes.NewReader(out))
		for {
			var p pkg
			if err := dec.Decode(&p); err == io.EOF {
				break
			} else if err != nil {
				loadErr = err
				return
			}
			loaded[strings.TrimPrefix(p.ImportPath, module)] = p
		}
	})
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(loaded) < 30 {
		t.Fatalf("go list reports %d packages: the rules below would pass on too little", len(loaded))
	}
	return loaded
}

// local strips the module prefix, and reports whether the path is in the
// module.
func local(path string) (string, bool) {
	return strings.CutPrefix(path, module)
}

// under reports whether a module-relative path is the package dir or lies
// below it. A dir written with a trailing "=" stands for that package alone,
// not for what lies below it.
func under(path, dir string) bool {
	if exact, ok := strings.CutSuffix(dir, "="); ok {
		return path == exact
	}
	return path == dir || strings.HasPrefix(path, dir+"/")
}

// matching returns the packages of the graph that are dir or lie below it.
func matching(g map[string]pkg, dir string) []string {
	var out []string
	for path := range g {
		if under(path, dir) {
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out
}

// TestImportablePackagesStandAlone: policy and receipt are the only packages
// another program may import. They link nothing internal, so their exported
// identifiers cannot mention an internal type either.
func TestImportablePackagesStandAlone(t *testing.T) {
	g := graph(t)
	for _, name := range []string{"policy", "receipt"} {
		p, ok := g[name]
		if !ok {
			t.Fatalf("package %s is not in the module", name)
		}
		for _, dep := range p.Deps {
			if rel, in := local(dep); in {
				t.Errorf("%s depends on %s: an importable package depends on nothing else of the module", name, rel)
			}
		}
	}
	// Everything else is under internal/ or is a command: nothing more can
	// be imported from outside the module.
	for path := range g {
		switch {
		case path == "policy", path == "receipt", under(path, "internal"), under(path, "cmd"):
		case path == "packaging":
			// Tests only: the package has no code to import.
		default:
			t.Errorf("package %s can be imported from outside the module: only policy and receipt may", path)
		}
	}
}

// TestContractPackagesStaySmall lists, for each package that only declares a
// contract, everything of the module it may depend on. A new dependency is a
// decision, taken here.
func TestContractPackagesStaySmall(t *testing.T) {
	g := graph(t)
	for name, allowed := range map[string][]string{
		"internal/ids":          {},
		"internal/iox":          {},
		"internal/testhost":     {},
		"internal/exit":         {"receipt"},
		"internal/layout":       {"internal/ids"},
		"internal/hostprobe":    {"policy"},
		"internal/sandbox":      {"policy", "internal/ids", "internal/hostprobe"},
		"internal/changeset":    {"internal/ids"},
		"internal/hidden/entry": {"internal/exit", "receipt"},
		"internal/ctl":          {"policy", "receipt", "internal/ids", "internal/exit", "internal/hostprobe"},
	} {
		p, ok := g[name]
		if !ok {
			t.Errorf("package %s is not in the module", name)
			continue
		}
		ok2 := map[string]bool{}
		for _, a := range allowed {
			ok2[a] = true
		}
		for _, dep := range p.Deps {
			if rel, in := local(dep); in && !ok2[rel] {
				t.Errorf("%s depends on %s, which is not in its list (%v)", name, rel, allowed)
			}
		}
	}
}

// TestLayers holds the direction of the dependencies: a package on the left
// never depends, directly or not, on anything on the right.
func TestLayers(t *testing.T) {
	g := graph(t)
	for _, rule := range []struct {
		why       string
		from      []string // these packages and everything below them
		forbidden []string // may not depend on these or anything below them
		// atLeast names packages that must exist, so that the rule does not
		// pass on nothing.
		atLeast []string
	}{
		{
			why:       "the lower layers do not know the engine, the service or the clients above them",
			from:      []string{"internal/backend", "internal/layers", "internal/state", "internal/cgroup", "internal/fsx", "internal/seccomp", "internal/caps", "internal/egress", "internal/image", "internal/untar", "internal/differ", "internal/sandbox", "internal/hostprobe"},
			forbidden: []string{"internal/engine", "internal/serve", "internal/client", "internal/mcpserver", "internal/ctl"},
			atLeast:   []string{"internal/backend/native", "internal/backend/gvisor", "internal/layers", "internal/seccomp", "internal/egress", "internal/image", "internal/differ"},
		},
		{
			why:  "the unprivileged client links no engine, no backend and nothing that only root can use: the protocol, the client and the change sets are what the user's own process runs",
			from: []string{"internal/ctl", "internal/client", "internal/changeset"},
			// The worker itself and the table of entry points are root's; what
			// lies below them (how to start a worker, the handshake) is not.
			forbidden: []string{"internal/engine", "internal/backend", "internal/serve=", "internal/hidden=", "internal/layers", "internal/state", "internal/cgroup", "internal/seccomp", "internal/egress", "internal/image", "internal/differ", "internal/config", "internal/mcpserver"},
			atLeast:   []string{"internal/ctl", "internal/client", "internal/client/clienttest", "internal/changeset"},
		},
		{
			why:       "the engine is driven by the worker and knows neither the protocol nor its clients",
			from:      []string{"internal/engine"},
			forbidden: []string{"internal/ctl", "internal/client", "internal/serve", "internal/mcpserver"},
			atLeast:   []string{"internal/engine"},
		},
		{
			why:       "the table of hidden entry points imports the packages that own one, so none of them, and nothing they depend on, imports it back",
			from:      []string{"internal/hidden/entry"},
			forbidden: []string{"internal/backend", "internal/serve", "internal/egress", "internal/image", "internal/engine"},
			atLeast:   []string{"internal/hidden/entry"},
		},
	} {
		for _, must := range rule.atLeast {
			if _, ok := g[must]; !ok {
				t.Errorf("package %s is not in the module: the rule %q would pass on nothing", must, rule.why)
			}
		}
		for _, dir := range rule.from {
			for _, name := range matching(g, dir) {
				for _, dep := range g[name].Deps {
					rel, in := local(dep)
					if !in {
						continue
					}
					for _, bad := range rule.forbidden {
						if under(rel, bad) {
							t.Errorf("%s depends on %s: %s", name, rel, rule.why)
						}
					}
				}
			}
		}
	}
}

// TestRootSideParsesNoAgentOrModelText: the binary that runs as root links
// neither the MCP SDK nor a model client, nor the packages of this module
// that use them. Nothing that parses what an agent or a model wrote can then
// run as root, in the address space that holds the signing key.
func TestRootSideParsesNoAgentOrModelText(t *testing.T) {
	g := graph(t)
	root, ok := g["cmd/sandmeterd"]
	if !ok {
		t.Fatal("cmd/sandmeterd is not in the module")
	}
	if len(root.Deps) < 50 {
		t.Fatalf("cmd/sandmeterd has %d dependencies: the check below would pass on too little", len(root.Deps))
	}
	hidden := false
	for _, dep := range root.Deps {
		switch {
		case strings.HasPrefix(dep, "github.com/modelcontextprotocol/"):
			t.Errorf("the root side links %s: the MCP server belongs to the unprivileged client", dep)
		case strings.HasPrefix(dep, "github.com/anthropics/"), strings.HasPrefix(dep, "github.com/openai/"):
			t.Errorf("the root side links %s: model clients belong to the lab", dep)
		}
		rel, in := local(dep)
		if !in {
			continue
		}
		for _, bad := range []string{"internal/mcpserver", "internal/agenteval", "internal/bench", "internal/escape"} {
			if under(rel, bad) {
				t.Errorf("the root side links %s", rel)
			}
		}
		hidden = hidden || rel == "internal/hidden"
	}
	if !hidden {
		t.Error("cmd/sandmeterd does not link the table of hidden entry points")
	}
	// The same holds for everything the table of entry points reaches: each
	// entry point runs as root or is started by root.
	for _, dep := range g["internal/hidden"].Deps {
		if strings.HasPrefix(dep, "github.com/modelcontextprotocol/") || strings.HasPrefix(dep, "github.com/anthropics/") {
			t.Errorf("a hidden entry point links %s", dep)
		}
	}
}

// prototypeImporters is the list of packages that still import the contract
// and the policy of the prototype. It only shrinks: a package leaves it when
// it moves to internal/sandbox and policy, and when it is empty
// internal/prototype is deleted. Nothing new may be written against the
// prototype.
var prototypeImporters = []string{
	"cmd/sandmeter",
	"cmd/sandmeter-lab",
	"internal/backend/gvisor",
	"internal/backend/native",
	"internal/bench",
	"internal/cgroup",
	"internal/engine",
	"internal/escape",
	"internal/escape/harness",
	"internal/mcpserver",
	"internal/netpolicy",
}

func TestNothingNewImportsThePrototype(t *testing.T) {
	g := graph(t)
	allowed := map[string]bool{}
	for _, name := range prototypeImporters {
		allowed[name] = true
	}
	using := map[string]bool{}
	for name, p := range g {
		if under(name, "internal/prototype") {
			continue
		}
		for _, list := range [][]string{p.Imports, p.TestImports, p.XTestImports} {
			for _, imp := range list {
				if rel, in := local(imp); in && under(rel, "internal/prototype") {
					using[name] = true
					if !allowed[name] {
						t.Errorf("%s imports %s: new code is written against internal/sandbox and policy", name, rel)
					}
				}
			}
		}
	}
	for _, name := range prototypeImporters {
		if !using[name] {
			t.Errorf("%s no longer imports the prototype: remove it from the list, which only shrinks", name)
		}
	}
	if len(using) == 0 {
		if _, ok := g["internal/prototype/sandbox"]; ok {
			t.Error("nothing imports internal/prototype any more: delete it")
		}
	}
}

// TestOnlyCommandsImportTheEntryPointTable keeps the table of hidden entry
// points at the top of the graph: it imports the packages that own an entry
// point, and only commands, and tests that start a sandbox, import it.
func TestOnlyCommandsImportTheEntryPointTable(t *testing.T) {
	g := graph(t)
	for name, p := range g {
		if under(name, "cmd") {
			continue
		}
		for _, imp := range p.Imports {
			if rel, in := local(imp); in && rel == "internal/hidden" {
				t.Errorf("%s imports internal/hidden: only a command, or a test that starts a sandbox, dispatches hidden entry points", name)
			}
		}
	}
}
