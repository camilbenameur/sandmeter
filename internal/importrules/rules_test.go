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

// tagSets are the sets of build tags under which the rules are held. The
// tests that need root are behind the "integration" tag: without the second
// set, no rule would ever see the files that start real sandboxes, which are
// the ones most tempted to reach across the layers.
var tagSets = []string{"", "integration"}

// loadedGraph is the import graph for one set of tags, loaded once.
type loadedGraph struct {
	once sync.Once
	pkgs map[string]pkg
	err  error
}

var graphs = map[string]*loadedGraph{"": {}, "integration": {}}

// graph returns every package of the module, keyed by its path below the
// module root, as the go command resolves it for this platform with the
// given build tags.
func graph(t *testing.T, tags string) map[string]pkg {
	t.Helper()
	g := graphs[tags]
	g.once.Do(func() {
		args := []string{"list", "-json=ImportPath,Imports,Deps,TestImports,XTestImports"}
		if tags != "" {
			args = append(args, "-tags", tags)
		}
		cmd := exec.Command("go", append(args, "./...")...)
		cmd.Dir = "../.."
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			g.err = errors.New("go list: " + err.Error() + ": " + stderr.String())
			return
		}
		g.pkgs = map[string]pkg{}
		dec := json.NewDecoder(bytes.NewReader(out))
		for {
			var p pkg
			if err := dec.Decode(&p); err == io.EOF {
				break
			} else if err != nil {
				g.err = err
				return
			}
			g.pkgs[strings.TrimPrefix(p.ImportPath, module)] = p
		}
	})
	if g.err != nil {
		t.Fatal(g.err)
	}
	if len(g.pkgs) < 30 {
		t.Fatalf("go list reports %d packages: the rules below would pass on too little", len(g.pkgs))
	}
	return g.pkgs
}

// eachGraph holds a rule for every set of build tags.
func eachGraph(t *testing.T, rule func(t *testing.T, g map[string]pkg)) {
	t.Helper()
	for _, tags := range tagSets {
		name := "default"
		if tags != "" {
			name = "tags=" + tags
		}
		t.Run(name, func(t *testing.T) { rule(t, graph(t, tags)) })
	}
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
	eachGraph(t, checkImportablePackagesStandAlone)
}

func checkImportablePackagesStandAlone(t *testing.T, g map[string]pkg) {
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

// TestContractPackagesStaySmall lists, for each package that everything else
// is written against, all it may depend on inside the module. These packages
// sit at the bottom of the graph: a dependency added to one of them is added
// to every package above it. The lists leave room for the code that is still
// to be written beside the contract of a package (the probe itself, the
// handling of change sets), and for nothing else.
func TestContractPackagesStaySmall(t *testing.T) {
	eachGraph(t, checkContractPackagesStaySmall)
}

func checkContractPackagesStaySmall(t *testing.T, g map[string]pkg) {
	for name, allowed := range map[string][]string{
		"internal/ids":          {},
		"internal/iox":          {},
		"internal/exit":         {"receipt"},
		"internal/layout":       {"internal/ids"},
		"internal/hidden/entry": {"internal/exit", "receipt"},
		"internal/hostprobe":    {"policy", "internal/layout", "internal/ids"},
		"internal/sandbox":      {"policy", "internal/ids", "internal/hostprobe", "internal/layout"},
		"internal/changeset":    {"internal/ids", "internal/layout", "internal/exit", "receipt"},
		"internal/ctl":          {"policy", "receipt", "internal/ids", "internal/exit", "internal/hostprobe", "internal/layout"},
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
	eachGraph(t, checkLayers)
}

func checkLayers(t *testing.T, g map[string]pkg) {
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
	eachGraph(t, checkRootSideParsesNoAgentOrModelText)
}

func checkRootSideParsesNoAgentOrModelText(t *testing.T, g map[string]pkg) {
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

// clientMustNotLink is what the unprivileged client binary must not contain:
// the engine, the backends and the registry client, and with them everything
// that only the root side has a use for. What a program does not link it
// cannot be tricked into running as the user who started it, and the code
// that parses what a registry or a sandbox sent stays on the side that has
// the service ids and the budgets to parse it under.
var clientMustNotLink = []string{
	"internal/engine", "internal/backend", "internal/serve=", "internal/hidden=",
	"internal/layers", "internal/state", "internal/cgroup", "internal/seccomp", "internal/egress",
	"internal/image", "internal/differ", "internal/config", "internal/escape/probe",
	"internal/agenteval", "internal/bench",
	"github.com/google/go-containerregistry", "github.com/anthropics/", "github.com/openai/",
}

// clientStillLinks is the closed list of what the client binary links today
// against that rule: it is still the program that runs the first engine in
// its own process, as root. The list only shrinks. An entry that is no
// longer linked simply stops counting, so that moving the client off one of
// them needs no edit here; anything forbidden that is not listed fails the
// test. When nothing of it is linked any more, the list is deleted.
var clientStillLinks = []string{
	"internal/engine", "internal/backend/native", "internal/backend/gvisor", "internal/serve", "internal/hidden",
	"internal/layers", "internal/cgroup", "internal/seccomp", "internal/egress",
	"internal/image", "internal/differ",
	"github.com/google/go-containerregistry",
}

// forbiddenToClient reports whether the client binary must not link dep, an
// import path. name is the path as the rules write it and rule the entry of
// clientMustNotLink that forbids it.
func forbiddenToClient(dep string) (name, rule string, forbidden bool) {
	name = dep
	if rel, in := local(dep); in {
		name = rel
	}
	for _, bad := range clientMustNotLink {
		switch {
		case strings.Contains(bad, ".") && !strings.HasPrefix(bad, "internal/"):
			// Another module, by the prefix of its import paths.
			if dep == strings.TrimSuffix(bad, "/") || strings.HasPrefix(dep, strings.TrimSuffix(bad, "/")+"/") {
				return name, bad, true
			}
		case name != dep && under(name, bad):
			return name, bad, true
		}
	}
	return name, "", false
}

// TestClientBinaryLinksNoRootSide holds the client binary to its side of the
// boundary, with the exceptions of today spelled out.
func TestClientBinaryLinksNoRootSide(t *testing.T) {
	eachGraph(t, checkClientBinaryLinksNoRootSide)
}

func checkClientBinaryLinksNoRootSide(t *testing.T, g map[string]pkg) {
	client, ok := g["cmd/sandmeter"]
	if !ok {
		t.Fatal("cmd/sandmeter is not in the module")
	}
	if len(client.Deps) < 50 {
		t.Fatalf("cmd/sandmeter has %d dependencies: the check below would pass on too little", len(client.Deps))
	}
	excused := func(name string) (string, bool) {
		for _, e := range clientStillLinks {
			if name == e || strings.HasPrefix(name, e+"/") {
				return e, true
			}
		}
		return "", false
	}
	used := map[string]bool{}
	// One line per rule that is broken, with the first package found and
	// how many more: a module that is linked brings dozens of packages.
	first, more := map[string]string{}, map[string]int{}
	for _, dep := range client.Deps {
		name, rule, forbidden := forbiddenToClient(dep)
		if !forbidden {
			continue
		}
		if e, ok := excused(name); ok {
			used[e] = true
			continue
		}
		if _, seen := first[rule]; seen {
			more[rule]++
		} else {
			first[rule] = name
		}
	}
	for _, rule := range clientMustNotLink {
		if name, broken := first[rule]; broken {
			t.Errorf("cmd/sandmeter links %s and %d more under %q: the client contains neither the engine, nor a backend, nor the registry client, nor anything only the root side uses",
				name, more[rule], strings.TrimSuffix(rule, "="))
		}
	}
	// An exception is an exception to the rule: one that the rule does not
	// forbid would be a way to excuse something else later.
	for _, e := range clientStillLinks {
		probe := e
		if !strings.Contains(e, ".") || strings.HasPrefix(e, "internal/") {
			probe = module + e
		}
		if _, _, forbidden := forbiddenToClient(probe); !forbidden {
			t.Errorf("clientStillLinks excuses %s, which the rule does not forbid", e)
		}
	}
	t.Logf("cmd/sandmeter still links %d of the %d listed exceptions", len(used), len(clientStillLinks))
	if len(used) == 0 {
		t.Log("the client links nothing of the root side any more: clientStillLinks can be deleted")
	}
	// The other programs a user runs unprivileged are held to the same rule,
	// with no exception: the probe that runs inside a sandbox links nothing
	// of sandmeter's root side either.
	if probe, ok := g["cmd/sandmeter-probe"]; ok {
		for _, dep := range probe.Deps {
			if name, _, forbidden := forbiddenToClient(dep); forbidden && name != "internal/escape/probe" {
				t.Errorf("cmd/sandmeter-probe links %s", name)
			}
		}
	}
}

// prototypeImporters is the closed list of packages that were written
// against the contract and the policy of the prototype, and may go on
// importing them until they move to internal/sandbox and policy. Nothing
// else may: no new code is written against the prototype. When the last of
// them has moved, internal/prototype is deleted.
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
	eachGraph(t, checkNothingNewImportsThePrototype)
}

func checkNothingNewImportsThePrototype(t *testing.T, g map[string]pkg) {
	allowed := map[string]bool{}
	for _, name := range prototypeImporters {
		allowed[name] = true
	}
	still := 0
	for name, p := range g {
		if under(name, "internal/prototype") {
			continue
		}
		uses := false
		for _, list := range [][]string{p.Imports, p.TestImports, p.XTestImports} {
			for _, imp := range list {
				if rel, in := local(imp); in && under(rel, "internal/prototype") {
					uses = true
					if !allowed[name] {
						t.Errorf("%s imports %s: new code is written against internal/sandbox and policy", name, rel)
					}
				}
			}
		}
		if uses {
			still++
		}
	}
	// The list is not required to be exact: a package that moved on simply
	// stops counting, so that moving one never needs an edit here.
	if _, exists := g["internal/prototype/sandbox"]; exists {
		t.Logf("%d of the %d listed packages still import internal/prototype", still, len(prototypeImporters))
		if still == 0 {
			t.Log("nothing imports internal/prototype any more: it can be deleted")
		}
	}
}

// TestOnlyCommandsImportTheEntryPointTable keeps the table of hidden entry
// points at the top of the graph: it imports the packages that own an entry
// point, and only commands, and tests that start a sandbox, import it.
func TestOnlyCommandsImportTheEntryPointTable(t *testing.T) {
	eachGraph(t, checkOnlyCommandsImportTheEntryPointTable)
}

func checkOnlyCommandsImportTheEntryPointTable(t *testing.T, g map[string]pkg) {
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
