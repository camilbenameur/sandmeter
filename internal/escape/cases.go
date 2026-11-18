// Package escape is a replayable escape test suite: a fixed set of shell
// scripts, run inside a sandbox on every backend, each trying one technique
// a sandboxed process might use to reach the host. The result table is
// published as is, including failures: see README.md for the bias warning.
package escape

import (
	"embed"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

//go:embed cases/*.sh
var caseFS embed.FS

// Case is one escape test, parsed from the header comments of a cases/*.sh
// script.
type Case struct {
	// ID is the case identifier, such as "01-proc-root". It must match the
	// script's filename without the .sh suffix.
	ID string
	// Title is a one-line human description.
	Title string
	// Class groups cases by the kind of surface they probe: filesystem,
	// proc, devices, kernel-surface, namespaces, network, resources or
	// host-tooling.
	Class string
	// Expect is the outcome the case author expects on a sound backend,
	// such as "blocked". It is informational: Judge decides the real
	// outcome from evidence, it does not read Expect.
	Expect string
	// Needs lists preconditions the harness must set up before running the
	// case, such as {"network": "none"} or {"network": "allowlist"}. A case
	// with no "needs" header runs under any network mode.
	Needs map[string]string
	// Timeout is the maximum time the harness gives the script to run.
	Timeout time.Duration
	// Script is the full script source, to copy into the sandbox verbatim.
	Script string
}

var headerLine = regexp.MustCompile(`^#\s*([a-zA-Z_]+):\s*(.*)$`)

// Cases returns every case embedded under cases/*.sh, sorted by ID. It
// fails on a parse error in any one script, rather than silently dropping
// a broken case from the suite.
func Cases() ([]Case, error) {
	entries, err := caseFS.ReadDir("cases")
	if err != nil {
		return nil, fmt.Errorf("escape: read cases dir: %w", err)
	}

	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sh") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	cases := make([]Case, 0, len(names))
	seen := make(map[string]string, len(names))
	for _, name := range names {
		data, err := caseFS.ReadFile("cases/" + name)
		if err != nil {
			return nil, fmt.Errorf("escape: read %s: %w", name, err)
		}
		c, err := parseCase(name, string(data))
		if err != nil {
			return nil, fmt.Errorf("escape: parse %s: %w", name, err)
		}
		if prev, ok := seen[c.ID]; ok {
			return nil, fmt.Errorf("escape: duplicate case id %q in %s and %s", c.ID, prev, name)
		}
		seen[c.ID] = name
		cases = append(cases, c)
	}
	return cases, nil
}

var validClass = map[string]bool{
	"filesystem":     true,
	"proc":           true,
	"devices":        true,
	"kernel-surface": true,
	"namespaces":     true,
	"network":        true,
	"resources":      true,
	"host-tooling":   true,
}

// parseCase reads the header comment block at the top of a case script.
// The block is every "# key: value" line found right after an optional
// shebang; the first line that is not of that exact shape ends the block,
// so free-form explanatory comments below the header are not mistaken for
// fields.
func parseCase(filename, content string) (Case, error) {
	c := Case{Script: content, Needs: map[string]string{}}

	lines := strings.Split(content, "\n")
	start := 0
	if len(lines) > 0 && strings.HasPrefix(lines[0], "#!") {
		start = 1
	}

	for _, line := range lines[start:] {
		m := headerLine.FindStringSubmatch(line)
		if m == nil {
			break
		}
		key, val := strings.ToLower(m[1]), strings.TrimSpace(m[2])
		switch key {
		case "id":
			c.ID = val
		case "title":
			c.Title = val
		case "class":
			c.Class = val
		case "expect":
			c.Expect = val
		case "timeout":
			d, err := time.ParseDuration(val)
			if err != nil {
				return Case{}, fmt.Errorf("timeout %q: %w", val, err)
			}
			c.Timeout = d
		case "needs":
			k, v, ok := strings.Cut(val, "=")
			if !ok {
				return Case{}, fmt.Errorf("needs %q: want key=value", val)
			}
			c.Needs[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}

	wantID := strings.TrimSuffix(filename, ".sh")
	switch {
	case c.ID == "":
		return Case{}, fmt.Errorf("missing %q header", "id")
	case c.Title == "":
		return Case{}, fmt.Errorf("missing %q header", "title")
	case c.Class == "":
		return Case{}, fmt.Errorf("missing %q header", "class")
	case c.ID != wantID:
		return Case{}, fmt.Errorf("id %q does not match filename (want %q)", c.ID, wantID)
	case !validClass[c.Class]:
		return Case{}, fmt.Errorf("class %q is not one of the known classes", c.Class)
	}
	return c, nil
}
