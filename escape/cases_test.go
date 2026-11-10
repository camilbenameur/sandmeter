package escape

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func TestCasesParsesAll(t *testing.T) {
	cases, err := Cases()
	if err != nil {
		t.Fatalf("Cases(): %v", err)
	}
	if len(cases) != 15 {
		t.Fatalf("got %d cases, want 15", len(cases))
	}

	seen := map[string]bool{}
	for i, c := range cases {
		if c.ID == "" || c.Title == "" || c.Class == "" {
			t.Errorf("case %d: missing a required header: %+v", i, c)
		}
		if !validClass[c.Class] {
			t.Errorf("case %d (%s): class %q is not a known class", i, c.ID, c.Class)
		}
		if seen[c.ID] {
			t.Errorf("duplicate case id %q", c.ID)
		}
		seen[c.ID] = true

		n, err := strconv.Atoi(strings.SplitN(c.ID, "-", 2)[0])
		if err != nil {
			t.Errorf("case %s: id does not start with a number: %v", c.ID, err)
			continue
		}
		if n != i+1 {
			t.Errorf("case %d: id %q is out of order (want number %d)", i, c.ID, i+1)
		}
	}
	if len(seen) != 15 {
		t.Fatalf("got %d distinct ids, want 15", len(seen))
	}
}

func TestCasesAreValidShell(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh on PATH to syntax-check against")
	}

	cases, err := Cases()
	if err != nil {
		t.Fatalf("Cases(): %v", err)
	}
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			cmd := exec.Command(sh, "-n", "/dev/stdin")
			cmd.Stdin = strings.NewReader(c.Script)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("sh -n failed: %v\n%s", err, out)
			}
		})
	}
}

func TestCasesHaveExactlyOneResultLine(t *testing.T) {
	cases, err := Cases()
	if err != nil {
		t.Fatalf("Cases(): %v", err)
	}
	for _, c := range cases {
		n := strings.Count(c.Script, "RESULT:")
		if n != 1 {
			t.Errorf("case %s: script contains %q %d times, want exactly 1", c.ID, "RESULT:", n)
		}
	}
}

func TestParseCaseRejectsMissingHeaders(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"missing id", "#!/bin/sh\n# title: x\n# class: proc\necho hi\n"},
		{"missing title", "#!/bin/sh\n# id: 01-x\n# class: proc\necho hi\n"},
		{"missing class", "#!/bin/sh\n# id: 01-x\n# title: x\necho hi\n"},
		{"unknown class", "#!/bin/sh\n# id: 01-x\n# title: x\n# class: not-a-class\necho hi\n"},
		{"id mismatch", "#!/bin/sh\n# id: 02-x\n# title: x\n# class: proc\necho hi\n"},
		{"bad timeout", "#!/bin/sh\n# id: 01-x\n# title: x\n# class: proc\n# timeout: notaduration\necho hi\n"},
		{"bad needs", "#!/bin/sh\n# id: 01-x\n# title: x\n# class: proc\n# needs: nope\necho hi\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseCase("01-x.sh", tt.content); err == nil {
				t.Error("parseCase: want an error, got nil")
			}
		})
	}
}

func TestParseCaseHappyPath(t *testing.T) {
	content := "#!/bin/sh\n" +
		"# id: 01-x\n" +
		"# title: a title\n" +
		"# class: network\n" +
		"# expect: blocked\n" +
		"# needs: network=none\n" +
		"# timeout: 20s\n" +
		"#\n" +
		"# A free-form comment: not a header, has a colon too.\n" +
		"echo \"RESULT: BLOCKED ok\"\n"

	c, err := parseCase("01-x.sh", content)
	if err != nil {
		t.Fatalf("parseCase: %v", err)
	}
	if c.ID != "01-x" || c.Title != "a title" || c.Class != "network" || c.Expect != "blocked" {
		t.Errorf("parsed fields wrong: %+v", c)
	}
	if c.Needs["network"] != "none" {
		t.Errorf("Needs[network] = %q, want %q", c.Needs["network"], "none")
	}
	if c.Timeout.String() != "20s" {
		t.Errorf("Timeout = %v, want 20s", c.Timeout)
	}
	if c.Script != content {
		t.Errorf("Script does not preserve the raw source")
	}
}
