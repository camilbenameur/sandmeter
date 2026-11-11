package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestCapsPrintsJSON(t *testing.T) {
	for _, b := range []string{"native", "gvisor"} {
		code, out, _ := runCLI("caps", "-backend", b)
		if code != 0 {
			t.Fatalf("%s: exit %d", b, code)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(out), &m); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, out)
		}
		if m["backend"] != b {
			t.Fatalf("backend = %v", m["backend"])
		}
	}
}

func TestCheckDefaultPolicy(t *testing.T) {
	code, out, stderr := runCLI("check")
	if code != 0 || !strings.Contains(out, "ok: backend \"native\"") {
		t.Fatalf("exit %d, out %q, stderr %q", code, out, stderr)
	}
}

func TestCheckRefusesBadPolicy(t *testing.T) {
	f := filepath.Join(t.TempDir(), "p.toml")
	if err := os.WriteFile(f, []byte("[network]\nmode = \"host\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLI("check", f)
	if code != 1 || !strings.Contains(stderr, "network.mode") {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{{}, {"nope"}, {"caps", "-backend", "nope"}, {"check", "a", "b"}, {"run"}, {"pull"}, {"verify"}} {
		if code, _, _ := runCLI(args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

func TestEvalAgentRefusesOutsideThrowawayCI(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("SANDMETER_THROWAWAY_HOST", "")
	code, _, stderr := runCLI("eval-agent")
	if code != 1 || !strings.Contains(stderr, "refusing to run") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if code, _, _ := runCLI("eval-agent", "-budget", "50"); code != 2 {
		t.Fatalf("budget over the ceiling: exit %d, want 2", code)
	}
	if code, _, _ := runCLI("eval-agent", "-k", "5"); code != 2 {
		t.Fatalf("k=5: exit %d, want 2", code)
	}
}
