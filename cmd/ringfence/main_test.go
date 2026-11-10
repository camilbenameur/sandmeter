package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestCapsPrintsJSON(t *testing.T) {
	code, out, _ := runCLI("caps")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if m["backend"] != "native" {
		t.Fatalf("backend = %v", m["backend"])
	}
}

func TestCheckRefusesWhatNativeCannotDoYet(t *testing.T) {
	code, _, stderr := runCLI("check")
	if code != 1 || !strings.Contains(stderr, "limits.memory") {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr)
	}
}

func TestCheckPermissivePolicy(t *testing.T) {
	f := filepath.Join(t.TempDir(), "p.toml")
	content := "[limits]\ncpu = 0.0\nmemory = \"\"\npids = 0\nwall = \"\"\n" +
		"[filesystem]\nread_only_root = false\n[syscalls]\nfilter = \"off\"\n"
	if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	// native does not provide network "none" yet, so even this is refused.
	code, _, stderr := runCLI("check", f)
	if code != 1 || !strings.Contains(stderr, "network.mode") || strings.Contains(stderr, "limits.") {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{{}, {"nope"}, {"caps", "-backend", "nope"}, {"check", "a", "b"}} {
		if code, _, _ := runCLI(args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}
