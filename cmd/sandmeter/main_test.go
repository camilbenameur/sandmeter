package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime/debug"
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

// TestVerifyRecordedV1Receipts runs the verify command on the v1 receipts
// recorded under receipt/testdata/v1, with the public key in the form the
// builds that wrote v1 keep next to their signing key.
func TestVerifyRecordedV1Receipts(t *testing.T) {
	dir := filepath.Join("..", "..", "receipt", "testdata", "v1")
	pub := filepath.Join(dir, "key.pub")
	for name, result := range map[string]string{
		"success": "result:   exit 0\n",
		"failed":  "result:   exit 2\n",
		"killed":  "result:   killed (wall-timeout), exit 137\n",
		"oom":     "result:   killed (oom), exit 137\n",
	} {
		code, out, stderr := runCLI("verify", "-pub", pub, filepath.Join(dir, name+".json"))
		if code != 0 || !strings.Contains(out, "signature ok (key e3fe53e2a733fc90)\n") || !strings.Contains(out, result) {
			t.Errorf("%s: exit %d, stdout:\n%s\nstderr:\n%s", name, code, out, stderr)
		}
	}

	// The same receipt with one signed byte changed is refused.
	env, err := os.ReadFile(filepath.Join(dir, "success.json"))
	if err != nil {
		t.Fatal(err)
	}
	tampered := filepath.Join(t.TempDir(), "tampered.json")
	i := bytes.Index(env, []byte(`"payload": "`)) + len(`"payload": "`)
	env[i] ^= 1
	if err := os.WriteFile(tampered, env, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runCLI("verify", "-pub", pub, tampered); code != 1 || !strings.Contains(stderr, "verify failed") {
		t.Errorf("tampered receipt: exit %d, stderr %q", code, stderr)
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{{}, {"nope"}, {"caps", "-backend", "nope"}, {"check", "a", "b"}, {"run"}, {"pull"}, {"verify"}} {
		if code, _, _ := runCLI(args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
}

// TestLabCommandsAreNotHere checks the split: the benchmark and the agent
// eval belong to sandmeter-lab, and the usage text says where they went.
func TestLabCommandsAreNotHere(t *testing.T) {
	for _, name := range []string{"bench", "eval-agent"} {
		code, _, stderr := runCLI(name)
		if code != 2 || !strings.Contains(stderr, "unknown command") || !strings.Contains(stderr, "sandmeter-lab") {
			t.Errorf("%s: exit %d, stderr:\n%s", name, code, stderr)
		}
	}
}

// TestLinksNoModelSDK holds the reason the lab is a binary of its own: no
// model SDK is linked into sandmeter. The module list of this test binary is
// that of the command plus its tests, so a test that imports one fails too.
func TestLinksNoModelSDK(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("this test binary carries no build information to read its modules from")
	}
	if len(info.Deps) == 0 {
		t.Fatal("the build information lists no module: the check below would pass on nothing")
	}
	for _, dep := range info.Deps {
		if strings.HasPrefix(dep.Path, "github.com/anthropics/") {
			t.Errorf("sandmeter links %s: model clients belong in sandmeter-lab", dep.Path)
		}
	}
}
