package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/camilbenameur/sandmeter/agenteval"
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
	if code, _, _ := runCLI("eval-agent", "-model", "gpt"); code != 2 {
		t.Fatalf("unknown model: exit %d, want 2", code)
	}
}

func TestResolveAttacker(t *testing.T) {
	t.Setenv("OPENAI_BASE_URL", "")
	tests := []struct {
		name    string
		env     string
		flags   evalModelFlags
		wantErr string
		check   func(attacker) bool
	}{
		{"default is haiku", "", evalModelFlags{provider: "anthropic"}, "",
			func(a attacker) bool { return a.modelID == "claude-haiku-5-5" && a.pricing == agenteval.HaikuPricing }},
		{"sonnet", "", evalModelFlags{provider: "anthropic", model: "sonnet"}, "",
			func(a attacker) bool { return a.modelID == "claude-sonnet-5-5" }},
		{"unknown anthropic model", "", evalModelFlags{provider: "anthropic", model: "qwen"}, "unknown model", nil},
		{"anthropic rejects base url", "", evalModelFlags{provider: "anthropic", baseURL: "http://x"}, "apply to -provider openai", nil},
		{"unknown provider", "", evalModelFlags{provider: "gemini"}, "unknown provider", nil},
		{"openai needs a model", "", evalModelFlags{provider: "openai", baseURL: "http://x", tokenBudget: 1}, "-model is required", nil},
		{"openai needs a base url", "", evalModelFlags{provider: "openai", model: "m", tokenBudget: 1}, "base URL", nil},
		{"openai base url from env", "http://env:8000", evalModelFlags{provider: "openai", model: "m", tokenBudget: 1}, "",
			func(a attacker) bool { return a.baseURL == "http://env:8000" }},
		{"flag beats env", "http://env:8000", evalModelFlags{provider: "openai", model: "m", baseURL: "https://flag", tokenBudget: 1}, "",
			func(a attacker) bool { return a.baseURL == "https://flag" }},
		{"free model needs a cap", "", evalModelFlags{provider: "openai", model: "m", baseURL: "http://x"}, "needs -token-budget or -wall-budget", nil},
		{"wall cap is enough", "", evalModelFlags{provider: "openai", model: "m", baseURL: "http://x", wallBudget: time.Hour}, "",
			func(a attacker) bool { return a.modelID == "m" && a.pricing == (agenteval.Pricing{}) }},
		{"priced model needs no cap", "", evalModelFlags{provider: "openai", model: "m", baseURL: "http://x", inPrice: 1, outPrice: 2}, "",
			func(a attacker) bool { return a.pricing.InputPerMTok == 1 && a.pricing.OutputPerMTok == 2 }},
		{"negative cap", "", evalModelFlags{provider: "openai", model: "m", baseURL: "http://x", tokenBudget: -1}, "negative", nil},
		{"non-http base url", "", evalModelFlags{provider: "openai", model: "m", baseURL: "localhost:8000", tokenBudget: 1}, "base URL", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("OPENAI_BASE_URL", tt.env)
			a, err := resolveAttacker(tt.flags)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || !tt.check(a) {
				t.Fatalf("%+v, %v", a, err)
			}
		})
	}
}

func TestEvalAgentOpenAIUsageErrorsComeFirst(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("OPENAI_BASE_URL", "")
	for _, args := range [][]string{
		{"eval-agent", "-provider", "openai"},
		{"eval-agent", "-provider", "openai", "-model", "m", "-base-url", "http://x"},
		{"eval-agent", "-provider", "nope"},
	} {
		if code, _, _ := runCLI(args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	// A valid openai invocation still stops at the throwaway-host guard.
	code, _, stderr := runCLI("eval-agent", "-provider", "openai", "-model", "m", "-base-url", "http://x", "-token-budget", "1000")
	if code != 1 || !strings.Contains(stderr, "refusing to run") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}
