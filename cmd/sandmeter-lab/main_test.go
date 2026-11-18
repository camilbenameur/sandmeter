package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/camilbenameur/sandmeter/internal/agenteval"
)

func runCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{{}, {"nope"}, {"run"}, {"escape"}, {"bench", "-nope"}, {"eval-agent", "-nope"}} {
		code, out, stderr := runCLI(args...)
		if code != 2 || out != "" || !strings.Contains(stderr, "sandmeter-lab") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q, want exit 2 and a message on stderr", args, code, out, stderr)
		}
	}
	code, out, _ := runCLI("help")
	if code != 0 || !strings.Contains(out, "bench") || !strings.Contains(out, "eval-agent") {
		t.Errorf("help: exit %d, stdout:\n%s", code, out)
	}
	if code, out, _ := runCLI("version"); code != 0 || out != version+"\n" {
		t.Errorf("version: exit %d, stdout %q", code, out)
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
