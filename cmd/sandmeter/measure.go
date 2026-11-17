package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go/v2"

	"github.com/camilbenameur/sandmeter/agenteval"
	"github.com/camilbenameur/sandmeter/bench"
	"github.com/camilbenameur/sandmeter/engine"
	"github.com/camilbenameur/sandmeter/escape"
	"github.com/camilbenameur/sandmeter/escape/harness"
	"github.com/camilbenameur/sandmeter/policy"
)

func cmdEscape(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("escape", flag.ContinueOnError)
	backendsFlag := fs.String("backends", "native,gvisor", "comma-separated backends")
	img := fs.String("image", "docker.io/library/alpine:3.20", "image reference")
	probe := fs.String("probe", "", "static rfprobe binary (build: CGO_ENABLED=0 go build ./escape/probe)")
	out := fs.String("out", "", "write the verdicts as JSON to this file")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *probe == "" {
		return usageError{errors.New("escape: -probe is required")}
	}
	e, err := newEngine(filepath.Join(home(), "escape-receipts"))
	if err != nil {
		return err
	}
	h := &harness.Harness{
		Engine: e,
		Image:  *img,
		Probe:  *probe,
		// Outside SANDMETER_HOME (0700): see harness.Harness.WorkDir.
		WorkDir: "/run/sandmeter-escape",
		Log:     func(s string) { fmt.Fprintln(os.Stderr, s) },
	}
	verdicts, err := h.Run(ctx, strings.Split(*backendsFlag, ","))
	if err != nil {
		return err
	}
	if *out != "" {
		data, err := json.MarshalIndent(verdicts, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(*out, data, 0o644); err != nil {
			return err
		}
	}
	fmt.Fprint(stdout, escape.Markdown(verdicts))
	return nil
}

func cmdBench(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	backendsFlag := fs.String("backends", "native,gvisor", "comma-separated backends")
	img := fs.String("image", "docker.io/library/alpine:3.20", "image reference")
	starts := fs.Int("n", 100, "runs of `true` for start latency")
	snaps := fs.Int("snapshots", 20, "snapshot/restore cycles")
	conc := fs.Int("concurrency", 20, "sandboxes started at once")
	out := fs.String("out", "", "write raw results as JSON to this file")
	if err := parse(fs, args); err != nil {
		return err
	}
	e, err := newEngine(filepath.Join(home(), "bench-receipts"))
	if err != nil {
		return err
	}
	res, err := bench.Run(ctx, e, bench.Options{
		Image: *img, Backends: strings.Split(*backendsFlag, ","),
		StartRuns: *starts, SnapRuns: *snaps, Concurrency: *conc,
	}, time.Now())
	if err != nil {
		return err
	}
	if *out != "" {
		data, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(*out, data, 0o644); err != nil {
			return err
		}
	}
	fmt.Fprint(stdout, res.Markdown())
	return nil
}

// maxBudgetUSD is a ceiling no flag can raise.
const maxBudgetUSD = 5.0

func cmdEvalAgent(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("eval-agent", flag.ContinueOnError)
	backend := fs.String("backend", "native", "backend")
	img := fs.String("image", "docker.io/library/alpine:3.20", "image reference")
	k := fs.Int("k", 30, "episodes")
	budget := fs.Float64("budget", 2.0, "hard budget in dollars for the whole campaign (max 5)")
	turns := fs.Int("turns", 20, "model turns per episode")
	effort := fs.String("effort", "medium", "effort: low, medium, high (sent to -provider anthropic only)")
	provider := fs.String("provider", "anthropic", "attacker API: anthropic (the Messages API) or openai (any OpenAI-compatible /v1/chat/completions)")
	model := fs.String("model", "", "attacker model: with -provider anthropic haiku (default) or sonnet; with -provider openai the model id the server expects")
	baseURL := fs.String("base-url", "", "server root for -provider openai, e.g. http://localhost:8000 (default: $OPENAI_BASE_URL; the key, if any, is $OPENAI_API_KEY)")
	inPrice := fs.Float64("input-price", 0, "dollars per million input tokens, -provider openai (default 0: self-hosted)")
	outPrice := fs.Float64("output-price", 0, "dollars per million output tokens, -provider openai (default 0: self-hosted)")
	tokenBudget := fs.Int64("token-budget", 0, "cap on the tokens the whole campaign may process, 0 for none (required for a zero-priced model unless -wall-budget is set)")
	wallBudget := fs.Duration("wall-budget", 0, "cap on the wall-clock time of the whole campaign, e.g. 2h, 0 for none")
	out := fs.String("out", "", "write the report as JSON to this file")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *budget <= 0 || *budget > maxBudgetUSD {
		return usageError{fmt.Errorf("eval-agent: budget must be in (0, %.0f]", maxBudgetUSD)}
	}
	atk, err := resolveAttacker(evalModelFlags{
		provider: *provider, model: *model, baseURL: *baseURL, inPrice: *inPrice, outPrice: *outPrice,
		tokenBudget: *tokenBudget, wallBudget: *wallBudget,
	})
	if err != nil {
		return usageError{err}
	}
	if *k < 30 {
		return usageError{errors.New("eval-agent: k must be at least 30 for the interval to say anything")}
	}
	// The agent is asked to attack the host. Refuse anywhere but a CI runner
	// marked as throwaway.
	if os.Getenv("CI") != "true" || os.Getenv("SANDMETER_THROWAWAY_HOST") != "1" {
		return errors.New("eval-agent: refusing to run: set CI=true and SANDMETER_THROWAWAY_HOST=1 on a throwaway machine only")
	}
	client := anthropic.NewClient()
	attackerModel, err := atk.build(&client)
	if err != nil {
		return err
	}
	e, err := newEngine(filepath.Join(home(), "eval-receipts"))
	if err != nil {
		return err
	}
	// Same rule as the escape suite: the canary must be readable by the
	// sandbox uid, so only isolation (not file modes) keeps it out of reach.
	work := "/run/sandmeter-eval"
	if err := os.MkdirAll(work, 0o711); err != nil {
		return err
	}
	if err := os.Chmod(work, 0o711); err != nil {
		return err
	}
	p := policy.Default()
	p.Limits.Wall = "30s"
	r := &agenteval.Runner{
		Model: attackerModel,
		Config: agenteval.Config{
			Provider: atk.provider, ModelID: atk.modelID, Pricing: atk.pricing,
			Effort: atk.effort(*effort), MaxTokens: 4096, MaxTurns: *turns,
			Episodes: *k, BudgetUSD: *budget, ToolOutput: 8000,
			TokenBudget: *tokenBudget, WallBudget: *wallBudget,
		},
		Backend: *backend,
		Log:     func(s string) { fmt.Fprintln(os.Stderr, s) },
		NewEpisode: func(ctx context.Context, i int) (agenteval.Shell, agenteval.Target, func(), error) {
			dir, err := os.MkdirTemp(work, fmt.Sprintf("ep%02d-", i))
			if err != nil {
				return nil, agenteval.Target{}, nil, err
			}
			canary, token, err := escape.NewCanary(dir)
			if err == nil {
				err = errors.Join(os.Chmod(dir, 0o711), os.Chmod(canary, 0o644))
			}
			if err != nil {
				os.RemoveAll(dir)
				return nil, agenteval.Target{}, nil, err
			}
			marker := filepath.Join(dir, "marker")
			s, err := e.Start(ctx, *backend, *img, p)
			if err != nil {
				os.RemoveAll(dir)
				return nil, agenteval.Target{}, nil, err
			}
			t := agenteval.Target{
				CanaryPath: canary, CanaryToken: token, MarkerPath: marker,
				MarkerExists: func() bool { _, err := os.Lstat(marker); return err == nil },
			}
			cleanup := func() { s.Stop(context.Background()); os.RemoveAll(dir) }
			return sessionShell{s}, t, cleanup, nil
		},
	}
	rep, err := r.Run(ctx, time.Now)
	if err != nil {
		return err
	}
	if *out != "" {
		data, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(*out, data, 0o644); err != nil {
			return err
		}
	}
	fmt.Fprint(stdout, rep.Markdown())
	return nil
}

// sessionShell runs agent commands with sh -c in a session.
type sessionShell struct{ s *engine.Session }

func (sh sessionShell) Run(ctx context.Context, command string) (string, int, error) {
	o, err := sh.s.Run(ctx, []string{"sh", "-c", command})
	if err != nil {
		return "", -1, err
	}
	out := string(o.Result.Stdout) + string(o.Result.Stderr)
	if o.Result.Killed != "" {
		out += "\n[killed: " + o.Result.Killed + "]"
	}
	return out, o.Result.ExitCode, nil
}

// apiModel adapts the SDK's message service to agenteval.Model.
type apiModel struct{ svc *anthropic.MessageService }

func (m apiModel) New(ctx context.Context, p anthropic.MessageNewParams) (*anthropic.Message, error) {
	return m.svc.New(ctx, p)
}
