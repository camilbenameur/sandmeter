package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go/v2"

	"github.com/camilbenameur/sandmeter/agenteval"
)

// evalModelFlags are the eval-agent flags that choose the attacker.
type evalModelFlags struct {
	provider, model, baseURL string
	inPrice, outPrice        float64
	tokenBudget              int64
	wallBudget               time.Duration
}

// attacker is the resolved choice: what to call and how to cost it.
type attacker struct {
	provider string
	modelID  string
	pricing  agenteval.Pricing
	baseURL  string // openai only
}

// resolveAttacker validates the attacker flags. It touches no network and
// reads only OPENAI_BASE_URL; the API keys are checked later, once the
// throwaway-host guard has passed.
func resolveAttacker(f evalModelFlags) (attacker, error) {
	if f.tokenBudget < 0 || f.wallBudget < 0 || f.inPrice < 0 || f.outPrice < 0 {
		return attacker{}, errors.New("eval-agent: prices and caps cannot be negative")
	}
	switch f.provider {
	case "anthropic":
		name := f.model
		if name == "" {
			name = "haiku"
		}
		m, ok := agenteval.Models[name]
		if !ok {
			return attacker{}, fmt.Errorf("eval-agent: unknown model %q (haiku or sonnet; use -provider openai for other model ids)", name)
		}
		if f.baseURL != "" || f.inPrice != 0 || f.outPrice != 0 {
			return attacker{}, errors.New("eval-agent: -base-url, -input-price and -output-price apply to -provider openai only")
		}
		return attacker{provider: "anthropic", modelID: m.ID, pricing: m.Pricing}, nil
	case "openai":
		if f.model == "" {
			return attacker{}, errors.New("eval-agent: -model is required with -provider openai (the model id the server expects)")
		}
		base := f.baseURL
		if base == "" {
			base = os.Getenv("OPENAI_BASE_URL")
		}
		if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
			return attacker{}, errors.New("eval-agent: -provider openai needs an http(s) base URL from -base-url or OPENAI_BASE_URL")
		}
		p := agenteval.Pricing{InputPerMTok: f.inPrice, OutputPerMTok: f.outPrice}
		// A zero-priced model never trips the dollar guard: something else
		// must be able to stop it.
		if p == (agenteval.Pricing{}) && f.tokenBudget == 0 && f.wallBudget == 0 {
			return attacker{}, errors.New("eval-agent: a zero-priced model needs -token-budget or -wall-budget, or it could run forever (or set -input-price and -output-price)")
		}
		return attacker{provider: "openai", modelID: f.model, pricing: p, baseURL: base}, nil
	default:
		return attacker{}, fmt.Errorf("eval-agent: unknown provider %q (anthropic or openai)", f.provider)
	}
}

// build returns the agenteval.Model for the attacker, or an error naming the
// missing credential. The OpenAI-compatible key is optional.
func (a attacker) build(client *anthropic.Client) (agenteval.Model, error) {
	if a.provider == "openai" {
		return agenteval.NewOpenAIModel(a.baseURL, os.Getenv("OPENAI_API_KEY")), nil
	}
	if os.Getenv("ANTHROPIC_API_KEY") == "" {
		return nil, errors.New("eval-agent: ANTHROPIC_API_KEY is not set")
	}
	return apiModel{&client.Messages}, nil
}

// effort is the effort level to send: only the Messages API has one.
func (a attacker) effort(v string) anthropic.OutputConfigEffort {
	if a.provider != "anthropic" {
		return ""
	}
	return anthropic.OutputConfigEffort(v)
}
