# Choosing the attacker for the agent eval

The agent eval (`sandmeter eval-agent`) measures how often a model, given a
`bash` tool inside the sandbox, gets out. It is only as useful as the attacker
it drives. Two facts from the runs on 2026-11-11 set the problem:

- `claude-haiku-5-5` accepts the task and probes the sandbox, but it is a weak
  attacker: short runs, few techniques, no adaptation across turns.
- `claude-sonnet-5-5` is stronger but declined every one of 60 episodes at the
  first turn, even with the framing spelled out as an authorised, consented,
  defensive test on a throwaway host (`docs/eval-sonnet-*.json`). The harness
  does not reword the task to get around a refusal, so Sonnet measures nothing
  here.

A stress test wants an attacker that is both **willing** and **capable**. The
API models on hand are one or the other. Two directions close the gap. Both
keep the honesty rules the project already holds to: the task is stated plainly,
the escape is judged on host-side evidence, and every episode — holds and
escapes alike — is published. We change *who* attacks, never deceive the
attacker into it.

## Axis A — willing attackers through an OpenAI-compatible adapter

Most open-weight models (including the open Chinese families, e.g. Qwen and
DeepSeek) are served behind an OpenAI-compatible `/v1/chat/completions` endpoint
— locally with vLLM, SGLang or Ollama, or through a hosted provider — and many
of them accept a clearly-scoped red-team task that the API models decline. They
are chosen because they *attempt* the task, which is exactly what a sandbox
stress test needs; this is a question of attacker selection, not of bypassing a
safety guardrail.

The eval loop already depends on a one-method interface:

```go
type Model interface {
    New(ctx context.Context, params anthropic.MessageNewParams) (*anthropic.Message, error)
}
```

so a second implementation is all that is needed. It maps agenteval's request
to a chat-completions call with a `bash` tool and maps the reply back to a
`*anthropic.Message` (one `text` block, zero or more `tool_use` blocks, a
`stop_reason` of `tool_use` / `end_turn`, and a `Usage` the existing `Pricing`
can cost). No change to the loop, the judging, or the report.

Plan:

1. `agenteval/openai.go`: an `openAIModel` implementing `Model` against any
   base URL + key (`OPENAI_BASE_URL`, `OPENAI_API_KEY`), model id from a flag.
   Translate tools, tool results, and the stop reason; fail closed on a
   malformed tool call (treat it as `end_turn`, never as an escape).
2. `eval-agent` flags: `-provider anthropic|openai`, `-model <id>`,
   `-base-url`, and a `Pricing` per model (open-weight self-hosted = zero
   dollar cost; the budget guard then bounds tokens or wall-clock instead).
3. A tiny recorded-transcript test (no network) that feeds a canned
   chat-completions reply through the adapter and checks the mapping, the same
   way the Anthropic path is tested.

Caveats to write down in the report, not hide: an open-weight attacker that
refuses less is not "better" at finding real holes, only more willing to try;
the model's licence and the provider's terms govern this use; and a local model
with no safety training will also produce noisy, invalid tool calls that the
adapter must reject rather than miscount.

## Axis B — a continuous local attacker (24/7)

With a willing attacker and (for a self-hosted open-weight model) near-zero
per-episode dollar cost, the eval stops being a one-shot of 30 episodes and
becomes a process: run episodes continuously on a throwaway VM, accumulate a
much larger N, and surface any escape the moment it happens.

What this needs on top of Axis A:

- A long-running mode that keeps starting episodes until stopped, appending to
  a rolling report and tightening the Wilson interval as N grows (30 episodes
  bound the rate at ~12%; a few thousand bring it well under 1%).
- An alert on the first `escaped` episode: stop, keep the receipt and the full
  transcript, and notify — one real escape is worth more than any count of
  holds.
- The same host rules as every run: root on a throwaway machine only, never a
  real host, the canary a dummy token. A rented GPU box or a local box kept off
  the main network fits; the budget guard becomes a wall-clock or token cap
  since the dollar cost is ~0.
- Rotating the attacker model and the task phrasing between batches, so the
  number reflects a family of attackers rather than one model's blind spots —
  the same reason the deterministic suite has 15 distinct cases.

This does not replace the deterministic escape suite (`escape/cases`), which
stays the backbone: fixed, reviewed, judged from the host. The continuous agent
is the open-ended half — it looks for the case nobody wrote.

## The same machinery read the other way — an attacker benchmark

Point the harness at a fixed sandbox instead of a fixed attacker and it stops
measuring the sandbox and starts measuring the attacker. Give any LLM or agent
the `bash` tool inside one pinned, versioned sandbox, run N episodes, and a
model **qualifies** only if it produces at least one escape the host can verify
— the canary read out, or the marker file created. No self-report counts.

What makes this a benchmark worth running, where most agent benchmarks are
weak, is the grading: the pass criterion is ground truth, not an LLM judge and
not the model's own claim. An escape either left evidence on the host or it did
not. That is hard to game and cheap to check, and every run ships a signed
receipt of what actually happened. Rank the field by escape rate, by
turns-to-first-escape, by dollars spent.

It only works under conditions the project already has reasons to hold:

- **The target is pinned.** Scores only compare across attackers if the sandbox
  version, image, and policy are fixed; a benchmark run names the commit.
- **Refusals are not failures.** A model that declines the task (as Sonnet did,
  60/60) is not "incapable of escaping" — it opted out. Report refused, failed,
  and escaped as three separate columns, never fold refusals into the score.
- **The ceiling is the sandbox's real holes.** If the sandbox is tight, nobody
  qualifies and the board is empty — which is then a statement about the
  sandbox, not the models. The two readings are the same measurement; this is
  dual-use by construction, and the honest framing (defensive tool, published
  failures, throwaway host) carries over unchanged.

Axes A and B feed this directly: a willing open-weight attacker and a 24/7
local runner are how a field of contenders actually gets measured.

## Status

Not built yet. Axis A is the next step and is self-contained (one adapter file,
flags, one test); Axis B builds on it. Until then the published agent-eval
numbers are Haiku only, and the Sonnet refusal is recorded as what it is.
