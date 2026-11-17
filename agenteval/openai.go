package agenteval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go/v2"
)

// OpenAIModel implements Model on top of an OpenAI-compatible
// {BaseURL}/v1/chat/completions endpoint (vLLM, SGLang, Ollama, a hosted
// provider). It only uses the standard library.
//
// The conversation the loop keeps is in the Messages API shape; the adapter
// translates it on every call and translates the reply back, so the loop, the
// judging and the report do not know which provider is behind Model.
//
// Anything the adapter cannot trust fails closed: a tool call whose
// arguments are not a JSON object with a "command" string, a call to a tool
// that was not offered, or a reply cut off in the middle of a tool call makes
// New return a *ToolCallError. The loop ends the episode as "failed"; the
// call is never executed and never counted as an escape.
type OpenAIModel struct {
	// BaseURL is the server root, with or without a trailing /v1.
	BaseURL string
	// APIKey is optional: self-hosted servers usually need none.
	APIKey string
	// HTTP is the client used; nil means a client with no overall timeout (the
	// context bounds each call).
	HTTP *http.Client
	// MaxAttempts bounds the tries for one request (first try included).
	// Zero means 4.
	MaxAttempts int
	// BackoffBase is the first retry delay, doubled after each retry up to
	// BackoffMax. Zero means 1s and 30s. A Retry-After header from the server
	// replaces the computed delay, capped at BackoffMax.
	BackoffBase, BackoffMax time.Duration
	// Sleep waits for d or until ctx is done; nil uses a real timer. Tests
	// replace it.
	Sleep func(ctx context.Context, d time.Duration) error
}

// NewOpenAIModel returns a model for baseURL. The key may be empty.
func NewOpenAIModel(baseURL, apiKey string) *OpenAIModel {
	return &OpenAIModel{BaseURL: baseURL, APIKey: apiKey}
}

// ToolCallError reports a reply whose tool call cannot be run safely. The
// response was paid for, so the usage travels with the error.
type ToolCallError struct {
	Reason string
	Usage  anthropic.Usage
}

func (e *ToolCallError) Error() string { return "invalid tool call: " + e.Reason }

const maxResponseBytes = 8 << 20

// ---- request side ----------------------------------------------------------

type oaiMessage struct {
	Role       string        `json:"role"`
	Content    *string       `json:"content,omitempty"`
	ToolCalls  []oaiToolCall `json:"tool_calls,omitempty"`
	ToolCallID string        `json:"tool_call_id,omitempty"`
}

type oaiToolCall struct {
	ID       string      `json:"id"`
	Type     string      `json:"type"`
	Function oaiFunction `json:"function"`
}

type oaiFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type oaiTool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string          `json:"name"`
		Description string          `json:"description,omitempty"`
		Parameters  json.RawMessage `json:"parameters,omitempty"`
	} `json:"function"`
}

type oaiRequest struct {
	Model     string       `json:"model"`
	Messages  []oaiMessage `json:"messages"`
	Tools     []oaiTool    `json:"tools,omitempty"`
	MaxTokens int64        `json:"max_tokens,omitempty"`
}

// wireParams is the part of the Messages API request the adapter reads. It is
// obtained by marshalling the SDK params, so any content the loop builds
// (including resp.ToParam) is read in its wire form.
type wireParams struct {
	System []struct {
		Text string `json:"text"`
	} `json:"system"`
	Messages []struct {
		Role    string      `json:"role"`
		Content []wireBlock `json:"content"`
	} `json:"messages"`
	Tools []struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		InputSchema json.RawMessage `json:"input_schema"`
	} `json:"tools"`
}

type wireBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"`
	IsError   bool            `json:"is_error"`
	Content   json.RawMessage `json:"content"`
}

func strp(s string) *string { return &s }

// buildRequest translates Messages API params into a chat-completions body.
func buildRequest(p anthropic.MessageNewParams) (oaiRequest, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return oaiRequest{}, fmt.Errorf("encode params: %w", err)
	}
	var w wireParams
	if err := json.Unmarshal(raw, &w); err != nil {
		return oaiRequest{}, fmt.Errorf("decode params: %w", err)
	}
	req := oaiRequest{Model: string(p.Model), MaxTokens: p.MaxTokens}
	if len(w.System) > 0 {
		var parts []string
		for _, s := range w.System {
			parts = append(parts, s.Text)
		}
		req.Messages = append(req.Messages, oaiMessage{Role: "system", Content: strp(strings.Join(parts, "\n\n"))})
	}
	for _, m := range w.Messages {
		switch m.Role {
		case "assistant":
			req.Messages = append(req.Messages, assistantMessage(m.Content))
		case "user":
			req.Messages = append(req.Messages, userMessages(m.Content)...)
		default:
			return oaiRequest{}, fmt.Errorf("unsupported message role %q", m.Role)
		}
	}
	for _, t := range w.Tools {
		var ot oaiTool
		ot.Type = "function"
		ot.Function.Name, ot.Function.Description, ot.Function.Parameters = t.Name, t.Description, t.InputSchema
		req.Tools = append(req.Tools, ot)
	}
	return req, nil
}

// assistantMessage turns text and tool_use blocks into one assistant message;
// tool calls keep the order of the blocks.
func assistantMessage(blocks []wireBlock) oaiMessage {
	msg := oaiMessage{Role: "assistant"}
	var text []string
	for _, b := range blocks {
		switch b.Type {
		case "text":
			text = append(text, b.Text)
		case "tool_use":
			args := string(b.Input)
			if args == "" || args == "null" {
				args = "{}"
			}
			msg.ToolCalls = append(msg.ToolCalls, oaiToolCall{ID: b.ID, Type: "function",
				Function: oaiFunction{Name: b.Name, Arguments: args}})
		}
	}
	if len(text) > 0 {
		msg.Content = strp(strings.Join(text, "\n"))
	} else if len(msg.ToolCalls) == 0 {
		msg.Content = strp("")
	}
	return msg
}

// userMessages turns a user turn into role=tool messages (one per tool result,
// in order) followed by a user message for any plain text.
func userMessages(blocks []wireBlock) []oaiMessage {
	var out []oaiMessage
	var text []string
	for _, b := range blocks {
		switch b.Type {
		case "text":
			text = append(text, b.Text)
		case "tool_result":
			content := toolResultText(b.Content)
			if b.IsError {
				content = "error: " + content
			}
			out = append(out, oaiMessage{Role: "tool", ToolCallID: b.ToolUseID, Content: strp(content)})
		}
	}
	if len(text) > 0 {
		out = append(out, oaiMessage{Role: "user", Content: strp(strings.Join(text, "\n"))})
	}
	return out
}

// toolResultText reads a tool_result content, which is a string or a list of
// text blocks.
func toolResultText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var blocks []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &blocks) != nil {
		return ""
	}
	var parts []string
	for _, b := range blocks {
		parts = append(parts, b.Text)
	}
	return strings.Join(parts, "\n")
}

// ---- response side ---------------------------------------------------------

type oaiResponse struct {
	Choices []struct {
		FinishReason string `json:"finish_reason"`
		Message      struct {
			Content   json.RawMessage `json:"content"`
			Refusal   string          `json:"refusal"`
			ToolCalls []oaiToolCall   `json:"tool_calls"`
		} `json:"message"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens     int64 `json:"prompt_tokens"`
		CompletionTokens int64 `json:"completion_tokens"`
		Details          struct {
			CachedTokens int64 `json:"cached_tokens"`
		} `json:"prompt_tokens_details"`
	} `json:"usage"`
}

// messageText reads message.content, a string, null, or a list of parts.
func messageText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) != nil {
		return ""
	}
	var out []string
	for _, p := range parts {
		if p.Type == "" || p.Type == "text" {
			out = append(out, p.Text)
		}
	}
	return strings.Join(out, "")
}

// usageOf maps the reply's usage to the Messages API usage the budget guard
// costs. A reply without usage is estimated from sizes at 3 bytes per token,
// the same over-estimate the guard uses for its own pre-check, so a server
// that omits usage cannot hide spend. Cached prompt tokens are split out so
// that input_tokens + cache_read_input_tokens is the whole prompt.
func usageOf(r oaiResponse, reqBytes, respBytes int) anthropic.Usage {
	var u anthropic.Usage
	if r.Usage == nil {
		u.InputTokens = int64(reqBytes/3 + 1)
		u.OutputTokens = int64(respBytes/3 + 1)
		return u
	}
	cached := min(r.Usage.Details.CachedTokens, r.Usage.PromptTokens)
	u.InputTokens = r.Usage.PromptTokens - cached
	u.CacheReadInputTokens = cached
	u.OutputTokens = r.Usage.CompletionTokens
	return u
}

// stopReasonOf maps finish_reason. A reply that carries tool calls is
// tool_use whatever the server wrote (several servers say "stop").
func stopReasonOf(finish string, calls int, refusal string) anthropic.StopReason {
	switch {
	case refusal != "" || finish == "content_filter":
		return anthropic.StopReasonRefusal
	case calls > 0:
		return anthropic.StopReasonToolUse
	case finish == "length":
		return anthropic.StopReasonMaxTokens
	default:
		return anthropic.StopReasonEndTurn
	}
}

// parseResponse turns a chat-completions reply into a Messages API message.
// sent is the size of the request body, for the usage estimate.
func parseResponse(body []byte, sent int, offered map[string]bool) (*anthropic.Message, error) {
	var r oaiResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if len(r.Choices) == 0 {
		return nil, errors.New("response has no choices")
	}
	ch := r.Choices[0]
	usage := usageOf(r, sent, len(body))
	var content []map[string]any
	if text := messageText(ch.Message.Content); text != "" {
		content = append(content, map[string]any{"type": "text", "text": text})
	}
	seen := map[string]bool{}
	for i, tc := range ch.Message.ToolCalls {
		call, err := toolUseBlock(i, tc, offered, seen)
		if err != nil {
			return nil, &ToolCallError{Reason: err.Error(), Usage: usage}
		}
		content = append(content, call)
	}
	if len(ch.Message.ToolCalls) > 0 && ch.FinishReason == "length" {
		return nil, &ToolCallError{Reason: "reply truncated (finish_reason length) in the middle of tool calls", Usage: usage}
	}
	if ch.FinishReason == "tool_calls" && len(ch.Message.ToolCalls) == 0 {
		return nil, &ToolCallError{Reason: "finish_reason tool_calls without any tool call", Usage: usage}
	}
	stop := stopReasonOf(ch.FinishReason, len(ch.Message.ToolCalls), ch.Message.Refusal)
	if content == nil {
		content = []map[string]any{}
	}
	msg := map[string]any{
		"id": "openai", "type": "message", "role": "assistant", "model": "openai-compatible",
		"stop_reason": string(stop), "content": content,
		"usage": map[string]any{
			"input_tokens": usage.InputTokens, "output_tokens": usage.OutputTokens,
			"cache_read_input_tokens": usage.CacheReadInputTokens,
		},
	}
	enc, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	var out anthropic.Message
	if err := json.Unmarshal(enc, &out); err != nil {
		return nil, fmt.Errorf("build message: %w", err)
	}
	return &out, nil
}

// toolUseBlock validates one tool call and returns it as a tool_use block.
// Calls keep the server's order; a missing or repeated id gets a
// deterministic one derived from the index so results can be matched.
func toolUseBlock(i int, tc oaiToolCall, offered map[string]bool, seen map[string]bool) (map[string]any, error) {
	if !offered[tc.Function.Name] {
		return nil, fmt.Errorf("call %d: tool %q was not offered", i, tc.Function.Name)
	}
	var args map[string]json.RawMessage
	if err := json.Unmarshal([]byte(tc.Function.Arguments), &args); err != nil || args == nil {
		return nil, fmt.Errorf("call %d: arguments are not a JSON object: %s", i, clip(tc.Function.Arguments, 200))
	}
	var cmd string
	if err := json.Unmarshal(args["command"], &cmd); err != nil || cmd == "" {
		return nil, fmt.Errorf("call %d: arguments have no non-empty string \"command\"", i)
	}
	id := tc.ID
	if id == "" || seen[id] {
		id = "call_" + strconv.Itoa(i)
		for seen[id] {
			id += "_"
		}
	}
	seen[id] = true
	return map[string]any{"type": "tool_use", "id": id, "name": tc.Function.Name,
		"input": json.RawMessage(tc.Function.Arguments)}, nil
}

// ---- transport -------------------------------------------------------------

func (m *OpenAIModel) endpoint() string {
	base := strings.TrimRight(m.BaseURL, "/")
	base = strings.TrimSuffix(base, "/v1")
	return base + "/v1/chat/completions"
}

// New implements Model.
func (m *OpenAIModel) New(ctx context.Context, p anthropic.MessageNewParams) (*anthropic.Message, error) {
	req, err := buildRequest(p)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	offered := map[string]bool{}
	for _, t := range req.Tools {
		offered[t.Function.Name] = true
	}
	respBody, err := m.post(ctx, body)
	if err != nil {
		return nil, err
	}
	return parseResponse(respBody, len(body), offered)
}

// post sends body, retrying 429, 5xx and transport errors with bounded
// exponential backoff. Other statuses fail at once.
func (m *OpenAIModel) post(ctx context.Context, body []byte) ([]byte, error) {
	attempts := m.MaxAttempts
	if attempts <= 0 {
		attempts = 4
	}
	base, maxDelay := m.BackoffBase, m.BackoffMax
	if base <= 0 {
		base = time.Second
	}
	if maxDelay <= 0 {
		maxDelay = 30 * time.Second
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		out, retryAfter, retryable, err := m.once(ctx, body)
		if err == nil {
			return out, nil
		}
		lastErr = err
		if !retryable || ctx.Err() != nil {
			break
		}
		if attempt == attempts-1 {
			break
		}
		delay := min(base<<attempt, maxDelay)
		if retryAfter > 0 {
			delay = min(retryAfter, maxDelay)
		}
		if err := m.sleep(ctx, delay); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("openai-compatible endpoint %s: %w", m.endpoint(), lastErr)
}

func (m *OpenAIModel) sleep(ctx context.Context, d time.Duration) error {
	if m.Sleep != nil {
		return m.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// once makes one HTTP request.
func (m *OpenAIModel) once(ctx context.Context, body []byte) (out []byte, retryAfter time.Duration, retryable bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.endpoint(), bytes.NewReader(body))
	if err != nil {
		return nil, 0, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	if m.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+m.APIKey)
	}
	client := m.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, true, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, 0, true, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode == http.StatusOK {
		return data, 0, false, nil
	}
	err = fmt.Errorf("HTTP %d: %s", resp.StatusCode, clip(strings.TrimSpace(string(data)), 300))
	retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
	return nil, parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()), retry, err
}

// parseRetryAfter reads delay-seconds or an HTTP date; zero when absent or
// unusable.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		return max(0, time.Duration(secs)*time.Second)
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(0, t.Sub(now))
	}
	return 0
}
