// Package audit writes and reads the gateway's JSON Lines audit log.
package audit

import (
	"bufio"
	"encoding/json"
	"io"
	"regexp"
	"sync"
	"time"
)

// Event types.
const (
	ToolCall    = "tool_call"
	ToolResult  = "tool_result"
	ToolFlagged = "tool_flagged" // suspicious description in tools/list
	ToolChanged = "tool_changed" // definition changed mid-session
	Rejected    = "rejected"     // malformed or unsupported message
	LLMCall     = "llm_call"     // one model API call through the LLM gateway
	// AttackInjected records adversarial content attckus test inserted.
	AttackInjected = "attack_injected"
)

// Decisions recorded on tool_call events.
const (
	Forwarded      = "forwarded"
	Denied         = "denied"
	WouldDeny      = "would_deny" // dry-run
	PendingApprove = "pending_approval"
	Faulted        = "fault_injected"
	BudgetExceeded = "budget_exceeded"
	ModelDenied    = "model_denied"
)

// Event is one audit record.
type Event struct {
	Time      time.Time      `json:"time"`
	Type      string         `json:"type"`
	Agent     string         `json:"agent,omitempty"`
	Server    string         `json:"server,omitempty"`
	Tool      string         `json:"tool,omitempty"`
	CallID    string         `json:"call_id,omitempty"`
	Args      map[string]any `json:"args,omitempty"`
	ArgsHash  string         `json:"args_hash,omitempty"`
	Decision  string         `json:"decision,omitempty"`
	Rule      string         `json:"rule,omitempty"`
	Fault     string         `json:"fault,omitempty"`
	IsError   bool           `json:"is_error,omitempty"`
	LatencyMs int64          `json:"latency_ms,omitempty"`
	Detail    string         `json:"detail,omitempty"`

	// llm_call fields
	Model        string  `json:"model,omitempty"`
	Status       int     `json:"status,omitempty"`
	InputTokens  int64   `json:"input_tokens,omitempty"`
	OutputTokens int64   `json:"output_tokens,omitempty"`
	CacheTokens  int64   `json:"cache_tokens,omitempty"`
	CostUSD      float64 `json:"cost_usd,omitempty"`
	ToolCalls    int     `json:"tool_calls,omitempty"`
}

// Writer appends events. Safe for concurrent use; a nil Writer discards.
type Writer struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func NewWriter(w io.Writer) *Writer { return &Writer{enc: json.NewEncoder(w)} }

func (w *Writer) Write(e Event) {
	if w == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_ = w.enc.Encode(e)
}

// Read parses an audit log, skipping lines that do not decode.
func Read(r io.Reader) ([]Event, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	var out []Event
	for sc.Scan() {
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) == nil && e.Type != "" {
			out = append(out, e)
		}
	}
	return out, sc.Err()
}

var sensitiveKey = regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token|api_?key|authorization|cookie|private_?key|credential)`)

// Redact copies args, hiding values under sensitive-looking keys at any depth.
func Redact(args map[string]any) map[string]any {
	if args == nil {
		return nil
	}
	out := make(map[string]any, len(args))
	for k, v := range args {
		if sensitiveKey.MatchString(k) {
			out[k] = "REDACTED"
			continue
		}
		out[k] = redactValue(v)
	}
	return out
}

func redactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return Redact(t)
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = redactValue(x)
		}
		return out
	}
	return v
}
