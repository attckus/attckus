package analyze

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/mohitkumar/attckus/internal/audit"
)

var t0 = time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)

func at(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }

func kinds(r Report) map[string]Issue {
	out := map[string]Issue{}
	for _, is := range r.Issues {
		out[is.Kind] = is
	}
	return out
}

func TestRetryStorm(t *testing.T) {
	var evs []audit.Event
	for i := 0; i < 6; i++ {
		evs = append(evs, audit.Event{Time: at(i), Type: audit.ToolCall, Agent: "bot", Tool: "get_order", ArgsHash: "h1", Decision: audit.Faulted, Fault: "error"})
	}
	// Same tool, different arguments: not part of the storm.
	evs = append(evs, audit.Event{Time: at(2), Type: audit.ToolCall, Agent: "bot", Tool: "get_order", ArgsHash: "h2", Decision: audit.Forwarded})
	r := Run(evs, DefaultOptions())
	is, ok := kinds(r)[RetryStorm]
	if !ok || is.Count != 6 {
		t.Fatalf("storm = %+v", r.Issues)
	}
	// Spread over 10 minutes: no storm.
	var slow []audit.Event
	for i := 0; i < 6; i++ {
		slow = append(slow, audit.Event{Time: at(i * 120), Type: audit.ToolCall, Agent: "bot", Tool: "get_order", ArgsHash: "h1", Decision: audit.Forwarded})
	}
	if _, ok := kinds(Run(slow, DefaultOptions()))[RetryStorm]; ok {
		t.Error("calls two minutes apart are not a storm")
	}
}

func TestDuplicateSideEffect(t *testing.T) {
	evs := []audit.Event{
		{Time: at(0), Type: audit.ToolResult, Agent: "bot", Tool: "refund_order", ArgsHash: "o1"},
		{Time: at(3), Type: audit.ToolResult, Agent: "bot", Tool: "refund_order", ArgsHash: "o1"},
		{Time: at(4), Type: audit.ToolResult, Agent: "bot", Tool: "get_order", ArgsHash: "o1"},
		{Time: at(5), Type: audit.ToolResult, Agent: "bot", Tool: "get_order", ArgsHash: "o1"},
		{Time: at(6), Type: audit.ToolResult, Agent: "bot", Tool: "send_email", ArgsHash: "e1", IsError: true},
		{Time: at(7), Type: audit.ToolResult, Agent: "bot", Tool: "send_email", ArgsHash: "e1"},
	}
	r := Run(evs, DefaultOptions())
	dups := 0
	for _, is := range r.Issues {
		if is.Kind == DuplicateSide {
			dups++
			if is.Tool != "refund_order" || is.Severity != "critical" {
				t.Errorf("unexpected duplicate: %+v", is)
			}
		}
	}
	if dups != 1 {
		t.Errorf("duplicates = %d; reads and a failed-then-succeeded send are not duplicates", dups)
	}
}

func TestEscalationAfterFailure(t *testing.T) {
	evs := []audit.Event{
		{Time: at(0), Type: audit.ToolCall, Agent: "bot", Tool: "query", Decision: audit.Denied},
		{Time: at(5), Type: audit.ToolCall, Agent: "bot", Tool: "run_shell", Decision: audit.Forwarded},
		{Time: at(500), Type: audit.ToolCall, Agent: "other", Tool: "get_order", Decision: audit.Denied},
		{Time: at(900), Type: audit.ToolCall, Agent: "other", Tool: "delete_order", Decision: audit.Forwarded}, // outside window
	}
	r := Run(evs, DefaultOptions())
	var n int
	for _, is := range r.Issues {
		if is.Kind == Escalation {
			n++
			if is.Agent != "bot" || is.Tool != "run_shell" {
				t.Errorf("escalation = %+v", is)
			}
		}
	}
	if n != 1 {
		t.Errorf("escalations = %d, want 1", n)
	}
}

func TestSummaryAndText(t *testing.T) {
	evs := []audit.Event{
		{Time: at(0), Type: audit.ToolCall, Agent: "a", Tool: "x", Decision: audit.Forwarded},
		{Time: at(1), Type: audit.ToolResult, Agent: "a", Tool: "x", LatencyMs: 40},
		{Time: at(2), Type: audit.ToolCall, Agent: "a", Tool: "delete_x", Decision: audit.Denied},
		{Time: at(3), Type: audit.ToolFlagged, Tool: "evil", Server: "s", Detail: "contains an <IMPORTANT> block"},
	}
	r := Run(evs, DefaultOptions())
	if s := r.Summary; s.Calls != 2 || s.Forwarded != 1 || s.Blocked != 1 || s.P95Ms != 40 {
		t.Errorf("summary = %+v", s)
	}
	if r.Issues[0].Kind != ToolFlagged {
		t.Errorf("high issues first: %+v", r.Issues)
	}
	var b bytes.Buffer
	Text(&b, r)
	if !strings.Contains(b.String(), "2 tool calls") || !strings.Contains(b.String(), "blocked_attempts") {
		t.Errorf("text:\n%s", b.String())
	}
}

func TestLLMSummaryAndBudget(t *testing.T) {
	evs := []audit.Event{
		{Time: at(0), Type: audit.LLMCall, Agent: "bot", Model: "claude-sonnet-5-5", InputTokens: 1000, OutputTokens: 200, CostUSD: 0.004, Decision: audit.Forwarded},
		{Time: at(1), Type: audit.LLMCall, Agent: "bot", Decision: audit.BudgetExceeded},
		{Time: at(2), Type: audit.LLMCall, Agent: "other", Fault: "rate_limit", Decision: audit.Faulted},
	}
	r := Run(evs, DefaultOptions())
	if s := r.Summary; s.LLMCalls != 3 || s.InputTokens != 1000 || s.CostByAgent["bot"] != 0.004 || s.Faults != 1 {
		t.Errorf("summary = %+v", s)
	}
	if is, ok := kinds(r)[BudgetHit]; !ok || is.Agent != "bot" {
		t.Errorf("budget issue: %+v", r.Issues)
	}
	var b bytes.Buffer
	Text(&b, r)
	if !strings.Contains(b.String(), "3 model calls") || !strings.Contains(b.String(), "bot $0.0040") {
		t.Errorf("text:\n%s", b.String())
	}
}

func TestRunawayLoop(t *testing.T) {
	var evs []audit.Event
	for i := 0; i < 5; i++ { // search -> fetch -> search -> fetch ...
		evs = append(evs,
			audit.Event{Time: at(i * 20), Type: audit.ToolCall, Agent: "bot", Tool: "search_orders", ArgsHash: "a", Decision: audit.Forwarded},
			audit.Event{Time: at(i*20 + 5), Type: audit.ToolCall, Agent: "bot", Tool: "get_order", ArgsHash: "b", Decision: audit.Forwarded})
	}
	is, ok := kinds(Run(evs, DefaultOptions()))[RunawayLoop]
	if !ok || is.Count != 5 || !strings.Contains(is.Detail, "search_orders → get_order") {
		t.Fatalf("loop = %+v", is)
	}
	// Same tools with changing arguments is progress (paging), not a loop.
	var paging []audit.Event
	for i := 0; i < 5; i++ {
		h := string(rune('a' + i))
		paging = append(paging,
			audit.Event{Time: at(i * 20), Type: audit.ToolCall, Agent: "bot", Tool: "search_orders", ArgsHash: h, Decision: audit.Forwarded},
			audit.Event{Time: at(i*20 + 5), Type: audit.ToolCall, Agent: "bot", Tool: "get_order", ArgsHash: h, Decision: audit.Forwarded})
	}
	if _, ok := kinds(Run(paging, DefaultOptions()))[RunawayLoop]; ok {
		t.Error("paging flagged as a loop")
	}
	// Four identical calls in a row are the retry storm detector's job.
	var same []audit.Event
	for i := 0; i < 8; i++ {
		same = append(same, audit.Event{Time: at(i), Type: audit.ToolCall, Agent: "bot", Tool: "get_order", ArgsHash: "x", Decision: audit.Forwarded})
	}
	if _, ok := kinds(Run(same, DefaultOptions()))[RunawayLoop]; ok {
		t.Error("single repeated call flagged as a loop")
	}
}
