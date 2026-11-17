package llm

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/attckus/attckus/internal/attack"
	"github.com/attckus/attckus/internal/audit"
	"github.com/attckus/attckus/internal/chaos"
	"github.com/attckus/attckus/internal/policy"
)

const testPolicy = `{
  "version": 1,
  "mode": "enforce",
  "rules": [
    {"name": "no deletes", "tool": "delete_*", "action": "deny", "reason": "destructive"},
    {"name": "approve email", "tool": "send_email", "action": "approve"}
  ],
  "llm": {"models": ["anthropic/claude-*", "openai/gpt-*"]}
}`

const anthropicJSON = `{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-5-5",
 "content":[{"type":"text","text":"Deleting it."},{"type":"tool_use","id":"toolu_1","name":"delete_order","input":{"order_id":"A1"}}],
 "stop_reason":"tool_use","usage":{"input_tokens":1000,"output_tokens":200,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}}`

func anthropicSSE(tool, args1, args2 string) string {
	ev := func(name, data string) string { return "event: " + name + "\ndata: " + data + "\n\n" }
	return ev("message_start", `{"type":"message_start","message":{"id":"msg_1","model":"claude-sonnet-5-5","usage":{"input_tokens":1000,"output_tokens":1}}}`) +
		ev("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`) +
		ev("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"On it."}}`) +
		ev("content_block_stop", `{"type":"content_block_stop","index":0}`) +
		ev("content_block_start", `{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"`+tool+`","input":{}}}`) +
		ev("content_block_delta", `{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":`+args1+`}}`) +
		ev("content_block_delta", `{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":`+args2+`}}`) +
		ev("content_block_stop", `{"type":"content_block_stop","index":1}`) +
		ev("message_delta", `{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":200}}`) +
		ev("message_stop", `{"type":"message_stop"}`)
}

const openAIJSON = `{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-5","choices":[{"index":0,
 "message":{"role":"assistant","content":null,"tool_calls":[
   {"id":"call_1","type":"function","function":{"name":"delete_order","arguments":"{\"order_id\":\"A1\"}"}},
   {"id":"call_2","type":"function","function":{"name":"get_order","arguments":"{\"order_id\":\"A1\"}"}}]},
 "finish_reason":"tool_calls"}],
 "usage":{"prompt_tokens":1000,"completion_tokens":50,"prompt_tokens_details":{"cached_tokens":200}}}`

func openAISSE() string {
	d := func(s string) string { return "data: " + s + "\n\n" }
	return d(`{"id":"c1","model":"gpt-5","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}`) +
		d(`{"id":"c1","model":"gpt-5","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"delete_order","arguments":"{\"order"}}]},"finish_reason":null}]}`) +
		d(`{"id":"c1","model":"gpt-5","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"_id\":\"A1\"}"}}]},"finish_reason":null}]}`) +
		d(`{"id":"c1","model":"gpt-5","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`) +
		d(`{"id":"c1","model":"gpt-5","choices":[],"usage":{"prompt_tokens":500,"completion_tokens":20}}`) +
		d(`[DONE]`)
}

// fakeUpstream records the last request and answers with a canned body.
type fakeUpstream struct {
	mu      sync.Mutex
	body    string
	ctype   string
	status  int
	lastReq []byte
	lastHdr http.Header
	calls   int
}

func (f *fakeUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastReq, _ = io.ReadAll(r.Body)
	f.lastHdr = r.Header.Clone()
	w.Header().Set("Content-Type", f.ctype)
	w.Header().Set("request-id", "req_123")
	if f.status != 0 {
		w.WriteHeader(f.status)
	}
	_, _ = io.WriteString(w, f.body)
}

type harness struct {
	proxy  *Proxy
	up     *fakeUpstream
	srv    *httptest.Server
	events *bytes.Buffer
	mu     *sync.Mutex
}

func newHarness(t *testing.T, provider, body, ctype string, mutate func(*policy.Policy)) *harness {
	t.Helper()
	pol, err := policy.Parse([]byte(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(pol)
	}
	up := &fakeUpstream{body: body, ctype: ctype}
	upSrv := httptest.NewServer(up)
	t.Cleanup(upSrv.Close)
	prices, _ := LoadPrices()
	prices.Set("openai/gpt-5", Price{Input: 1, Output: 10, CacheRead: 0.1})
	var buf bytes.Buffer
	var mu sync.Mutex
	p := &Proxy{
		Policy: pol, Agent: "support-bot", Prices: prices,
		Audit:     audit.NewWriter(lockedWriter{&buf, &mu}),
		Upstreams: map[string]Upstream{Anthropic: {Provider: Anthropic, BaseURL: upSrv.URL}, OpenAI: {Provider: OpenAI, BaseURL: upSrv.URL + "/v1"}},
	}
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	return &harness{proxy: p, up: up, srv: srv, events: &buf, mu: &mu}
}

type lockedWriter struct {
	b  *bytes.Buffer
	mu *sync.Mutex
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (h *harness) post(t *testing.T, path, body string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", h.srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func (h *harness) audit(t *testing.T) []audit.Event {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	evs, err := audit.Read(bytes.NewReader(h.events.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

func llmEvent(t *testing.T, evs []audit.Event) audit.Event {
	t.Helper()
	for _, e := range evs {
		if e.Type == audit.LLMCall {
			return e
		}
	}
	t.Fatalf("no llm_call event in %+v", evs)
	return audit.Event{}
}

const anthropicReq = `{"model":"claude-sonnet-5-5","max_tokens":1024,"messages":[{"role":"user","content":"delete order A1"}]}`

func TestAnthropicJSONBlockedToolIsReplaced(t *testing.T) {
	h := newHarness(t, Anthropic, anthropicJSON, "application/json", nil)
	resp, body := h.post(t, "/v1/messages", anthropicReq, map[string]string{"x-api-key": "caller-key"})
	if resp.StatusCode != 200 || resp.Header.Get("request-id") != "req_123" {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var out struct {
		Content []struct {
			Type, Text, Name string
		}
		StopReason string `json:"stop_reason"`
	}
	_ = json.Unmarshal([]byte(body), &out)
	if out.StopReason != "end_turn" || len(out.Content) != 2 || out.Content[1].Type != "text" || !strings.Contains(out.Content[1].Text, "blocked by policy (no deletes)") {
		t.Errorf("rewritten response: %s", body)
	}
	if h.up.lastHdr.Get("x-api-key") != "caller-key" || h.up.lastHdr.Get("anthropic-version") == "" {
		t.Errorf("caller credentials not forwarded: %v", h.up.lastHdr)
	}
	evs := h.audit(t)
	if evs[0].Type != audit.ToolCall || evs[0].Decision != audit.Denied || evs[0].Server != "llm:anthropic" {
		t.Errorf("tool audit: %+v", evs[0])
	}
	e := llmEvent(t, evs)
	if e.InputTokens != 1000 || e.OutputTokens != 200 || math.Abs(e.CostUSD-0.004) > 1e-9 || e.ToolCalls != 1 {
		t.Errorf("llm audit: %+v", e)
	}
	if got := h.proxy.Spent("support-bot"); math.Abs(got-0.004) > 1e-9 {
		t.Errorf("spent = %v", got)
	}
}

func TestAnthropicStreamBlockedTool(t *testing.T) {
	h := newHarness(t, Anthropic, anthropicSSE("delete_order", `"{\"order_"`, `"id\":\"A1\"}"`), "text/event-stream", nil)
	_, body := h.post(t, "/v1/messages", strings.Replace(anthropicReq, `"max_tokens"`, `"stream":true,"max_tokens"`, 1), nil)
	if strings.Contains(body, `"tool_use"`) || strings.Contains(body, "input_json_delta") {
		t.Errorf("blocked tool_use leaked:\n%s", body)
	}
	if !strings.Contains(body, "blocked by policy (no deletes)") || !strings.Contains(body, `"stop_reason":"end_turn"`) || !strings.Contains(body, "On it.") {
		t.Errorf("stream not rewritten:\n%s", body)
	}
	e := llmEvent(t, h.audit(t))
	if e.InputTokens != 1000 || e.OutputTokens != 200 {
		t.Errorf("stream usage: %+v", e)
	}
}

func TestAnthropicStreamAllowedToolPassesThrough(t *testing.T) {
	sse := anthropicSSE("get_order", `"{\"order_"`, `"id\":\"A1\"}"`)
	h := newHarness(t, Anthropic, sse, "text/event-stream", nil)
	_, body := h.post(t, "/v1/messages", anthropicReq, nil)
	if body != sse {
		t.Errorf("allowed stream must be byte-identical\n got: %q\nwant: %q", body, sse)
	}
	evs := h.audit(t)
	if evs[0].Tool != "get_order" || evs[0].Decision != audit.Forwarded || evs[0].Args["order_id"] != "A1" {
		t.Errorf("tool audit: %+v", evs[0])
	}
}

func TestOpenAIJSONPartialBlock(t *testing.T) {
	h := newHarness(t, OpenAI, openAIJSON, "application/json", nil)
	_, body := h.post(t, "/v1/chat/completions", `{"model":"gpt-5","messages":[]}`, map[string]string{"Authorization": "Bearer sk-caller"})
	var out struct {
		Choices []struct {
			Message struct {
				Content   string
				ToolCalls []struct{ Function struct{ Name string } } `json:"tool_calls"`
			}
			FinishReason string `json:"finish_reason"`
		}
	}
	_ = json.Unmarshal([]byte(body), &out)
	c := out.Choices[0]
	if len(c.Message.ToolCalls) != 1 || c.Message.ToolCalls[0].Function.Name != "get_order" || c.FinishReason != "tool_calls" || !strings.Contains(c.Message.Content, "delete_order") {
		t.Errorf("partial rewrite: %s", body)
	}
	if h.up.lastHdr.Get("Authorization") != "Bearer sk-caller" {
		t.Error("caller auth not forwarded")
	}
	e := llmEvent(t, h.audit(t))
	if e.InputTokens != 800 || e.CacheTokens != 200 || e.OutputTokens != 50 {
		t.Errorf("openai usage: %+v", e)
	}
}

func TestOpenAIStreamAllBlocked(t *testing.T) {
	h := newHarness(t, OpenAI, openAISSE(), "text/event-stream", nil)
	_, body := h.post(t, "/v1/chat/completions", `{"model":"gpt-5","stream":true,"messages":[]}`, nil)
	if strings.Contains(body, "tool_calls\":[") || !strings.Contains(body, `"finish_reason":"stop"`) || !strings.Contains(body, "blocked by policy") || !strings.Contains(body, "[DONE]") {
		t.Errorf("openai stream:\n%s", body)
	}
	if !strings.Contains(string(h.up.lastReq), `"include_usage":true`) {
		t.Errorf("include_usage not requested: %s", h.up.lastReq)
	}
	if e := llmEvent(t, h.audit(t)); e.InputTokens != 500 || e.OutputTokens != 20 {
		t.Errorf("stream usage: %+v", e)
	}
}

func TestBudgetLowersMaxTokensThenRefuses(t *testing.T) {
	h := newHarness(t, Anthropic, anthropicJSON, "application/json", func(p *policy.Policy) {
		p.LLM.Budgets = []policy.Budget{{Agent: "support-bot", USD: 0.005}}
	})
	h.post(t, "/v1/messages", anthropicReq, nil)
	var sent struct {
		MaxTokens int `json:"max_tokens"`
	}
	_ = json.Unmarshal(h.up.lastReq, &sent)
	if sent.MaxTokens >= 1024 || sent.MaxTokens < minOutputTokens {
		t.Errorf("max_tokens should be lowered to fit $0.005, got %d", sent.MaxTokens)
	}
	resp, body := h.post(t, "/v1/messages", anthropicReq, nil)
	if resp.StatusCode != 429 || !strings.Contains(body, `"rate_limit_error"`) {
		t.Errorf("second call should be refused: %d %s", resp.StatusCode, body)
	}
	if h.up.calls != 1 {
		t.Errorf("refused call reached upstream")
	}
	// Another agent has its own (unlimited) allowance.
	if resp, _ := h.post(t, "/v1/messages", anthropicReq, map[string]string{AgentHeader: "report-writer"}); resp.StatusCode != 200 {
		t.Errorf("other agent: %d", resp.StatusCode)
	}
}

func TestModelAllowlist(t *testing.T) {
	h := newHarness(t, Anthropic, anthropicJSON, "application/json", nil)
	resp, body := h.post(t, "/v1/messages", `{"model":"some-other-model","messages":[]}`, nil)
	if resp.StatusCode != 403 || !strings.Contains(body, `"permission_error"`) {
		t.Errorf("model allowlist: %d %s", resp.StatusCode, body)
	}
}

func TestChaosProviderFaults(t *testing.T) {
	h := newHarness(t, Anthropic, anthropicJSON, "application/json", nil)
	inj, err := chaos.New(chaos.Config{Enabled: true, Seed: 1, Faults: []chaos.Fault{
		{Tool: "anthropic/claude-sonnet-*", Type: chaos.RateLimit, Probability: 1},
		{Tool: "openai/*", Type: chaos.Error, Probability: 1},
	}}, "staging")
	if err != nil {
		t.Fatal(err)
	}
	h.proxy.Chaos = inj
	resp, body := h.post(t, "/v1/messages", anthropicReq, nil)
	if resp.StatusCode != 429 || resp.Header.Get("retry-after") != "1" || !strings.Contains(body, "injected") {
		t.Errorf("rate_limit fault: %d %s", resp.StatusCode, body)
	}
	resp, body = h.post(t, "/v1/chat/completions", `{"model":"gpt-5","messages":[]}`, nil)
	if resp.StatusCode != 503 || !strings.Contains(body, `"error"`) {
		t.Errorf("error fault: %d %s", resp.StatusCode, body)
	}
	if h.up.calls != 0 {
		t.Error("faulted calls must not reach the provider")
	}
	if e := llmEvent(t, h.audit(t)); e.Decision != audit.Faulted || e.Fault != "rate_limit" {
		t.Errorf("audit: %+v", e)
	}
}

func TestInjectedKeyReplacesCaller(t *testing.T) {
	h := newHarness(t, Anthropic, anthropicJSON, "application/json", nil)
	up := h.proxy.Upstreams[Anthropic]
	up.APIKey = "server-key"
	h.proxy.Upstreams[Anthropic] = up
	h.post(t, "/v1/messages", anthropicReq, map[string]string{"x-api-key": "caller-key"})
	if h.up.lastHdr.Get("x-api-key") != "server-key" {
		t.Errorf("x-api-key = %q", h.up.lastHdr.Get("x-api-key"))
	}
}

func TestUpstreamErrorsPassThroughUnmetered(t *testing.T) {
	h := newHarness(t, Anthropic, `{"type":"error","error":{"type":"overloaded_error","message":"busy"}}`, "application/json", nil)
	h.up.status = 529
	resp, body := h.post(t, "/v1/messages", anthropicReq, nil)
	if resp.StatusCode != 529 || !strings.Contains(body, "busy") {
		t.Errorf("upstream error: %d %s", resp.StatusCode, body)
	}
	if e := llmEvent(t, h.audit(t)); e.Status != 529 || e.CostUSD != 0 {
		t.Errorf("audit: %+v", e)
	}
}

func TestReadUsageCompaction(t *testing.T) {
	var u Usage
	model := ""
	readUsage(Anthropic, []byte(`{"type":"message_delta","usage":{"output_tokens":300,"iterations":[{"type":"compaction","input_tokens":50,"output_tokens":10},{"type":"message","input_tokens":999}]}}`), &u, &model)
	if u.OutputTokens != 310 || u.InputTokens != 50 {
		t.Errorf("usage = %+v", u)
	}
	readUsage(OpenAI, []byte(`{"model":"gpt-5","usage":null}`), &u, &model)
	if model != "gpt-5" {
		t.Error("model from openai chunk")
	}
}

func TestFitOutputTokens(t *testing.T) {
	p := Price{Input: 2, Output: 10}
	if n, ok := fitOutputTokens(p, 1000, 4096, 0.01); !ok || n != 800 {
		t.Errorf("fit = %d %v, want 800", n, ok)
	}
	if _, ok := fitOutputTokens(p, 1000, 4096, 0.003); ok {
		t.Error("$0.001 left for output is under the minimum")
	}
	if n, _ := fitOutputTokens(p, 10, 100, 10); n != 100 {
		t.Error("never raise max_tokens")
	}
}

func TestAttacksOnRequests(t *testing.T) {
	h := newHarness(t, Anthropic, anthropicJSON, "application/json", nil)
	inj, _ := attack.New([]attack.Attack{
		{Type: attack.PoisonTool, Tool: "get_order", Target: "delete_order"},
		{Type: attack.InjectResult, Tool: "fetch"},
	}, "attckus-canary-xyz")
	h.proxy.Attacks = inj
	req := `{"model":"claude-sonnet-5-5","max_tokens":100,
	 "tools":[{"name":"get_order","description":"Look up an order.","input_schema":{}}],
	 "messages":[{"role":"user","content":"hi"},
	  {"role":"assistant","content":[{"type":"tool_use","id":"tu1","name":"fetch","input":{"url":"x"}}]},
	  {"role":"user","content":[{"type":"tool_result","tool_use_id":"tu1","content":"page text"}]}]}`
	h.post(t, "/v1/messages", req, nil)
	sent := string(h.up.lastReq)
	if strings.Count(sent, "attckus-canary-xyz") != 2 || !strings.Contains(sent, "`delete_order`") || !strings.Contains(sent, `page text\n`) {
		t.Errorf("attacks not applied: %s", sent)
	}
	n := 0
	for _, e := range h.audit(t) {
		if e.Type == audit.AttackInjected {
			n++
		}
	}
	if n != 2 {
		t.Errorf("attack events = %d", n)
	}

	// OpenAI: tool messages are matched to the assistant's tool_calls.
	h2 := newHarness(t, OpenAI, openAIJSON, "application/json", nil)
	h2.proxy.Attacks = inj
	h2.post(t, "/v1/chat/completions", `{"model":"gpt-5","messages":[
	  {"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"fetch","arguments":"{}"}}]},
	  {"role":"tool","tool_call_id":"c1","content":"page"}],
	  "tools":[{"type":"function","function":{"name":"get_order","description":"Look up."}}]}`, nil)
	if strings.Count(string(h2.up.lastReq), "attckus-canary-xyz") != 2 {
		t.Errorf("openai attacks: %s", h2.up.lastReq)
	}
}
