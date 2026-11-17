package llm

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/mohitkumar/attckus/internal/attack"
	"github.com/mohitkumar/attckus/internal/audit"
	"github.com/mohitkumar/attckus/internal/chaos"
	"github.com/mohitkumar/attckus/internal/policy"
)

// AgentHeader names the calling agent; the proxy's default agent is used
// when it is absent.
const AgentHeader = "X-Attckus-Agent"

const maxBody = 32 << 20

// Upstream is one provider endpoint. When APIKey is empty the caller's own
// credentials are forwarded, so the gateway holds no secrets.
type Upstream struct {
	Provider string // Anthropic or OpenAI
	BaseURL  string // https://api.anthropic.com or https://api.openai.com/v1
	APIKey   string
}

// Proxy is the model API proxy HTTP handler.
//
//	POST /v1/messages          → Anthropic Messages API
//	POST /v1/chat/completions  → OpenAI Chat Completions (and compatible servers)
type Proxy struct {
	Policy    *policy.Policy
	Agent     string
	Audit     *audit.Writer
	Chaos     *chaos.Injector
	Attacks   *attack.Injector // attckus test only
	Prices    *PriceTable
	Upstreams map[string]Upstream
	Client    *http.Client
	Warn      func(string)
	Now       func() time.Time

	mu    sync.Mutex
	spent map[string]float64 // agent -> USD
}

// Spent returns an agent's spend so far.
func (p *Proxy) Spent(agent string) float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.spent[agent]
}

func (p *Proxy) addSpend(agent string, usd float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.spent == nil {
		p.spent = map[string]float64{}
	}
	p.spent[agent] += usd
}

func (p *Proxy) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var provider, upstreamPath string
	switch strings.TrimSuffix(r.URL.Path, "/") {
	case "/v1/messages":
		provider, upstreamPath = Anthropic, "/v1/messages"
	case "/v1/chat/completions", "/chat/completions":
		provider, upstreamPath = OpenAI, "/chat/completions"
	default:
		writeError(w, OpenAI, http.StatusNotFound, "not_found", "attckus llm gateway serves POST /v1/messages and /v1/chat/completions")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, provider, http.StatusMethodNotAllowed, "invalid_request_error", "use POST")
		return
	}
	up, ok := p.Upstreams[provider]
	if !ok {
		writeError(w, provider, http.StatusServiceUnavailable, "api_error", provider+" upstream is not configured on this gateway")
		return
	}
	agent := r.Header.Get(AgentHeader)
	if agent == "" {
		agent = p.Agent
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		writeError(w, provider, http.StatusRequestEntityTooLarge, "request_too_large", "request body too large or unreadable")
		return
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(body, &doc) != nil {
		writeError(w, provider, http.StatusBadRequest, "invalid_request_error", "body is not a JSON object")
		return
	}
	var model string
	_ = json.Unmarshal(doc["model"], &model)
	stream := string(doc["stream"]) == "true"
	ref := provider + "/" + model
	ev := audit.Event{Type: audit.LLMCall, Agent: agent, Server: provider, Model: model}
	dryRun := p.Policy.Mode == policy.DryRun

	refuse := func(status int, kind, decision, msg string) {
		ev.Decision, ev.Status, ev.Detail = decision, status, msg
		p.Audit.Write(ev)
		writeError(w, provider, status, kind, msg)
	}

	// 1. Model allowlist.
	if !p.Policy.ModelAllowed(ref) {
		if !dryRun {
			refuse(http.StatusForbidden, "permission_error", audit.ModelDenied, fmt.Sprintf("model %s is not allowed by attckus policy", ref))
			return
		}
		ev.Detail = "model not allowed (dry-run)"
	}
	// 3. Budget: cap max_tokens so the worst case fits what is left
	// (ported from zoko's passthrough budget handling).
	maxField := "max_tokens"
	if provider == OpenAI && doc["max_completion_tokens"] != nil {
		maxField = "max_completion_tokens"
	}
	if limit := p.Policy.BudgetFor(agent); limit > 0 && !dryRun {
		remaining := limit - p.Spent(agent)
		if remaining <= 0 {
			refuse(http.StatusTooManyRequests, "rate_limit_error", audit.BudgetExceeded, fmt.Sprintf("agent %s has used its $%.2f budget", agent, limit))
			return
		}
		price, priced := p.Prices.Lookup(ref)
		if !priced {
			refuse(http.StatusForbidden, "permission_error", audit.BudgetExceeded, fmt.Sprintf("no price configured for %s, so the agent's budget cannot be enforced (set ATTCKUS_PRICES_FILE)", ref))
			return
		}
		var want int
		_ = json.Unmarshal(doc[maxField], &want)
		if want <= 0 {
			want = 4096
		}
		fit, ok := fitOutputTokens(price, estimateInputTokens(body), want, remaining)
		if !ok {
			refuse(http.StatusTooManyRequests, "rate_limit_error", audit.BudgetExceeded, fmt.Sprintf("agent %s has $%.4f left, not enough for a call to %s", agent, remaining, ref))
			return
		}
		if fit != want || doc[maxField] == nil {
			doc[maxField], _ = json.Marshal(fit)
			ev.Detail = fmt.Sprintf("max tokens lowered to %d to fit budget", fit)
		}
	}
	if provider == OpenAI && stream {
		// Ask for the final usage chunk so the call can be metered (from zoko).
		var so map[string]any
		_ = json.Unmarshal(doc["stream_options"], &so)
		if so == nil {
			so = map[string]any{}
		}
		if _, set := so["include_usage"]; !set {
			so["include_usage"] = true
			doc["stream_options"], _ = json.Marshal(so)
		}
	}
	for _, a := range applyAttacks(provider, doc, p.Attacks) {
		typ, tool, _ := strings.Cut(a, ":")
		p.Audit.Write(audit.Event{Type: audit.AttackInjected, Agent: agent, Server: "llm:" + provider, Tool: tool, Detail: typ})
	}
	body, _ = json.Marshal(doc)

	// 4. Chaos: provider faults, matched on the "provider/model" ref.
	if f := p.Chaos.Pick(agent, ref); f != nil {
		ev.Fault = string(f.Type)
		switch f.Type {
		case chaos.RateLimit:
			w.Header().Set("retry-after", "1")
			refuse(http.StatusTooManyRequests, "rate_limit_error", audit.Faulted, f.Message)
			return
		case chaos.Error:
			status, kind := http.StatusServiceUnavailable, "api_error"
			if provider == Anthropic {
				status, kind = 529, "overloaded_error"
			}
			refuse(status, kind, audit.Faulted, f.Message)
			return
		case chaos.Timeout:
			if !sleep(r, f.Delay) {
				return
			}
			refuse(http.StatusGatewayTimeout, "timeout_error", audit.Faulted, f.Message)
			return
		case chaos.Malformed:
			ev.Decision, ev.Status = audit.Faulted, http.StatusOK
			p.Audit.Write(ev)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, f.Message)
			return
		case chaos.Latency:
			if !sleep(r, f.Delay) {
				return
			}
		}
	}

	// 5. Forward.
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, strings.TrimRight(up.BaseURL, "/")+upstreamPath, bytes.NewReader(body))
	if err != nil {
		writeError(w, provider, http.StatusBadGateway, "api_error", err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")
	for _, h := range []string{"Accept", "anthropic-version", "anthropic-beta", "OpenAI-Beta", "OpenAI-Organization", "OpenAI-Project"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	switch {
	case up.APIKey != "" && provider == Anthropic:
		req.Header.Set("x-api-key", up.APIKey)
	case up.APIKey != "":
		req.Header.Set("Authorization", "Bearer "+up.APIKey)
	default:
		for _, h := range []string{"x-api-key", "Authorization"} {
			if v := r.Header.Get(h); v != "" {
				req.Header.Set(h, v)
			}
		}
	}
	if provider == Anthropic && req.Header.Get("anthropic-version") == "" {
		req.Header.Set("anthropic-version", "2023-06-01")
	}

	start := p.now()
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	}
	res, err := client.Do(req)
	if err != nil {
		refuse(http.StatusBadGateway, "api_error", "upstream_error", "upstream: "+err.Error())
		return
	}
	defer res.Body.Close()
	for _, h := range []string{"Content-Type", "request-id", "x-request-id", "retry-after", "anthropic-ratelimit-requests-remaining",
		"anthropic-ratelimit-tokens-remaining", "x-ratelimit-remaining-requests", "x-ratelimit-remaining-tokens"} {
		if v := res.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}

	var usage Usage
	respModel := model
	decide := p.decider(agent, provider, &ev)
	if res.StatusCode >= 300 {
		w.WriteHeader(res.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(res.Body, 64<<20))
	} else if strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream") {
		w.WriteHeader(res.StatusCode)
		var rw streamRewriter = &openAIStream{decide: decide}
		if provider == Anthropic {
			rw = &anthropicStream{decide: decide}
		}
		pipeSSE(w, res.Body, rw, func(data []byte) { readUsage(provider, data, &usage, &respModel) })
	} else {
		data, err := io.ReadAll(io.LimitReader(res.Body, 64<<20))
		if err != nil {
			return
		}
		readUsage(provider, data, &usage, &respModel)
		if provider == Anthropic {
			data, _ = rewriteAnthropic(data, decide)
		} else {
			data, _ = rewriteOpenAI(data, decide)
		}
		w.Header().Del("Content-Length")
		w.WriteHeader(res.StatusCode)
		_, _ = w.Write(data)
	}

	ev.Status = res.StatusCode
	ev.Model = respModel
	ev.LatencyMs = p.now().Sub(start).Milliseconds()
	if ev.Decision == "" {
		ev.Decision = audit.Forwarded
	}
	if res.StatusCode < 300 {
		ev.InputTokens, ev.OutputTokens = usage.InputTokens, usage.OutputTokens
		ev.CacheTokens = usage.CacheReadTokens + usage.CacheWriteTokens
		if price, ok := p.Prices.Lookup(provider + "/" + respModel); ok {
			ev.CostUSD = price.Cost(usage)
			p.addSpend(agent, ev.CostUSD)
		}
	}
	p.Audit.Write(ev)
}

// decider applies tool policy to each tool call in a response and audits it.
func (p *Proxy) decider(agent, provider string, call *audit.Event) Decider {
	server := "llm:" + provider
	dryRun := p.Policy.Mode == policy.DryRun
	return func(tc ToolCall) Verdict {
		call.ToolCalls++
		d := p.Policy.Decide(agent, server, tc.Name, tc.Args)
		ev := audit.Event{Type: audit.ToolCall, Agent: agent, Server: server, Tool: tc.Name, CallID: tc.ID,
			Args: audit.Redact(tc.Args), ArgsHash: hashArgs(tc.Args), Rule: d.Rule, Decision: audit.Forwarded}
		var v Verdict
		if d.Action != policy.Allow {
			reason := d.Reason
			if reason == "" {
				reason = "not allowed by policy"
			}
			switch {
			case dryRun:
				ev.Decision = audit.WouldDeny
			case d.Action == policy.Approve:
				ev.Decision = audit.PendingApprove
				v = Verdict{Blocked: true, Message: fmt.Sprintf("[attckus] The %s tool call was held for human approval (%s): %s. Do not retry it.", tc.Name, d.Rule, reason)}
			default:
				ev.Decision = audit.Denied
				v = Verdict{Blocked: true, Message: fmt.Sprintf("[attckus] The %s tool call was blocked by policy (%s): %s.", tc.Name, d.Rule, reason)}
			}
		}
		p.Audit.Write(ev)
		return v
	}
}

// pipeSSE copies a server-sent event stream through rw, flushing per event.
func pipeSSE(w http.ResponseWriter, body io.Reader, rw streamRewriter, onData func([]byte)) {
	flusher, _ := w.(http.Flusher)
	emit := func(evs []sseEvent) {
		for _, e := range evs {
			_, _ = w.Write(e.bytes())
		}
		if len(evs) > 0 && flusher != nil {
			flusher.Flush()
		}
	}
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 0, 64*1024), 16<<20)
	var cur sseEvent
	for sc.Scan() {
		line := append([]byte(nil), sc.Bytes()...)
		if len(line) == 0 {
			if len(cur.lines) > 0 {
				emit(rw.push(cur))
				cur = sseEvent{}
			}
			continue
		}
		cur.lines = append(cur.lines, line)
		if data, ok := bytes.CutPrefix(line, []byte("data:")); ok {
			cur.data = bytes.TrimSpace(data)
			onData(cur.data)
		}
	}
	if len(cur.lines) > 0 {
		emit(rw.push(cur))
	}
	emit(rw.flush())
}

func sleep(r *http.Request, d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-r.Context().Done():
		return false
	}
}

// writeError answers in the provider's own error format so SDKs handle it.
func writeError(w http.ResponseWriter, provider string, status int, kind, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	var body any
	if provider == Anthropic {
		body = map[string]any{"type": "error", "error": map[string]string{"type": kind, "message": msg}}
	} else {
		body = map[string]any{"error": map[string]any{"message": msg, "type": kind, "code": kind}}
	}
	_ = json.NewEncoder(w).Encode(body)
}

func hashArgs(args map[string]any) string {
	b, _ := json.Marshal(args)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:6])
}
