// Package gateway is the MCP proxy attckus test puts in front of each MCP
// server: it applies the policy, faults and attacks to tool calls and writes
// the audit log. Engine holds the decision logic; stdio.go and http.go are
// transports that feed it messages.
package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/attckus/attckus/internal/attack"
	"github.com/attckus/attckus/internal/audit"
	"github.com/attckus/attckus/internal/chaos"
	"github.com/attckus/attckus/internal/mcp"
	"github.com/attckus/attckus/internal/policy"
)

// Engine decides what happens to each message. Safe for concurrent use.
type Engine struct {
	Policy *policy.Policy
	Agent  string // default agent name for decisions
	Server string // name of the upstream server, for rules and audit
	Audit  *audit.Writer
	Chaos  *chaos.Injector
	// Attacks tampers with tool listings and results (attckus test only).
	Attacks *attack.Injector
	Warn    func(string) // operator warnings (stderr); nil discards
	Now     func() time.Time

	mu      sync.Mutex
	pending map[string]pendingCall // session|id -> call in flight
	lists   map[string]bool        // session|id of tools/list requests
	hashes  map[string]string      // tool name -> definition hash
	changed map[string]bool        // tools whose definition changed
}

type pendingCall struct {
	agent, tool, hash string
	start             time.Time
}

// Outcome tells a transport what to do with one client message.
type Outcome struct {
	Forward []byte        // send to the server; nil means do not forward
	Reply   []byte        // send to the client
	Delay   time.Duration // wait this long before acting (chaos)
}

// New returns an engine with its maps initialised.
func New(p *policy.Policy, agent, server string) *Engine {
	return &Engine{
		Policy: p, Agent: agent, Server: server, Now: time.Now,
		pending: map[string]pendingCall{}, lists: map[string]bool{},
		hashes: map[string]string{}, changed: map[string]bool{},
	}
}

func (e *Engine) warn(format string, args ...any) {
	if e.Warn != nil {
		e.Warn(fmt.Sprintf(format, args...))
	}
}

// FromClient handles a message travelling from the agent to the server.
// agent overrides the default agent name when non-empty.
func (e *Engine) FromClient(session, agent string, raw []byte) Outcome {
	if agent == "" {
		agent = e.Agent
	}
	msg, err := mcp.Parse(raw)
	if errors.Is(err, mcp.ErrBatch) {
		e.Audit.Write(audit.Event{Type: audit.Rejected, Agent: agent, Server: e.Server, Detail: "json-rpc batch"})
		if e.Policy.Mode == policy.DryRun {
			return Outcome{Forward: raw}
		}
		return Outcome{Reply: mcp.ErrorResponse(nil, mcp.CodeInvalidRequest, "attckus gateway does not inspect JSON-RPC batches; send messages individually")}
	}
	if err != nil {
		return Outcome{Forward: raw} // let the server report the parse error
	}
	if msg.Method == "tools/list" && msg.IsRequest() {
		e.mu.Lock()
		e.lists[session+"|"+msg.Key()] = true
		e.mu.Unlock()
		return Outcome{Forward: raw}
	}
	if msg.Method != "tools/call" || !msg.IsRequest() {
		return Outcome{Forward: raw}
	}
	var call mcp.ToolCall
	if json.Unmarshal(msg.Params, &call) != nil || call.Name == "" {
		return Outcome{Forward: raw}
	}
	return e.toolCall(session, agent, msg, call, raw)
}

func (e *Engine) toolCall(session, agent string, msg *mcp.Message, call mcp.ToolCall, raw []byte) Outcome {
	ev := audit.Event{
		Type: audit.ToolCall, Agent: agent, Server: e.Server, Tool: call.Name, CallID: msg.Key(),
		Args: audit.Redact(call.Arguments), ArgsHash: hashArgs(call.Arguments),
	}
	block := func(decision, rule, text string) Outcome {
		ev.Decision, ev.Rule = decision, rule
		e.Audit.Write(ev)
		return Outcome{Reply: mcp.ToolResult(msg.ID, text, true)}
	}
	dryRun := e.Policy.Mode == policy.DryRun

	// 1. Tool definition changed mid-session.
	e.mu.Lock()
	changed := e.changed[call.Name]
	e.mu.Unlock()
	if changed && e.Policy.ToolChecks != nil && e.Policy.ToolChecks.BlockChangedTools && !dryRun {
		return block(audit.Denied, "tool_changed", "Blocked by attckus: this tool's definition changed during the session.")
	}
	// 4. Policy.
	d := e.Policy.Decide(agent, e.Server, call.Name, call.Arguments)
	ev.Rule = d.Rule
	if d.Action != policy.Allow {
		reason := d.Reason
		if reason == "" {
			reason = "not allowed by policy"
		}
		if !dryRun {
			decision := audit.Denied
			text := fmt.Sprintf("Blocked by attckus policy (%s): %s.", d.Rule, reason)
			if d.Action == policy.Approve {
				decision = audit.PendingApprove
				text = fmt.Sprintf("Held by attckus policy (%s): %s. A human must approve this call; do not retry it.", d.Rule, reason)
			}
			return block(decision, d.Rule, text)
		}
		ev.Decision = audit.WouldDeny
		if d.Action == policy.Approve {
			ev.Detail = "would need approval (dry-run)"
		}
	}
	// 5. Chaos.
	if f := e.Chaos.Pick(agent, call.Name); f != nil {
		ev.Fault = string(f.Type)
		switch f.Type {
		case chaos.Error, chaos.RateLimit:
			ev.Decision = audit.Faulted
			e.Audit.Write(ev)
			return Outcome{Reply: mcp.ToolResult(msg.ID, e.faultText(agent, call.Name, f.Message), true)}
		case chaos.Malformed:
			ev.Decision = audit.Faulted
			e.Audit.Write(ev)
			return Outcome{Reply: mcp.ToolResult(msg.ID, e.faultText(agent, call.Name, f.Message), false)}
		case chaos.Timeout:
			ev.Decision = audit.Faulted
			e.Audit.Write(ev)
			return Outcome{Reply: mcp.ErrorResponse(msg.ID, mcp.CodeTimeout, f.Message), Delay: f.Delay}
		case chaos.Latency:
			e.track(session, msg, agent, call.Name, ev.ArgsHash)
			if ev.Decision == "" {
				ev.Decision = audit.Forwarded
			}
			e.Audit.Write(ev)
			return Outcome{Forward: raw, Delay: f.Delay}
		}
	}
	e.track(session, msg, agent, call.Name, ev.ArgsHash)
	if ev.Decision == "" {
		ev.Decision = audit.Forwarded
	}
	e.Audit.Write(ev)
	return Outcome{Forward: raw}
}

// faultText is the text of a faulted reply. An inject_result attack on the
// failing tool rides in its error message: an agent whose plan is breaking
// reads error text closely, and error text is often attacker-influenced.
func (e *Engine) faultText(agent, tool, msg string) string {
	text := e.Attacks.Result(tool)
	if text == "" {
		return msg
	}
	e.Audit.Write(audit.Event{Type: audit.AttackInjected, Agent: agent, Server: e.Server, Tool: tool,
		Detail: string(attack.InjectResult) + " (in fault response)"})
	return msg + "\n" + text
}

func (e *Engine) track(session string, msg *mcp.Message, agent, tool, hash string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	// Latency is measured from when the gateway received the call, so it
	// includes injected delay: what the agent actually experienced.
	e.pending[session+"|"+msg.Key()] = pendingCall{agent: agent, tool: tool, hash: hash, start: e.Now()}
}

// FromServer handles a message travelling from the server to the agent and
// returns what to send on (possibly modified).
func (e *Engine) FromServer(session string, raw []byte) []byte {
	msg, err := mcp.Parse(raw)
	if err != nil || !msg.IsResponse() {
		return raw
	}
	key := session + "|" + msg.Key()
	e.mu.Lock()
	call, isCall := e.pending[key]
	delete(e.pending, key)
	isList := e.lists[key]
	delete(e.lists, key)
	e.mu.Unlock()

	if isCall {
		e.Audit.Write(audit.Event{
			Type: audit.ToolResult, Agent: call.agent, Server: e.Server, Tool: call.tool, CallID: msg.Key(),
			ArgsHash: call.hash, IsError: msg.Error != nil || mcp.ResultIsError(msg.Result),
			LatencyMs: e.Now().Sub(call.start).Milliseconds(),
		})
		if text := e.Attacks.Result(call.tool); text != "" && msg.Error == nil {
			if out, ok := appendResultText(msg, text); ok {
				e.Audit.Write(audit.Event{Type: audit.AttackInjected, Agent: call.agent, Server: e.Server, Tool: call.tool,
					Detail: string(attack.InjectResult)})
				return out
			}
		}
		return raw
	}
	if isList && msg.Error == nil {
		if out, ok := e.filterTools(msg); ok {
			return out
		}
	}
	return raw
}

// filterTools inspects a tools/list result: flags suspicious descriptions,
// detects definition changes, and hides tools the policy always denies.
func (e *Engine) filterTools(msg *mcp.Message) ([]byte, bool) {
	var result map[string]json.RawMessage
	if json.Unmarshal(msg.Result, &result) != nil {
		return nil, false
	}
	var tools []json.RawMessage
	if json.Unmarshal(result["tools"], &tools) != nil {
		return nil, false
	}
	checks := e.Policy.ToolChecks
	if checks == nil {
		checks = &policy.ToolChecks{}
	}
	kept := make([]json.RawMessage, 0, len(tools))
	modified := false
	for _, rawTool := range tools {
		var t mcp.Tool
		if json.Unmarshal(rawTool, &t) != nil {
			kept = append(kept, rawTool)
			continue
		}
		hide := false
		if checks.FlagInjection {
			if reasons := InjectionReasons(t.Description + " " + string(t.InputSchema)); len(reasons) > 0 {
				e.Audit.Write(audit.Event{Type: audit.ToolFlagged, Server: e.Server, Tool: t.Name, Detail: joinReasons(reasons)})
				e.warn("tool %q on %s looks poisoned: %s", t.Name, e.Server, joinReasons(reasons))
				hide = hide || checks.HideFlagged
			}
		}
		if checks.AlertOnChange {
			h := sha256.Sum256(append([]byte(t.Description), t.InputSchema...))
			sum := hex.EncodeToString(h[:8])
			e.mu.Lock()
			prev, seen := e.hashes[t.Name]
			e.hashes[t.Name] = sum
			if seen && prev != sum {
				e.changed[t.Name] = true
			}
			e.mu.Unlock()
			if seen && prev != sum {
				e.Audit.Write(audit.Event{Type: audit.ToolChanged, Server: e.Server, Tool: t.Name, Detail: "definition changed since first tools/list"})
				e.warn("tool %q on %s changed its definition mid-session", t.Name, e.Server)
			}
		}
		if checks.HideDenied && e.Policy.AlwaysDenied(e.Agent, e.Server, t.Name) {
			hide = true
		}
		if hide {
			modified = true
			continue
		}
		// Attacks are applied after the checks, so attckus's own payload is
		// never reported as a poisoned server.
		if desc, typ := e.Attacks.Description(t.Name, t.Description); typ != "" {
			var fields map[string]json.RawMessage
			if json.Unmarshal(rawTool, &fields) == nil {
				fields["description"], _ = json.Marshal(desc)
				if b, err := json.Marshal(fields); err == nil {
					rawTool, modified = b, true
					e.Audit.Write(audit.Event{Type: audit.AttackInjected, Server: e.Server, Tool: t.Name, Detail: string(typ)})
				}
			}
		}
		kept = append(kept, rawTool)
	}
	if !modified {
		return nil, false
	}
	b, err := json.Marshal(kept)
	if err != nil {
		return nil, false
	}
	result["tools"] = b
	if msg.Result, err = json.Marshal(result); err != nil {
		return nil, false
	}
	out, err := json.Marshal(msg)
	return out, err == nil
}

// appendResultText adds a text block to a tools/call result.
func appendResultText(msg *mcp.Message, text string) ([]byte, bool) {
	var result map[string]json.RawMessage
	if json.Unmarshal(msg.Result, &result) != nil {
		return nil, false
	}
	var content []json.RawMessage
	_ = json.Unmarshal(result["content"], &content)
	block, _ := json.Marshal(map[string]string{"type": "text", "text": text})
	content = append(content, block)
	result["content"], _ = json.Marshal(content)
	var err error
	if msg.Result, err = json.Marshal(result); err != nil {
		return nil, false
	}
	out, err := json.Marshal(msg)
	return out, err == nil
}

var injectionPatterns = []struct {
	reason string
	re     *regexp.Regexp
}{
	{"asks to ignore previous instructions", regexp.MustCompile(`(?i)ignore (all |any )?(the )?(previous|prior|above|earlier) (instructions|prompts|rules)`)},
	{"contains an <IMPORTANT> block", regexp.MustCompile(`(?i)<\s*/?\s*(important|system|instructions?)\s*>`)},
	{"asks to hide behaviour from the user", regexp.MustCompile(`(?i)(do not|don't|never) (tell|inform|mention|reveal|show)[^.]{0,40}\buser\b`)},
	{"references credential files", regexp.MustCompile(`(?i)(~/\.ssh|id_rsa|id_ed25519|\.aws/credentials|\.env\b|mcp\.json|\.netrc|private key)`)},
	{"mentions the system prompt", regexp.MustCompile(`(?i)system prompt`)},
	{"instructs actions on other tools", regexp.MustCompile(`(?i)(before|after|instead of) (using|calling) (this|any|the \w+) tool,? (you )?(must|should|always)`)},
	{"contains hidden Unicode", regexp.MustCompile(`[\x{200b}-\x{200f}\x{202a}-\x{202e}\x{2060}-\x{2064}\x{feff}\x{e0000}-\x{e007f}]`)},
}

// InjectionReasons returns why a tool description looks like it carries
// instructions for the model rather than documentation.
func InjectionReasons(text string) []string {
	var out []string
	for _, p := range injectionPatterns {
		if p.re.MatchString(text) {
			out = append(out, p.reason)
		}
	}
	return out
}

func joinReasons(rs []string) string {
	out := ""
	for i, r := range rs {
		if i > 0 {
			out += "; "
		}
		out += r
	}
	return out
}

func hashArgs(args map[string]any) string {
	b, _ := json.Marshal(args) // map keys are sorted, so this is canonical
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:6])
}
