// Package policy defines what agents may do during a test. Rules are
// evaluated in order and the first match wins; unmatched calls get the
// default action.
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/attckus/attckus/internal/chaos"
)

type Action string

const (
	Allow   Action = "allow"
	Deny    Action = "deny"
	Approve Action = "approve" // blocked until a human approves (approvals are phase 2)
)

type Mode string

const (
	Enforce Mode = "enforce"
	DryRun  Mode = "dry-run"
)

// Policy is the permission boundary attckus test runs the agent inside: which
// tools it may call, with which arguments, and which need approval.
type Policy struct {
	Version    int           `json:"version"`
	Mode       Mode          `json:"mode"`
	Default    Action        `json:"default"`
	Rules      []Rule        `json:"rules"`
	ToolChecks *ToolChecks   `json:"tool_checks,omitempty"`
	Chaos      *chaos.Config `json:"chaos,omitempty"`
	LLM        *LLMPolicy    `json:"llm,omitempty"`
}

// LLMPolicy applies to model API calls during a test. Tool rules above also
// apply to the tool calls models return.
type LLMPolicy struct {
	// Models, if set, is an allowlist of "provider/model" globs.
	Models []string `json:"models,omitempty"`
	// Budgets cap spend per agent (first matching glob wins) for one scenario.
	Budgets []Budget `json:"budgets,omitempty"`
}

type Budget struct {
	Agent string  `json:"agent,omitempty"`
	USD   float64 `json:"usd"`
}

// ToolChecks controls tools/list inspection.
type ToolChecks struct {
	HideDenied        bool `json:"hide_denied"`         // remove tools a rule always denies
	FlagInjection     bool `json:"flag_injection"`      // flag instruction-like descriptions
	HideFlagged       bool `json:"hide_flagged"`        // and remove them
	AlertOnChange     bool `json:"alert_on_change"`     // tool definition changed mid-session
	BlockChangedTools bool `json:"block_changed_tools"` // deny calls to changed tools
}

// Rule matches calls by agent, server, tool (globs) and arguments.
type Rule struct {
	Name   string             `json:"name"`
	Agent  string             `json:"agent,omitempty"`
	Server string             `json:"server,omitempty"`
	Tool   string             `json:"tool,omitempty"`
	Args   map[string]Matcher `json:"args,omitempty"`
	Action Action             `json:"action"`
	Reason string             `json:"reason,omitempty"`
}

// Matcher tests one argument, rendered as a string (JSON for non-strings).
type Matcher struct {
	Equals    *string `json:"equals,omitempty"`
	Prefix    *string `json:"prefix,omitempty"`
	Match     string  `json:"match,omitempty"`
	NotMatch  string  `json:"not_match,omitempty"`
	re, notRe *regexp.Regexp
}

// Decision is the outcome for one call.
type Decision struct {
	Action Action
	Rule   string
	Reason string
}

// Load reads and validates a policy file.
func Load(file string) (*Policy, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse decodes and validates a policy. Invalid policies are rejected so the
// gateway never starts with a policy it cannot enforce.
func Parse(data []byte) (*Policy, error) {
	var p Policy
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return &p, nil
}

func (p *Policy) validate() error {
	if p.Version != 1 {
		return fmt.Errorf("version must be 1, got %d", p.Version)
	}
	switch p.Mode {
	case "":
		p.Mode = Enforce
	case Enforce, DryRun:
	default:
		return fmt.Errorf("mode must be enforce or dry-run, got %q", p.Mode)
	}
	if p.Default == "" {
		p.Default = Allow
	}
	if !validAction(p.Default) {
		return fmt.Errorf("default must be allow, deny or approve, got %q", p.Default)
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Name == "" {
			r.Name = fmt.Sprintf("rule %d", i+1)
		}
		if !validAction(r.Action) {
			return fmt.Errorf("%s: action must be allow, deny or approve, got %q", r.Name, r.Action)
		}
		for _, g := range []string{r.Agent, r.Server, r.Tool} {
			if _, err := path.Match(g, ""); err != nil {
				return fmt.Errorf("%s: bad glob %q", r.Name, g)
			}
		}
		for k, m := range r.Args {
			var err error
			if m.Match != "" {
				if m.re, err = regexp.Compile(m.Match); err != nil {
					return fmt.Errorf("%s: args.%s.match: %w", r.Name, k, err)
				}
			}
			if m.NotMatch != "" {
				if m.notRe, err = regexp.Compile(m.NotMatch); err != nil {
					return fmt.Errorf("%s: args.%s.not_match: %w", r.Name, k, err)
				}
			}
			r.Args[k] = m
		}
	}
	if p.Chaos != nil {
		if err := p.Chaos.Validate(); err != nil {
			return err
		}
	}
	if p.LLM != nil {
		for _, m := range p.LLM.Models {
			if _, err := path.Match(m, ""); err != nil {
				return fmt.Errorf("llm.models: bad glob %q", m)
			}
		}
		for _, b := range p.LLM.Budgets {
			if b.USD <= 0 {
				return errors.New("llm.budgets: usd must be positive")
			}
		}
	}
	return nil
}

// ModelAllowed reports whether a "provider/model" ref passes the allowlist.
func (p *Policy) ModelAllowed(ref string) bool {
	if p.LLM == nil || len(p.LLM.Models) == 0 {
		return true
	}
	for _, m := range p.LLM.Models {
		if ok, _ := path.Match(m, ref); ok {
			return true
		}
	}
	return false
}

// BudgetFor returns the agent's spend cap in USD, or 0 for none.
func (p *Policy) BudgetFor(agent string) float64 {
	if p.LLM == nil {
		return 0
	}
	for _, b := range p.LLM.Budgets {
		if glob(b.Agent, agent) {
			return b.USD
		}
	}
	return 0
}

func validAction(a Action) bool { return a == Allow || a == Deny || a == Approve }

// Decide returns the action for a call.
func (p *Policy) Decide(agent, server, tool string, args map[string]any) Decision {
	for _, r := range p.Rules {
		if r.matches(agent, server, tool, args) {
			return Decision{Action: r.Action, Rule: r.Name, Reason: r.Reason}
		}
	}
	return Decision{Action: p.Default, Rule: "default"}
}

// AlwaysDenied reports whether a tool is denied whatever its arguments:
// the first rule that could match it is an argument-free deny.
func (p *Policy) AlwaysDenied(agent, server, tool string) bool {
	for _, r := range p.Rules {
		if !glob(r.Agent, agent) || !glob(r.Server, server) || !glob(r.Tool, tool) {
			continue
		}
		return len(r.Args) == 0 && r.Action == Deny
	}
	return p.Default == Deny
}

func (r Rule) matches(agent, server, tool string, args map[string]any) bool {
	if !glob(r.Agent, agent) || !glob(r.Server, server) || !glob(r.Tool, tool) {
		return false
	}
	for k, m := range r.Args {
		v, present := args[k]
		if !m.test(v, present) {
			return false
		}
	}
	return true
}

func (m Matcher) test(v any, present bool) bool {
	s := render(v)
	if m.Equals != nil && (!present || s != *m.Equals) {
		return false
	}
	if m.Prefix != nil && (!present || !strings.HasPrefix(s, *m.Prefix)) {
		return false
	}
	if m.re != nil && (!present || !m.re.MatchString(s)) {
		return false
	}
	if m.notRe != nil && present && m.notRe.MatchString(s) {
		return false
	}
	return true
}

func render(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if v == nil {
		return ""
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func glob(pattern, s string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	ok, _ := path.Match(pattern, s)
	return ok
}

// Default returns a starting boundary: destructive and execution tools are
// denied, SQL is read-only, outbound sends need approval, everything else is
// allowed. It enforces, so a test shows whether the boundary held.
func Default() *Policy {
	return &Policy{
		Version: 1,
		Mode:    Enforce,
		Default: Allow,
		Rules: []Rule{
			{Name: "no command execution", Tool: "*exec*", Action: Deny, Reason: "agents may not run arbitrary commands"},
			{Name: "no shell", Tool: "*shell*", Action: Deny, Reason: "agents may not run arbitrary commands"},
			{Name: "no deletes", Tool: "delete*", Action: Deny, Reason: "destructive tools are denied by default"},
			{Name: "no drops", Tool: "drop*", Action: Deny, Reason: "destructive tools are denied by default"},
			{Name: "no removes", Tool: "remove*", Action: Deny, Reason: "destructive tools are denied by default"},
			{Name: "read-only SQL", Tool: "*query*", Args: map[string]Matcher{
				"sql": {NotMatch: `(?i)\b(drop|delete|truncate|update|insert|alter|grant)\b`},
			}, Action: Allow},
			{Name: "block SQL writes", Tool: "*query*", Action: Deny, Reason: "only read-only SQL is allowed"},
			{Name: "approve outbound messages", Tool: "send*", Action: Approve, Reason: "outbound messages need a human"},
			{Name: "approve slack posts", Tool: "*post_message*", Action: Approve, Reason: "outbound messages need a human"},
			{Name: "approve merges", Tool: "merge*", Action: Approve, Reason: "merges need a human"},
		},
		ToolChecks: &ToolChecks{HideDenied: true, FlagInjection: true, AlertOnChange: true},
	}
}
