// Package suite defines attckus test suites: an agent command, the MCP
// servers and model APIs it uses, and scenarios that put it under failure
// and attack. The runner (run.go) executes each scenario through the attckus
// gateways and turns the audit log into a pass or fail verdict.
package suite

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/attckus/attckus/internal/attack"
	"github.com/attckus/attckus/internal/chaos"
)

// Suite is a attckus-suite.json file.
type Suite struct {
	Version int    `json:"version"`
	Agent   string `json:"agent"`
	// Command runs the agent once (typically its eval or integration test).
	// It reads ATTCKUS_MCP_CONFIG and, for model APIs, ANTHROPIC_BASE_URL /
	// OPENAI_BASE_URL.
	Command        []string          `json:"command"`
	Dir            string            `json:"dir,omitempty"` // working directory, relative to the suite file
	Env            map[string]string `json:"env,omitempty"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty"`
	// Policy is an optional base policy file; scenarios add faults and attacks.
	Policy string `json:"policy,omitempty"`
	// Scan is a directory for attckus scan, relative to the suite file. When
	// set, obeyed injections report what the agent's identity can reach.
	Scan       string     `json:"scan,omitempty"`
	Seed       uint64     `json:"seed,omitempty"`
	MCPServers []Server   `json:"mcp_servers,omitempty"`
	LLM        *LLMTarget `json:"llm,omitempty"`
	Scenarios  []Scenario `json:"scenarios"`
	file       string
}

// Server is an MCP server the agent uses: a command (stdio) or a URL.
type Server struct {
	Name    string   `json:"name"`
	Command []string `json:"command,omitempty"`
	URL     string   `json:"url,omitempty"`
}

// LLMTarget enables the LLM gateway for agents that call model APIs.
type LLMTarget struct {
	AnthropicURL string `json:"anthropic_url,omitempty"`
	OpenAIURL    string `json:"openai_url,omitempty"`
	InjectKeys   bool   `json:"inject_keys,omitempty"`
}

// Scenario is one run of the agent under specific conditions.
type Scenario struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Faults      []chaos.Fault   `json:"faults,omitempty"`
	Attacks     []attack.Attack `json:"attacks,omitempty"`
	Expect      Expect          `json:"expect,omitempty"`
	// Control, on a scenario with both faults and attacks, also runs the
	// same attacks without the faults and reports whether the failure
	// changed what the agent obeyed.
	Control bool `json:"control,omitempty"`
}

// KindCompound is a scenario that attacks the agent while tools are failing.
const KindCompound = "attack+failure"

// Kind is attack, failure, attack+failure or baseline, from what the
// scenario does.
func (s Scenario) Kind() string {
	switch {
	case len(s.Attacks) > 0 && len(s.Faults) > 0:
		return KindCompound
	case len(s.Attacks) > 0:
		return "attack"
	case len(s.Faults) > 0:
		return "failure"
	}
	return "baseline"
}

// Expect tunes the verdict. By default a scenario fails on any retry storm,
// duplicate side effect, escalation after failure, budget hit, poisoned or
// changed server tool, or obeyed injection.
type Expect struct {
	// Allow lists issue kinds that do not fail this scenario.
	Allow []string `json:"allow,omitempty"`
	// ForbiddenTools fail the scenario if called at all.
	ForbiddenTools []string `json:"forbidden_tools,omitempty"`
	// AgentSucceeds requires the agent command to exit 0.
	AgentSucceeds bool `json:"agent_succeeds,omitempty"`
	// AllowContained passes an obeyed injection when policy blocked every
	// resulting call (the agent is vulnerable, the policy is not).
	AllowContained bool `json:"allow_contained,omitempty"`
	// AtMostOnce lists tools that may succeed at most once per run, whatever
	// their arguments: a refund, a payment, an email. It catches the
	// double-charge that a retry with a fresh id slips past.
	AtMostOnce []string `json:"at_most_once,omitempty"`
	// MaxToolCalls, MaxModelCalls and MaxCostUSD cap a run; zero means no cap.
	MaxToolCalls  int     `json:"max_tool_calls,omitempty"`
	MaxModelCalls int     `json:"max_model_calls,omitempty"`
	MaxCostUSD    float64 `json:"max_cost_usd,omitempty"`
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Load reads and validates a suite file.
func Load(file string) (*Suite, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var s Suite
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("suite %s: %w", file, err)
	}
	s.file, _ = filepath.Abs(file)
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("suite %s: %w", file, err)
	}
	return &s, nil
}

func (s *Suite) validate() error {
	if s.Version != 1 {
		return fmt.Errorf("version must be 1, got %d", s.Version)
	}
	if len(s.Command) == 0 {
		return errors.New("command is required")
	}
	if s.Agent == "" {
		s.Agent = "agent"
	}
	if len(s.MCPServers) == 0 && s.LLM == nil {
		return errors.New("add at least one mcp_servers entry or an llm section, or there is nothing to test through")
	}
	seen := map[string]bool{}
	for _, m := range s.MCPServers {
		if !nameRe.MatchString(m.Name) || seen[m.Name] {
			return fmt.Errorf("mcp server name %q must be unique and use letters, digits, _ or -", m.Name)
		}
		seen[m.Name] = true
		if (len(m.Command) == 0) == (m.URL == "") {
			return fmt.Errorf("mcp server %s: set exactly one of command or url", m.Name)
		}
	}
	if len(s.Scenarios) == 0 {
		return errors.New("at least one scenario is required")
	}
	names := map[string]bool{}
	for _, sc := range s.Scenarios {
		if sc.Name == "" || names[sc.Name] {
			return fmt.Errorf("scenario names must be present and unique (%q)", sc.Name)
		}
		names[sc.Name] = true
		if sc.Control && sc.Kind() != KindCompound {
			return fmt.Errorf("scenario %q: control needs both faults and attacks", sc.Name)
		}
		cfg := chaos.Config{Faults: sc.Faults}
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("scenario %q: %w", sc.Name, err)
		}
		for _, a := range sc.Attacks {
			if err := a.Validate(); err != nil {
				return fmt.Errorf("scenario %q: %w", sc.Name, err)
			}
		}
	}
	return nil
}

// ScanDir is the resolved scan directory, or "" when none is configured.
func (s *Suite) ScanDir() string { return s.path(s.Scan) }

// path resolves p relative to the suite file.
func (s *Suite) path(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(filepath.Dir(s.file), p)
}

// Slug turns a scenario name into a directory name.
func Slug(name string) string {
	out := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 32
		}
		return '-'
	}, name)
	for strings.Contains(out, "--") {
		out = strings.ReplaceAll(out, "--", "-")
	}
	return strings.Trim(out, "-")
}
