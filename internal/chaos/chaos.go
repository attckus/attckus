// Package chaos injects faults into tool calls passing through the gateway.
// Faults only change what the agent sees; they never touch real systems.
// Runs are repeatable: the same seed and call sequence give the same faults.
package chaos

import (
	"fmt"
	"math/rand/v2"
	"path"
	"strings"
	"sync"
	"time"
)

type FaultType string

const (
	Latency   FaultType = "latency"    // delay, then forward
	Error     FaultType = "error"      // isError tool result, not forwarded
	Timeout   FaultType = "timeout"    // delay, then a JSON-RPC timeout error
	Malformed FaultType = "malformed"  // garbage tool content, not forwarded
	RateLimit FaultType = "rate_limit" // LLM gateway: provider 429 with retry-after
)

// Config is the "chaos" section of a policy file.
type Config struct {
	Enabled   bool    `json:"enabled"`
	Seed      uint64  `json:"seed"`
	AllowProd bool    `json:"allow_prod"`
	Faults    []Fault `json:"faults"`
}

type Fault struct {
	Agent       string    `json:"agent,omitempty"`
	Tool        string    `json:"tool,omitempty"`
	Type        FaultType `json:"type"`
	Probability float64   `json:"probability"`
	DelayMs     int       `json:"delay_ms,omitempty"`
	Message     string    `json:"message,omitempty"`
}

func (c *Config) Validate() error {
	for i, f := range c.Faults {
		switch f.Type {
		case Latency, Timeout:
			if f.DelayMs <= 0 {
				return fmt.Errorf("chaos fault %d: %s needs delay_ms > 0", i+1, f.Type)
			}
		case Error, Malformed, RateLimit:
		default:
			return fmt.Errorf("chaos fault %d: unknown type %q", i+1, f.Type)
		}
		if f.Probability < 0 || f.Probability > 1 {
			return fmt.Errorf("chaos fault %d: probability must be in [0, 1]", i+1)
		}
		if f.DelayMs > 120_000 {
			return fmt.Errorf("chaos fault %d: delay_ms above 2 minutes is not allowed", i+1)
		}
	}
	return nil
}

// Injector picks faults for calls. Safe for concurrent use.
type Injector struct {
	cfg Config
	mu  sync.Mutex
	rng *rand.Rand
}

// New returns an injector, or an error when chaos is not allowed in env.
func New(cfg Config, env string) (*Injector, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if isProd(env) && !cfg.AllowProd {
		return nil, fmt.Errorf("chaos is enabled but the gateway env is %q; set chaos.allow_prod to run it there", env)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Injector{cfg: cfg, rng: rand.New(rand.NewPCG(cfg.Seed, cfg.Seed^0x9e3779b97f4a7c15))}, nil
}

// Injected describes the fault applied to one call.
type Injected struct {
	Type    FaultType
	Delay   time.Duration
	Message string
}

// Pick returns the fault for a call, or nil. Each matching fault rolls once
// in order; the first that fires wins.
func (in *Injector) Pick(agent, tool string) *Injected {
	if in == nil {
		return nil
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	for _, f := range in.cfg.Faults {
		if !glob(f.Agent, agent) || !glob(f.Tool, tool) {
			continue
		}
		if in.rng.Float64() >= f.Probability {
			continue
		}
		msg := f.Message
		if msg == "" {
			msg = defaultMessage(f.Type)
		}
		return &Injected{Type: f.Type, Delay: time.Duration(f.DelayMs) * time.Millisecond, Message: msg}
	}
	return nil
}

func defaultMessage(t FaultType) string {
	switch t {
	case Error:
		return "upstream service unavailable (injected by attckus chaos)"
	case Timeout:
		return "request timed out (injected by attckus chaos)"
	case Malformed:
		return "\x00\x7f{\"partial\": tru"
	case RateLimit:
		return "rate limit exceeded (injected by attckus chaos)"
	}
	return ""
}

func glob(p, s string) bool {
	if p == "" || p == "*" {
		return true
	}
	ok, _ := path.Match(p, s)
	return ok
}

func isProd(env string) bool {
	e := strings.ToLower(env)
	return e == "prod" || e == "production" || strings.HasPrefix(e, "prod-")
}
