// Package llm is the model API proxy attckus test puts between an agent and
// the Anthropic Messages or OpenAI Chat Completions APIs. It meters usage,
// enforces per-agent budgets, applies tool policy to the tool calls models
// return, injects attacks into tools and tool results, and injects provider
// faults.
//
// Pricing, usage parsing and budget fitting are ported from the zoko model
// gateway (internal/gateway/pricing.go and passthrough.go), rewritten on the
// standard library.
package llm

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Price is USD per million tokens.
type Price struct {
	Input      float64 `json:"input"`
	Output     float64 `json:"output"`
	CacheRead  float64 `json:"cache_read"`
	CacheWrite float64 `json:"cache_write"`
}

// Usage is token usage for one call.
type Usage struct {
	InputTokens      int64 `json:"input_tokens"` // uncached input
	OutputTokens     int64 `json:"output_tokens"`
	CacheReadTokens  int64 `json:"cache_read_tokens"`
	CacheWriteTokens int64 `json:"cache_write_tokens"`
}

// defaultPrices are Anthropic first-party list prices (USD/MTok) as of
// 2026-10, from zoko. Cache writes are the 5-minute TTL rate. Extend or
// override with ATTCKUS_PRICES_FILE. Models without a price are metered in
// tokens only, and a budget cannot be enforced for them.
var defaultPrices = map[string]Price{
	"anthropic/claude-fable-5-1":  {Input: 10, Output: 50, CacheRead: 0.25, CacheWrite: 12.5},
	"anthropic/claude-fable-5":    {Input: 10, Output: 50, CacheRead: 1.00, CacheWrite: 12.5},
	"anthropic/claude-opus-5-5":   {Input: 4, Output: 20, CacheRead: 0.20, CacheWrite: 5},
	"anthropic/claude-opus-5":     {Input: 5, Output: 25, CacheRead: 0.50, CacheWrite: 6.25},
	"anthropic/claude-opus-4-8":   {Input: 5, Output: 25, CacheRead: 0.50, CacheWrite: 6.25},
	"anthropic/claude-opus-4-7":   {Input: 5, Output: 25, CacheRead: 0.50, CacheWrite: 6.25},
	"anthropic/claude-opus-4-6":   {Input: 5, Output: 25, CacheRead: 0.50, CacheWrite: 6.25},
	"anthropic/claude-sonnet-5-5": {Input: 2, Output: 10, CacheRead: 0.20, CacheWrite: 2.5},
	"anthropic/claude-sonnet-5":   {Input: 2, Output: 10, CacheRead: 0.20, CacheWrite: 2.5},
	"anthropic/claude-sonnet-4-6": {Input: 3, Output: 15, CacheRead: 0.30, CacheWrite: 3.75},
	"anthropic/claude-haiku-5-5":  {Input: 0.10, Output: 0.50, CacheRead: 0.01, CacheWrite: 0.125},
	"anthropic/claude-haiku-4-5":  {Input: 1, Output: 5, CacheRead: 0.10, CacheWrite: 1.25},
}

// freeProviders run locally; their calls cost nothing.
var freeProviders = map[string]bool{"ollama": true, "local": true}

// PriceTable maps "provider/model" to a price.
type PriceTable struct{ prices map[string]Price }

// LoadPrices returns the defaults merged with ATTCKUS_PRICES_FILE, a JSON
// object of {"provider/model": {"input": …, "output": …, …}}.
func LoadPrices() (*PriceTable, error) {
	t := &PriceTable{prices: map[string]Price{}}
	for k, v := range defaultPrices {
		t.prices[k] = v
	}
	if path := os.Getenv("ATTCKUS_PRICES_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read prices file: %w", err)
		}
		var extra map[string]Price
		if err := json.Unmarshal(b, &extra); err != nil {
			return nil, fmt.Errorf("parse prices file: %w", err)
		}
		for k, v := range extra {
			t.prices[k] = v
		}
	}
	return t, nil
}

func (t *PriceTable) Set(ref string, p Price) { t.prices[ref] = p }

// Lookup returns the price for a "provider/model" ref.
func (t *PriceTable) Lookup(ref string) (Price, bool) {
	if p, ok := t.prices[ref]; ok {
		return p, true
	}
	if provider, _, ok := strings.Cut(ref, "/"); ok && freeProviders[provider] {
		return Price{}, true
	}
	return Price{}, false
}

// Cost prices a usage record.
func (p Price) Cost(u Usage) float64 {
	return (float64(u.InputTokens)*p.Input +
		float64(u.OutputTokens)*p.Output +
		float64(u.CacheReadTokens)*p.CacheRead +
		float64(u.CacheWriteTokens)*p.CacheWrite) / 1e6
}

// minOutputTokens is the smallest response budget worth calling a model for.
const minOutputTokens = 256

// fitOutputTokens returns the largest max_tokens (≤ want) whose worst-case
// cost, with the estimated input at the uncached rate, fits within budget.
func fitOutputTokens(p Price, inputTokens int64, want int, budget float64) (int, bool) {
	remaining := budget - float64(inputTokens)*p.Input/1e6
	if remaining <= 0 {
		return 0, false
	}
	if p.Output <= 0 {
		return want, true
	}
	fit := int(remaining * 1e6 / p.Output)
	if fit < minOutputTokens {
		return 0, false
	}
	return min(fit, want), true
}

// estimateInputTokens over-estimates prompt size without a tokenizer:
// about 3 bytes per token is conservative for English and JSON.
func estimateInputTokens(body []byte) int64 { return int64(len(body)/3) + 64 }
