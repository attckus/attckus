package llm

import "encoding/json"

// readUsage folds one response document or stream event into u and model.
// Ported from zoko's passthrough.readUsage. Anthropic counts are cumulative
// per message (later events overwrite); compaction iterations are added
// because they are not in the top-level counts. OpenAI reports cached
// prompt tokens inside prompt_tokens.
func readUsage(provider string, data []byte, u *Usage, model *string) {
	var doc struct {
		Type    string          `json:"type"`
		Model   string          `json:"model"`
		Usage   json.RawMessage `json:"usage"`
		Message *struct {
			Model string          `json:"model"`
			Usage json.RawMessage `json:"usage"`
		} `json:"message"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return
	}
	if provider == Anthropic {
		usage := doc.Usage
		if doc.Type == "message_start" && doc.Message != nil {
			usage = doc.Message.Usage
			if doc.Message.Model != "" {
				*model = doc.Message.Model
			}
		} else if doc.Model != "" {
			*model = doc.Model
		}
		if len(usage) == 0 || string(usage) == "null" {
			return
		}
		var a struct {
			Input      *int64 `json:"input_tokens"`
			Output     *int64 `json:"output_tokens"`
			CacheRead  *int64 `json:"cache_read_input_tokens"`
			CacheWrite *int64 `json:"cache_creation_input_tokens"`
			Iterations []struct {
				Type       string `json:"type"`
				Input      int64  `json:"input_tokens"`
				Output     int64  `json:"output_tokens"`
				CacheRead  int64  `json:"cache_read_input_tokens"`
				CacheWrite int64  `json:"cache_creation_input_tokens"`
			} `json:"iterations"`
		}
		if json.Unmarshal(usage, &a) != nil {
			return
		}
		set := func(dst *int64, v *int64) {
			if v != nil {
				*dst = *v
			}
		}
		set(&u.InputTokens, a.Input)
		set(&u.OutputTokens, a.Output)
		set(&u.CacheReadTokens, a.CacheRead)
		set(&u.CacheWriteTokens, a.CacheWrite)
		for _, it := range a.Iterations {
			if it.Type == "compaction" {
				u.InputTokens += it.Input
				u.OutputTokens += it.Output
				u.CacheReadTokens += it.CacheRead
				u.CacheWriteTokens += it.CacheWrite
			}
		}
		return
	}
	if doc.Model != "" {
		*model = doc.Model
	}
	if len(doc.Usage) == 0 || string(doc.Usage) == "null" {
		return
	}
	var o struct {
		Prompt     int64 `json:"prompt_tokens"`
		Completion int64 `json:"completion_tokens"`
		Details    struct {
			Cached int64 `json:"cached_tokens"`
		} `json:"prompt_tokens_details"`
	}
	if json.Unmarshal(doc.Usage, &o) != nil {
		return
	}
	u.InputTokens = o.Prompt - o.Details.Cached
	u.CacheReadTokens = o.Details.Cached
	u.OutputTokens = o.Completion
}
