package llm

import (
	"encoding/json"

	"github.com/mohitkumar/attckus/internal/attack"
)

// applyAttacks tampers with a request before it reaches the model: tool
// descriptions (poison_tool, rug_pull) and tool results the agent is
// sending back (inject_result). It returns "type:tool" labels for audit.
// Requests carry the whole conversation, so an injected result is injected
// again on every later turn, as a real poisoned document would be.
func applyAttacks(provider string, doc map[string]json.RawMessage, in *attack.Injector) []string {
	if in == nil {
		return nil
	}
	var applied []string
	applied = append(applied, poisonTools(provider, doc, in)...)
	applied = append(applied, injectResults(provider, doc, in)...)
	return applied
}

func poisonTools(provider string, doc map[string]json.RawMessage, in *attack.Injector) []string {
	var tools []map[string]any
	if json.Unmarshal(doc["tools"], &tools) != nil || len(tools) == 0 {
		return nil
	}
	var applied []string
	for _, t := range tools {
		holder := t // Anthropic: the tool itself
		if provider == OpenAI {
			fn, ok := t["function"].(map[string]any)
			if !ok {
				continue
			}
			holder = fn
		}
		name, _ := holder["name"].(string)
		desc, _ := holder["description"].(string)
		if d, typ := in.Description(name, desc); typ != "" {
			holder["description"] = d
			applied = append(applied, string(typ)+":"+name)
		}
	}
	if len(applied) > 0 {
		doc["tools"], _ = json.Marshal(tools)
	}
	return applied
}

func injectResults(provider string, doc map[string]json.RawMessage, in *attack.Injector) []string {
	var msgs []map[string]any
	if json.Unmarshal(doc["messages"], &msgs) != nil {
		return nil
	}
	names := map[string]string{} // tool call id -> tool name
	var applied []string
	for _, m := range msgs {
		role, _ := m["role"].(string)
		switch {
		case provider == Anthropic && role == "assistant":
			blocks, _ := m["content"].([]any)
			for _, b := range blocks {
				blk, _ := b.(map[string]any)
				if blk["type"] == "tool_use" {
					id, _ := blk["id"].(string)
					name, _ := blk["name"].(string)
					names[id] = name
				}
			}
		case provider == Anthropic && role == "user":
			blocks, _ := m["content"].([]any)
			for _, b := range blocks {
				blk, _ := b.(map[string]any)
				if blk["type"] != "tool_result" {
					continue
				}
				id, _ := blk["tool_use_id"].(string)
				if text := in.Result(names[id]); text != "" {
					blk["content"] = appendText(blk["content"], text)
					applied = append(applied, string(attack.InjectResult)+":"+names[id])
				}
			}
		case provider == OpenAI && role == "assistant":
			calls, _ := m["tool_calls"].([]any)
			for _, c := range calls {
				call, _ := c.(map[string]any)
				fn, _ := call["function"].(map[string]any)
				id, _ := call["id"].(string)
				name, _ := fn["name"].(string)
				names[id] = name
			}
		case provider == OpenAI && role == "tool":
			id, _ := m["tool_call_id"].(string)
			if text := in.Result(names[id]); text != "" {
				m["content"] = appendText(m["content"], text)
				applied = append(applied, string(attack.InjectResult)+":"+names[id])
			}
		}
	}
	if len(applied) > 0 {
		doc["messages"], _ = json.Marshal(msgs)
	}
	return applied
}

// appendText adds text to message content that is either a string or a
// list of content parts.
func appendText(content any, text string) any {
	switch c := content.(type) {
	case string:
		return c + "\n" + text
	case []any:
		return append(c, map[string]any{"type": "text", "text": text})
	case nil:
		return text
	}
	return content
}
