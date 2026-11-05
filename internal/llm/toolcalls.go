package llm

import (
	"bytes"
	"encoding/json"
	"strings"
)

const (
	Anthropic = "anthropic"
	OpenAI    = "openai"
)

// ToolCall is a tool use the model asked the agent to perform.
type ToolCall struct {
	ID    string
	Name  string
	Args  map[string]any
	Index int
}

// Verdict decides one tool call. Blocked calls are replaced by a text block
// carrying Message, so the model and the agent both see why.
type Verdict struct {
	Blocked bool
	Message string
}

// Decider is called once per tool call in a response.
type Decider func(ToolCall) Verdict

func parseArgs(raw []byte) map[string]any {
	var m map[string]any
	if len(bytes.TrimSpace(raw)) == 0 || json.Unmarshal(raw, &m) != nil {
		return map[string]any{}
	}
	return m
}

// ---------------------------------------------------------------------------
// Non-streaming responses

// rewriteAnthropic replaces blocked tool_use blocks in a Messages response.
// If no tool_use is left, stop_reason becomes end_turn so the agent loop ends
// instead of waiting for tool results.
func rewriteAnthropic(body []byte, decide Decider) ([]byte, bool) {
	var doc map[string]json.RawMessage
	if json.Unmarshal(body, &doc) != nil {
		return body, false
	}
	var content []json.RawMessage
	if json.Unmarshal(doc["content"], &content) != nil {
		return body, false
	}
	changed, toolsLeft := false, 0
	for i, raw := range content {
		var b struct {
			Type  string          `json:"type"`
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		}
		if json.Unmarshal(raw, &b) != nil || b.Type != "tool_use" {
			continue
		}
		v := decide(ToolCall{ID: b.ID, Name: b.Name, Args: parseArgs(b.Input), Index: i})
		if !v.Blocked {
			toolsLeft++
			continue
		}
		content[i], _ = json.Marshal(map[string]string{"type": "text", "text": v.Message})
		changed = true
	}
	if !changed {
		return body, false
	}
	doc["content"], _ = json.Marshal(content)
	if toolsLeft == 0 && string(doc["stop_reason"]) == `"tool_use"` {
		doc["stop_reason"] = json.RawMessage(`"end_turn"`)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return body, false
	}
	return out, true
}

// rewriteOpenAI removes blocked tool_calls from each choice and adds their
// messages to the choice's content.
func rewriteOpenAI(body []byte, decide Decider) ([]byte, bool) {
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if dec.Decode(&doc) != nil {
		return body, false
	}
	choices, _ := doc["choices"].([]any)
	changed := false
	for _, c := range choices {
		choice, _ := c.(map[string]any)
		msg, _ := choice["message"].(map[string]any)
		calls, _ := msg["tool_calls"].([]any)
		if len(calls) == 0 {
			continue
		}
		var kept []any
		var notes []string
		for i, tc := range calls {
			call, _ := tc.(map[string]any)
			fn, _ := call["function"].(map[string]any)
			name, _ := fn["name"].(string)
			args, _ := fn["arguments"].(string)
			id, _ := call["id"].(string)
			v := decide(ToolCall{ID: id, Name: name, Args: parseArgs([]byte(args)), Index: i})
			if v.Blocked {
				notes = append(notes, v.Message)
				continue
			}
			kept = append(kept, tc)
		}
		if len(notes) == 0 {
			continue
		}
		changed = true
		text, _ := msg["content"].(string)
		msg["content"] = strings.TrimSpace(text + "\n" + strings.Join(notes, "\n"))
		if len(kept) == 0 {
			delete(msg, "tool_calls")
			choice["finish_reason"] = "stop"
		} else {
			msg["tool_calls"] = kept
		}
	}
	if !changed {
		return body, false
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return body, false
	}
	return out, true
}

// ---------------------------------------------------------------------------
// Streaming responses
//
// A stream is processed one server-sent event at a time (lines up to a blank
// line). Text streams through untouched; tool calls are held until they are
// complete, decided, then released or replaced. Tool-call arguments are
// usually small, so holding them adds little latency.

// sseEvent is one event: its raw lines and the JSON of its data line.
type sseEvent struct {
	lines [][]byte
	data  []byte
}

func (e sseEvent) bytes() []byte {
	var b bytes.Buffer
	for _, l := range e.lines {
		b.Write(l)
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	return b.Bytes()
}

func newEvent(eventName string, data any) sseEvent {
	d, _ := json.Marshal(data)
	var lines [][]byte
	if eventName != "" {
		lines = append(lines, []byte("event: "+eventName))
	}
	lines = append(lines, append([]byte("data: "), d...))
	return sseEvent{lines: lines, data: d}
}

// streamRewriter consumes events and returns what to emit.
type streamRewriter interface {
	push(ev sseEvent) []sseEvent
	flush() []sseEvent
}

// anthropicStream holds each tool_use content block from its
// content_block_start to its content_block_stop.
type anthropicStream struct {
	decide          Decider
	held            []sseEvent
	holding         bool
	index           int
	call            ToolCall
	args            strings.Builder
	allowed, denied int
}

func (s *anthropicStream) push(ev sseEvent) []sseEvent {
	var m struct {
		Type         string `json:"type"`
		Index        int    `json:"index"`
		ContentBlock struct {
			Type string `json:"type"`
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"content_block"`
		Delta struct {
			Type        string `json:"type"`
			PartialJSON string `json:"partial_json"`
			StopReason  string `json:"stop_reason"`
		} `json:"delta"`
	}
	_ = json.Unmarshal(ev.data, &m)

	if !s.holding && m.Type == "content_block_start" && m.ContentBlock.Type == "tool_use" {
		s.holding, s.index = true, m.Index
		s.call = ToolCall{ID: m.ContentBlock.ID, Name: m.ContentBlock.Name, Index: m.Index}
		s.args.Reset()
		s.held = []sseEvent{ev}
		return nil
	}
	if s.holding {
		s.held = append(s.held, ev)
		if m.Type == "content_block_delta" && m.Index == s.index && m.Delta.Type == "input_json_delta" {
			s.args.WriteString(m.Delta.PartialJSON)
		}
		if m.Type == "content_block_stop" && m.Index == s.index {
			return s.release()
		}
		return nil
	}
	if m.Type == "message_delta" && m.Delta.StopReason == "tool_use" && s.allowed == 0 && s.denied > 0 {
		return []sseEvent{rewriteStopReason(ev)}
	}
	return []sseEvent{ev}
}

func (s *anthropicStream) release() []sseEvent {
	s.holding = false
	s.call.Args = parseArgs([]byte(s.args.String()))
	v := s.decide(s.call)
	held := s.held
	s.held = nil
	if !v.Blocked {
		s.allowed++
		return held
	}
	s.denied++
	return []sseEvent{
		newEvent("content_block_start", map[string]any{"type": "content_block_start", "index": s.index,
			"content_block": map[string]any{"type": "text", "text": ""}}),
		newEvent("content_block_delta", map[string]any{"type": "content_block_delta", "index": s.index,
			"delta": map[string]any{"type": "text_delta", "text": v.Message}}),
		newEvent("content_block_stop", map[string]any{"type": "content_block_stop", "index": s.index}),
	}
}

func (s *anthropicStream) flush() []sseEvent {
	// A stream that ended mid tool block is passed on as received.
	held := s.held
	s.held = nil
	return held
}

func rewriteStopReason(ev sseEvent) sseEvent {
	var doc map[string]any
	if json.Unmarshal(ev.data, &doc) != nil {
		return ev
	}
	if d, ok := doc["delta"].(map[string]any); ok {
		d["stop_reason"] = "end_turn"
	}
	return newEvent("message_delta", doc)
}

// openAIStream holds every chunk from the first tool_calls delta to the chunk
// carrying finish_reason, then decides all calls together.
type openAIStream struct {
	decide  Decider
	held    []sseEvent
	holding bool
	calls   map[int]*ToolCall
	args    map[int]*strings.Builder
}

type oaChunk struct {
	Choices []struct {
		Index int `json:"index"`
		Delta struct {
			ToolCalls []struct {
				Index    int    `json:"index"`
				ID       string `json:"id"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
}

func (s *openAIStream) push(ev sseEvent) []sseEvent {
	var c oaChunk
	if len(ev.data) == 0 || json.Unmarshal(ev.data, &c) != nil || len(c.Choices) == 0 {
		if s.holding { // e.g. [DONE] or a usage-only chunk arriving early
			s.held = append(s.held, ev)
			return nil
		}
		return []sseEvent{ev}
	}
	ch := c.Choices[0]
	if len(ch.Delta.ToolCalls) > 0 && !s.holding {
		s.holding = true
		s.calls, s.args = map[int]*ToolCall{}, map[int]*strings.Builder{}
	}
	if !s.holding {
		return []sseEvent{ev}
	}
	s.held = append(s.held, ev)
	for _, tc := range ch.Delta.ToolCalls {
		call, ok := s.calls[tc.Index]
		if !ok {
			call = &ToolCall{Index: tc.Index}
			s.calls[tc.Index], s.args[tc.Index] = call, &strings.Builder{}
		}
		if tc.ID != "" {
			call.ID = tc.ID
		}
		if tc.Function.Name != "" {
			call.Name = tc.Function.Name
		}
		s.args[tc.Index].WriteString(tc.Function.Arguments)
	}
	if ch.FinishReason != nil && *ch.FinishReason != "" {
		return s.release()
	}
	return nil
}

func (s *openAIStream) release() []sseEvent {
	s.holding = false
	held := s.held
	s.held = nil
	blocked := map[int]bool{}
	var notes []string
	for idx, call := range s.calls {
		call.Args = parseArgs([]byte(s.args[idx].String()))
		if v := s.decide(*call); v.Blocked {
			blocked[idx] = true
			notes = append(notes, v.Message)
		}
	}
	if len(blocked) == 0 {
		return held
	}
	var out []sseEvent
	for _, ev := range held {
		var doc map[string]any
		if json.Unmarshal(ev.data, &doc) != nil {
			out = append(out, ev)
			continue
		}
		choices, _ := doc["choices"].([]any)
		if len(choices) == 0 {
			out = append(out, ev)
			continue
		}
		choice, _ := choices[0].(map[string]any)
		delta, _ := choice["delta"].(map[string]any)
		if tcs, ok := delta["tool_calls"].([]any); ok {
			var kept []any
			for _, tc := range tcs {
				m, _ := tc.(map[string]any)
				idx, _ := m["index"].(float64)
				if !blocked[int(idx)] {
					kept = append(kept, tc)
				}
			}
			if len(kept) == 0 {
				delete(delta, "tool_calls")
			} else {
				delta["tool_calls"] = kept
			}
		}
		if fr, _ := choice["finish_reason"].(string); fr != "" {
			// Tell the agent why, just before the finish chunk.
			note := map[string]any{}
			for k, v := range doc {
				note[k] = v
			}
			note["choices"] = []any{map[string]any{"index": choice["index"], "delta": map[string]any{"content": "\n" + strings.Join(notes, "\n")}, "finish_reason": nil}}
			delete(note, "usage")
			out = append(out, newEvent("", note))
			if len(blocked) == len(s.calls) {
				choice["finish_reason"] = "stop"
			}
		} else if len(delta) == 0 || (len(delta) == 1 && delta["role"] != nil) {
			if _, hasUsage := doc["usage"]; !hasUsage || doc["usage"] == nil {
				continue // nothing left in this chunk
			}
		}
		out = append(out, newEvent("", doc))
	}
	return out
}

func (s *openAIStream) flush() []sseEvent {
	held := s.held
	s.held = nil
	return held
}
