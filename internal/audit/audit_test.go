package audit

import (
	"bytes"
	"testing"
)

func TestRedactNested(t *testing.T) {
	in := map[string]any{
		"to": "a@b.c", "api_key": "sk-123",
		"headers": map[string]any{"Authorization": "Bearer x", "accept": "json"},
		"items":   []any{map[string]any{"password": "p", "id": 1.0}},
	}
	out := Redact(in)
	if out["api_key"] != "REDACTED" || out["to"] != "a@b.c" {
		t.Errorf("top level: %v", out)
	}
	if h := out["headers"].(map[string]any); h["Authorization"] != "REDACTED" || h["accept"] != "json" {
		t.Errorf("nested map: %v", h)
	}
	if it := out["items"].([]any)[0].(map[string]any); it["password"] != "REDACTED" || it["id"] != 1.0 {
		t.Errorf("nested slice: %v", it)
	}
	if in["api_key"] != "sk-123" {
		t.Error("input mutated")
	}
}

func TestWriteRead(t *testing.T) {
	var b bytes.Buffer
	w := NewWriter(&b)
	w.Write(Event{Type: ToolCall, Tool: "x", Decision: Denied})
	b.WriteString("not json\n")
	w.Write(Event{Type: ToolResult, Tool: "x"})
	var nilW *Writer
	nilW.Write(Event{Type: ToolCall}) // must not panic
	evs, err := Read(&b)
	if err != nil || len(evs) != 2 || evs[0].Time.IsZero() {
		t.Errorf("events = %+v err = %v", evs, err)
	}
}
