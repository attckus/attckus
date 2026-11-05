// Package mcp holds the JSON-RPC 2.0 message shapes the gateway inspects.
// Unknown fields are preserved by working on raw messages and re-encoding
// only what the gateway changes.
package mcp

import (
	"encoding/json"
	"errors"
)

const Version = "2.0"

// Message is any JSON-RPC message: request, notification or response.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// JSON-RPC and MCP error codes used by the gateway.
const (
	CodeInvalidRequest = -32600
	CodeInternal       = -32603
	CodeTimeout        = -32001
)

func (m *Message) IsRequest() bool  { return m.Method != "" && len(m.ID) > 0 }
func (m *Message) IsResponse() bool { return m.Method == "" && len(m.ID) > 0 }

// Key is a stable map key for a message ID (string and number IDs differ).
func (m *Message) Key() string { return string(m.ID) }

// Parse decodes one message. Batches (JSON arrays) return ErrBatch.
func Parse(line []byte) (*Message, error) {
	for _, c := range line {
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			continue
		}
		if c == '[' {
			return nil, ErrBatch
		}
		break
	}
	var m Message
	if err := json.Unmarshal(line, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

var ErrBatch = errors.New("json-rpc batch")

// ToolCall is the params of tools/call.
type ToolCall struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

// Tool is one entry of a tools/list result; Raw keeps unknown fields.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

// ToolResult builds a tools/call result. isError results are how MCP tells
// the model a tool failed, so the model sees why it was blocked.
func ToolResult(id json.RawMessage, text string, isError bool) []byte {
	b, _ := json.Marshal(map[string]any{
		"jsonrpc": Version,
		"id":      id,
		"result": map[string]any{
			"content": []map[string]string{{"type": "text", "text": text}},
			"isError": isError,
		},
	})
	return b
}

// ErrorResponse builds a JSON-RPC error response.
func ErrorResponse(id json.RawMessage, code int, msg string) []byte {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	b, _ := json.Marshal(map[string]any{
		"jsonrpc": Version,
		"id":      id,
		"error":   map[string]any{"code": code, "message": msg},
	})
	return b
}

// ResultIsError reports whether a tools/call result has isError set.
func ResultIsError(result json.RawMessage) bool {
	var r struct {
		IsError bool `json:"isError"`
	}
	_ = json.Unmarshal(result, &r)
	return r.IsError
}
