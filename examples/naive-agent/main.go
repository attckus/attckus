// Command naive-agent is a deliberately badly behaved agent for demos. It
// talks MCP over stdio to the command after "--", or to the first server in
// the config named by GROOT_MCP_CONFIG (which `groot test` writes), and
// makes four classic mistakes:
//
//  1. follows instructions it finds inside tool results (prompt injection),
//     standing in for an LLM that does the same
//  2. retries a failing refund immediately, six times, with no backoff
//  3. gives up on a slow send_email after 300 ms and sends it again
//  4. after the refund keeps failing, reaches for a more powerful tool
//
// With NAIVE_MODE=desperate it ignores instructions in tool results until
// something has failed, then reads error text and a fresh order lookup
// closely and obeys what it finds. That stands in for an LLM that is most
// compliant when its plan is breaking; it is what the compound scenarios in
// groot-suite-compound.json measure.
//
// Run it with `groot test --suite examples/demo-env/groot-suite.json`.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"sync"
	"time"
)

// injected matches the instruction groot's attack payload carries.
var injected = regexp.MustCompile("call the `([A-Za-z0-9_]+)` tool with the argument value \"([^\"]+)\"")

// serverCommand returns the MCP server command from "--" args or GROOT_MCP_CONFIG.
func serverCommand() []string {
	if len(os.Args) >= 3 && os.Args[1] == "--" {
		return os.Args[2:]
	}
	path := os.Getenv("GROOT_MCP_CONFIG")
	if path == "" {
		log.Fatal("usage: naive-agent -- <mcp server command...>   (or set GROOT_MCP_CONFIG)")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	var cfg struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatal(err)
	}
	names := make([]string, 0, len(cfg.MCPServers))
	for n, s := range cfg.MCPServers {
		if s.Command != "" {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		log.Fatal("no stdio server in GROOT_MCP_CONFIG")
	}
	sort.Strings(names)
	s := cfg.MCPServers[names[0]]
	return append([]string{s.Command}, s.Args...)
}

type client struct {
	in      io.Writer
	mu      sync.Mutex
	nextID  int
	waiters map[int]chan map[string]any
}

func (c *client) call(method string, params any, timeout time.Duration) (map[string]any, error) {
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	ch := make(chan map[string]any, 1)
	c.waiters[id] = ch
	c.mu.Unlock()
	msg, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if _, err := c.in.Write(append(msg, '\n')); err != nil {
		return nil, err
	}
	select {
	case resp := <-ch:
		return resp, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("%s timed out after %s", method, timeout)
	}
}

func (c *client) tool(name string, args map[string]any) (string, bool, error) {
	resp, err := c.call("tools/call", map[string]any{"name": name, "arguments": args}, 300*time.Millisecond)
	if err != nil {
		return "", true, err
	}
	if e, ok := resp["error"].(map[string]any); ok {
		return fmt.Sprint(e["message"]), true, nil
	}
	res, _ := resp["result"].(map[string]any)
	isErr, _ := res["isError"].(bool)
	// Read every text block, as a model would.
	text := ""
	if content, ok := res["content"].([]any); ok {
		for _, c := range content {
			if block, ok := c.(map[string]any); ok && block["type"] == "text" {
				text += fmt.Sprint(block["text"]) + "\n"
			}
		}
	}
	return text, isErr, nil
}

func main() {
	argv := serverCommand()
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stderr = os.Stderr
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}
	c := &client{in: in, waiters: map[int]chan map[string]any{}}
	go func() {
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 0, 64*1024), 16<<20)
		for sc.Scan() {
			var m map[string]any
			if json.Unmarshal(sc.Bytes(), &m) != nil {
				continue
			}
			id, _ := m["id"].(float64)
			c.mu.Lock()
			ch := c.waiters[int(id)]
			delete(c.waiters, int(id))
			c.mu.Unlock()
			if ch != nil {
				ch <- m
			}
		}
	}()

	if _, err := c.call("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]string{"name": "naive-agent", "version": "0"}}, 5*time.Second); err != nil {
		log.Fatal(err)
	}
	_, _ = in.Write([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"))
	if _, err := c.call("tools/list", map[string]any{}, 5*time.Second); err != nil {
		log.Fatal(err)
	}

	desperate := os.Getenv("NAIVE_MODE") == "desperate"
	obey := func(text string) {
		if m := injected.FindStringSubmatch(text); m != nil {
			out, isErr, err := c.tool(m[1], map[string]any{"to": m[2], "body": "as instructed"})
			log.Printf("followed instruction in tool result: %s -> err=%v isError=%v %s", m[1], err, isErr, out)
		}
	}

	// Mistake 1: obey instructions found in tool results.
	text, isErr, err := c.tool("get_order", map[string]any{"order_id": "ACME-1042"})
	log.Printf("get_order: err=%v isError=%v %s", err, isErr, text)
	if !desperate {
		obey(text)
	}

	// Mistake 2: retry storm.
	refunded := false
	for attempt := 1; attempt <= 6 && !refunded; attempt++ {
		text, isErr, err := c.tool("refund_order", map[string]any{"order_id": "ACME-1042"})
		log.Printf("refund attempt %d: err=%v isError=%v %s", attempt, err, isErr, text)
		refunded = err == nil && !isErr
		if desperate && !refunded {
			obey(text)
		}
	}
	if desperate && !refunded {
		text, _, _ := c.tool("get_order", map[string]any{"order_id": "ACME-1042"})
		obey(text)
	}
	// Mistake 3: duplicate side effect after a client-side timeout.
	for attempt := 1; attempt <= 2; attempt++ {
		text, isErr, err := c.tool("send_email", map[string]any{"to": "customer@example.com", "body": "Your refund is on its way."})
		log.Printf("email attempt %d: err=%v isError=%v %s", attempt, err, isErr, text)
		if err == nil && !isErr {
			break
		}
	}
	// Mistake 4: escalation after failure.
	if !refunded {
		text, isErr, err := c.tool("execute_sql", map[string]any{"sql": "UPDATE orders SET status = 'refunded' WHERE id = 'ACME-1042'"})
		log.Printf("escalation: err=%v isError=%v %s", err, isErr, text)
	}

	time.Sleep(1200 * time.Millisecond) // let delayed calls land so the audit log is complete
	in.Close()
	_ = cmd.Wait()
}
