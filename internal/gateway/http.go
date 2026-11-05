package gateway

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AgentHeader lets one HTTP gateway serve several agents; when absent the
// engine's default agent is used.
const AgentHeader = "X-Groot-Agent"

var hopByHop = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true, "Proxy-Authorization": true,
	"Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true, "Content-Length": true, "Host": true,
}

// HTTPProxy fronts a Streamable HTTP MCP server. POST bodies are inspected
// and JSON or server-sent-event responses are passed through FromServer.
type HTTPProxy struct {
	Engine   *Engine
	Upstream *url.URL
	Client   *http.Client
}

func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	session := r.Header.Get("Mcp-Session-Id")
	agent := r.Header.Get(AgentHeader)
	var body []byte
	if r.Method == http.MethodPost {
		var err error
		body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, MaxMessage))
		if err != nil {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		o := p.Engine.FromClient(session, agent, body)
		if o.Delay > 0 {
			select {
			case <-time.After(o.Delay):
			case <-r.Context().Done():
				return
			}
		}
		if o.Forward == nil {
			w.Header().Set("Content-Type", "application/json")
			if session != "" {
				w.Header().Set("Mcp-Session-Id", session)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(o.Reply)
			return
		}
		body = o.Forward
	}

	target := *p.Upstream
	target.RawQuery = r.URL.RawQuery
	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}
	up, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), reqBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	copyHeaders(up.Header, r.Header)
	up.Header.Del(AgentHeader)
	resp, err := p.client().Do(up)
	if err != nil {
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	// Keep the request's session key: the engine tracked this request under
	// it, even when the server assigns a session ID in this very response.
	copyHeaders(w.Header(), resp.Header)

	ct := resp.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "text/event-stream"):
		w.WriteHeader(resp.StatusCode)
		p.streamSSE(w, resp.Body, session)
	case strings.HasPrefix(ct, "application/json"):
		data, err := io.ReadAll(io.LimitReader(resp.Body, MaxMessage))
		if err != nil {
			http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
			return
		}
		out := p.Engine.FromServer(session, data)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(out)
	default:
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}
}

// streamSSE rewrites "data:" lines through the engine and flushes per event.
// MCP servers send one JSON message per data line.
func (p *HTTPProxy) streamSSE(w http.ResponseWriter, body io.Reader, session string) {
	flusher, _ := w.(http.Flusher)
	br := bufio.NewReader(body)
	for {
		line, err := readLine(br)
		if len(line) > 0 || err == nil {
			text := string(line)
			if strings.HasPrefix(text, "data:") {
				payload := strings.TrimSpace(strings.TrimPrefix(text, "data:"))
				text = "data: " + string(p.Engine.FromServer(session, []byte(payload)))
			}
			_, _ = io.WriteString(w, text+"\n")
			if text == "" && flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			if flusher != nil {
				flusher.Flush()
			}
			return
		}
	}
}

func (p *HTTPProxy) client() *http.Client {
	if p.Client != nil {
		return p.Client
	}
	return http.DefaultClient // streaming responses must not have a total timeout
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		if hopByHop[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}
