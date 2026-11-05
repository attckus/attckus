package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseMCPConfig(t *testing.T) {
	cfg := `{
  "mcpServers": {
    "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/data"]},
    "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]},
    "github": {"command": "docker", "args": ["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "ghcr.io/github/github-mcp-server"],
               "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz0123456789"}},
    "tools": {"url": "http://tools.internal:8080/mcp", "headers": {"Authorization": "Bearer ${TOOLS_TOKEN}"}},
    "aws": {"command": "uvx", "args": ["awslabs.aws-api-mcp-server==1.0.2"], "env": {"AWS_ROLE_ARN": "arn:aws:iam::1:role/x", "API_KEY": "your-key-here"}}
  }
}`
	got, err := ParseMCPConfig(".cursor/mcp.json", []byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]MCPServer{}
	for _, s := range got {
		by[s.Name] = s
	}
	if s := by["fs"]; !s.Pinned || s.Kind != "filesystem" || s.Line != 3 {
		t.Errorf("fs = %+v", s)
	}
	if s := by["fetch"]; s.Pinned || s.Package != "mcp-server-fetch" || s.Kind != "fetch" {
		t.Errorf("fetch = %+v", s)
	}
	gh := by["github"]
	if gh.Package != "ghcr.io/github/github-mcp-server" || gh.Pinned || len(gh.Secrets) != 1 || gh.Secrets[0].Redacted != "ghp_…REDACTED" {
		t.Errorf("github = %+v secrets=%+v", gh, gh.Secrets)
	}
	if s := by["tools"]; s.Transport != "http" || len(s.Secrets) != 0 || s.Kind != "unknown" {
		t.Errorf("tools = %+v (env reference is not a secret)", s)
	}
	if s := by["aws"]; !s.Pinned || s.AWSRole != "arn:aws:iam::1:role/x" || len(s.Secrets) != 0 {
		t.Errorf("aws = %+v (placeholder is not a secret)", s)
	}
}

func TestPinning(t *testing.T) {
	cases := map[string]bool{
		"pkg": false, "pkg@1.2.3": true, "@scope/pkg": false, "@scope/pkg@1.0.0": true,
		"pkg@latest": false, "pkg==0.4": true,
	}
	for spec, want := range cases {
		if got := pinnedPackage(spec); got != want {
			t.Errorf("pinnedPackage(%q) = %v", spec, got)
		}
	}
	images := map[string]bool{"img": false, "img:latest": false, "img:1.2": true, "reg:5000/img": false, "img@sha256:abc": true}
	for ref, want := range images {
		if got := pinnedImage(ref); got != want {
			t.Errorf("pinnedImage(%q) = %v", ref, got)
		}
	}
}

func TestDetectCode(t *testing.T) {
	py := "from langgraph.graph import StateGraph\nfrom openai import OpenAI\nfrom mcp import ClientSession\n"
	ts := "import { Client } from '@modelcontextprotocol/sdk/client/index.js'\nimport Anthropic from '@anthropic-ai/sdk'\nconst s = 'openai'\n"
	cases := []struct {
		file, src string
		want      int
	}{
		{"a/agent.py", py, 3},
		{"b/index.ts", ts, 2}, // the bare 'openai' string is not an import
		{"c/main.go", "import (\n\t\"github.com/anthropics/anthropic-sdk-go\"\n)\n", 1},
		{"d/util.py", "import os\n", 0},
	}
	for _, c := range cases {
		if got := detectCode(c.file, []byte(c.src)); len(got) != c.want {
			t.Errorf("%s: %d labels, want %d", c.file, len(got), c.want)
		}
	}
}

func TestDiscoverLinksAgents(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("agents/bot/agent.py", "from openai import OpenAI\n")
	write("agents/bot/mcp.json", `{"mcpServers":{"fetch":{"command":"uvx","args":["mcp-server-fetch"]}}}`)
	write(".mcp.json", `{"mcpServers":{"fs":{"command":"npx","args":["@modelcontextprotocol/server-filesystem@1.0.0"]}}}`)
	write("cluster/k8s.json", `{"apiVersion":"v1","kind":"List","items":[
	  {"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"bot","namespace":"s"},"spec":{"template":{"spec":{"containers":[{"image":"x","env":[{"name":"OPENAI_API_KEY"}]}]}}}},
	  {"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"web","namespace":"s"},"spec":{"template":{"spec":{"containers":[{"image":"y"}]}}}}]}`)
	write("package.json", `{"name":"x","kind":"not-k8s","apiVersion":"nope"}`)

	inv, err := Discover(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Agents) != 2 {
		for _, a := range inv.Agents {
			t.Logf("agent %s", a.Name)
		}
		t.Fatalf("agents = %d, want 2 (bot merged across code, config and workload; ide assistant)", len(inv.Agents))
	}
	bot := inv.Agents[0]
	if bot.Name != "bot" || bot.Code == nil || bot.Workload == nil || len(bot.Servers) != 1 {
		t.Errorf("bot not fully linked: %+v", bot)
	}
	if inv.Agents[1].Kind != "ide" {
		t.Errorf("root config should be an IDE assistant: %+v", inv.Agents[1])
	}
	if len(inv.K8sFiles) != 1 || len(inv.Warnings) != 0 {
		t.Errorf("k8s files %v warnings %v", inv.K8sFiles, inv.Warnings)
	}
}
