package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const demo = "../../examples/demo-env"

func runCLI(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(""), &out, &errb)
	return code, out.String(), errb.String()
}

func TestScanExitCodes(t *testing.T) {
	if code, out, _ := runCLI("scan", demo); code != 1 || !strings.Contains(out, "5 critical") {
		t.Errorf("default fail-on critical: code %d\n%s", code, out)
	}
	if code, _, _ := runCLI("scan", "--fail-on", "none", demo); code != 0 {
		t.Errorf("--fail-on none: %d", code)
	}
	empty := t.TempDir()
	if code, out, _ := runCLI("scan", empty); code != 0 || !strings.Contains(out, "No agents") {
		t.Errorf("empty dir: %d %s", code, out)
	}
	if code, _, _ := runCLI("scan", "--fail-on", "sometimes", demo); code != 2 {
		t.Errorf("bad severity: %d", code)
	}
}

func TestScanFormats(t *testing.T) {
	_, out, _ := runCLI("scan", "--format", "json", "--fail-on", "none", demo)
	var doc struct {
		Agents   []map[string]any
		Findings []map[string]any
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || len(doc.Agents) != 3 || len(doc.Findings) != 15 {
		t.Errorf("json: %v agents=%d findings=%d", err, len(doc.Agents), len(doc.Findings))
	}
	if _, out, _ := runCLI("scan", "--format", "sarif", "--fail-on", "none", demo); !strings.Contains(out, `"version": "2.1.0"`) {
		t.Error("sarif output")
	}
	if code, out, _ := runCLI("graph", demo); code != 0 || !strings.HasPrefix(out, "<!doctype html>") {
		t.Errorf("graph: %d", code)
	}
	if _, out, _ := runCLI("scan", "--format", "mermaid", "--fail-on", "none", demo); !strings.HasPrefix(out, "flowchart LR") {
		t.Error("mermaid output")
	}
}

func TestPolicyInitAndCheck(t *testing.T) {
	file := filepath.Join(t.TempDir(), "p.json")
	if code, _, errs := runCLI("policy", "init", "--out", file); code != 0 {
		t.Fatalf("init: %s", errs)
	}
	if code, _, _ := runCLI("policy", "init", "--out", file); code != 1 {
		t.Error("init must not overwrite")
	}
	if code, out, _ := runCLI("policy", "check", file); code != 0 || !strings.Contains(out, "mode enforce") {
		t.Errorf("check: %d %s", code, out)
	}
	for _, f := range []string{"test-policy.json"} {
		if code, _, errs := runCLI("policy", "check", filepath.Join(demo, "gateway", f)); code != 0 {
			t.Errorf("%s: %s", f, errs)
		}
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(bad, []byte(`{"version": 1, "mode": "maybe"}`), 0o644)
	if code, _, _ := runCLI("policy", "check", bad); code != 1 {
		t.Error("bad policy accepted")
	}
}

func TestAnalyzeCLI(t *testing.T) {
	log := filepath.Join(t.TempDir(), "audit.jsonl")
	var lines []string
	for i := 0; i < 5; i++ {
		lines = append(lines, `{"time":"2026-11-02T10:00:0`+string(rune('0'+i))+`Z","type":"tool_call","agent":"a","tool":"get_order","args_hash":"x","decision":"forwarded"}`)
	}
	_ = os.WriteFile(log, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	if code, out, _ := runCLI("analyze", log); code != 1 || !strings.Contains(out, "retry_storm") {
		t.Errorf("analyze: %d\n%s", code, out)
	}
	if code, _, _ := runCLI("analyze", "--retry-threshold", "6", log); code != 0 {
		t.Error("threshold 6 should find nothing")
	}
}

func TestGatewayArgErrors(t *testing.T) {
	cases := [][]string{
		{"gateway"},
		{"gateway", "stdio", "--policy", "x.json"},
		{"gateway", "stdio", "--", "true"},
	}
	for _, c := range cases {
		if code, _, _ := runCLI(c...); code != 2 {
			t.Errorf("%v: code %d, want 2", c, code)
		}
	}
}
