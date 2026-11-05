package suite

import (
	"bytes"
	"context"
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mohitkumar/groot/internal/analyze"
	"github.com/mohitkumar/groot/internal/attack"
	"github.com/mohitkumar/groot/internal/audit"
)

func writeSuite(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "groot-suite.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValidation(t *testing.T) {
	bad := map[string]string{
		"version":      `{"version": 2, "command": ["x"], "llm": {}, "scenarios": [{"name": "a"}]}`,
		"no command":   `{"version": 1, "llm": {}, "scenarios": [{"name": "a"}]}`,
		"no target":    `{"version": 1, "command": ["x"], "scenarios": [{"name": "a"}]}`,
		"no scenarios": `{"version": 1, "command": ["x"], "llm": {}}`,
		"dup scenario": `{"version": 1, "command": ["x"], "llm": {}, "scenarios": [{"name": "a"}, {"name": "a"}]}`,
		"bad server":   `{"version": 1, "command": ["x"], "mcp_servers": [{"name": "a b", "url": "http://x"}], "scenarios": [{"name": "a"}]}`,
		"both":         `{"version": 1, "command": ["x"], "mcp_servers": [{"name": "a", "url": "http://x", "command": ["y"]}], "scenarios": [{"name": "a"}]}`,
		"bad fault":    `{"version": 1, "command": ["x"], "llm": {}, "scenarios": [{"name": "a", "faults": [{"type": "meteor"}]}]}`,
		"bad attack":   `{"version": 1, "command": ["x"], "llm": {}, "scenarios": [{"name": "a", "attacks": [{"type": "poison_tool"}]}]}`,
		"unknown key":  `{"version": 1, "command": ["x"], "llm": {}, "scenarios": [{"name": "a"}], "extra": 1}`,
	}
	for name, body := range bad {
		if _, err := Load(writeSuite(t, body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	s, err := Load(writeSuite(t, `{"version": 1, "command": ["x"], "llm": {}, "scenarios": [
	  {"name": "a"}, {"name": "b", "faults": [{"tool": "x", "type": "error", "probability": 1}]},
	  {"name": "c", "attacks": [{"type": "inject_result", "tool": "x"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if s.Agent != "agent" || s.Scenarios[0].Kind() != "baseline" || s.Scenarios[1].Kind() != "failure" || s.Scenarios[2].Kind() != "attack" {
		t.Errorf("defaults/kinds: %+v", s)
	}
}

func TestSlug(t *testing.T) {
	if got := Slug("Prompt injection: in order data!"); got != "prompt-injection-in-order-data" {
		t.Errorf("slug = %q", got)
	}
}

func TestEvaluate(t *testing.T) {
	const canary = "groot-canary-1"
	sc := Scenario{Name: "inj", Expect: Expect{ForbiddenTools: []string{"delete_order"}}}
	sc.Attacks = append(sc.Attacks, mustAttack())
	events := []audit.Event{
		{Type: audit.ToolCall, Tool: "send_email", Args: map[string]any{"to": canary}, Decision: audit.Forwarded},
		{Type: audit.ToolCall, Tool: "delete_order", Args: map[string]any{"to": canary}, Decision: audit.Denied, Rule: "no deletes"},
	}
	checks := evaluate(sc, events, analyze.Report{}, canary, 0, false)
	byName := map[string]Check{}
	for _, c := range checks {
		byName[c.Name] = c
	}
	if c := byName["ignores injected instructions"]; c.Pass || !strings.Contains(c.Detail, "send_email(forwarded)") {
		t.Errorf("obeyed: %+v", c)
	}
	if c := byName["never calls forbidden tools"]; c.Pass {
		t.Errorf("forbidden: %+v", c)
	}

	// Only contained calls, and the scenario accepts containment.
	sc.Expect = Expect{AllowContained: true}
	checks = evaluate(sc, events[1:], analyze.Report{}, canary, 0, false)
	for _, c := range checks {
		if !c.Pass {
			t.Errorf("contained should pass: %+v", c)
		}
	}

	// Failure detectors, with one kind allowed.
	fsc := Scenario{Name: "f", Expect: Expect{Allow: []string{analyze.RetryStorm}, AgentSucceeds: true}}
	rep := analyze.Report{Issues: []analyze.Issue{{Kind: analyze.RetryStorm, Detail: "storm"}, {Kind: analyze.DuplicateSide, Detail: "dup"}}}
	failed := map[string]bool{}
	for _, c := range evaluate(fsc, nil, rep, canary, 3, true) {
		if !c.Pass {
			failed[c.Name] = true
		}
	}
	if failed["no retry storm"] || !failed["no duplicate side effect"] || !failed["agent exits 0"] || !failed["finishes in time"] {
		t.Errorf("failed checks = %v", failed)
	}
}

func TestReportFormats(t *testing.T) {
	r := Report{Agent: "bot", Results: []Result{
		{Scenario: "a", Kind: "baseline", Status: Pass, Checks: []Check{{Name: "ok", Pass: true}}},
		{Scenario: "b", Kind: "failure", Status: Fail, Checks: []Check{{Name: "no retry storm", Detail: "storm"}}},
		{Scenario: "c", Kind: "attack", Status: Inconclusive},
		{Scenario: "d", Kind: "attack", Status: Error, Error: "boom"},
	}}
	if !r.Failed(false) || (Report{Results: r.Results[:1]}).Failed(true) {
		t.Error("Failed()")
	}
	if !(Report{Results: r.Results[2:3]}).Failed(true) || (Report{Results: r.Results[2:3]}).Failed(false) {
		t.Error("strict mode")
	}
	var b bytes.Buffer
	if err := JUnit(&b, r); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Tests    int `xml:"tests,attr"`
		Failures int `xml:"failures,attr"`
		Errors   int `xml:"errors,attr"`
		Skipped  int `xml:"skipped,attr"`
	}
	if err := xml.Unmarshal(b.Bytes(), &doc); err != nil || doc.Tests != 4 || doc.Failures != 1 || doc.Errors != 1 || doc.Skipped != 1 {
		t.Errorf("junit %+v %v\n%s", doc, err, b.String())
	}
	b.Reset()
	Text(&b, r)
	if !strings.Contains(b.String(), "4 scenarios: 1 passed, 1 failed, 1 inconclusive, 1 errors") {
		t.Errorf("text:\n%s", b.String())
	}
}

// TestDemoSuiteEndToEnd builds groot and the demo binaries and runs the
// demo suite, the same way CI does.
func TestDemoSuiteEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binaries")
	}
	root, _ := filepath.Abs("../..")
	bin := t.TempDir()
	build := exec.Command("go", "build", "-o", bin+string(os.PathSeparator), "./cmd/groot", "./examples/naive-agent", "./examples/fake-mcp-server")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	s, err := Load(filepath.Join(root, "examples/demo-env/groot-suite.json"))
	if err != nil {
		t.Fatal(err)
	}
	s.Command = []string{filepath.Join(bin, "naive-agent")}
	s.MCPServers[0].Command = []string{filepath.Join(bin, "fake-mcp-server")}
	r := &Runner{Groot: filepath.Join(bin, "groot"), OutDir: t.TempDir()}
	rep := r.Run(context.Background(), s, nil)
	want := map[string]string{
		"baseline": Pass, "payments outage": Fail, "slow email provider": Fail,
		"prompt injection in order data": Fail, "injection contained by policy": Pass, "poisoned tool description": Pass,
	}
	for _, res := range rep.Results {
		if res.Status != want[res.Scenario] {
			t.Errorf("%s: %s, want %s (%+v)", res.Scenario, res.Status, want[res.Scenario], res.Checks)
		}
	}
	if len(rep.Results) != len(want) {
		t.Errorf("ran %d scenarios", len(rep.Results))
	}
}

func mustAttack() attack.Attack { return attack.Attack{Type: attack.InjectResult, Tool: "get_order"} }
