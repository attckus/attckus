package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/attckus/attckus/internal/inventory"
	"github.com/attckus/attckus/internal/risk"
)

func demo(t *testing.T) *risk.Result {
	t.Helper()
	inv, err := inventory.Discover("../../examples/demo-env")
	if err != nil {
		t.Fatal(err)
	}
	return risk.Analyze(inv)
}

func TestText(t *testing.T) {
	var b bytes.Buffer
	Text(&b, demo(t))
	out := b.String()
	for _, want := range []string{"■ support-bot", "path: support-bot → sa support/support-bot → role support-agent-role → role ops-admin", "CRITICAL", "fix:", "3 agents"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q", want)
		}
	}
	if strings.Contains(out, "AbCdEfGh") || strings.Contains(out, "Zx9dQ2") {
		t.Error("secret leaked into report")
	}
}

func TestSARIF(t *testing.T) {
	var b bytes.Buffer
	if err := SARIF(&b, demo(t), "test"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []struct{ ID string }
				}
			}
			Results []struct {
				RuleID    string
				Level     string
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string }
						Region           struct{ StartLine int }
					}
				}
			}
		}
	}
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 || len(doc.Runs[0].Tool.Driver.Rules) != len(risk.Rules) {
		t.Fatalf("bad sarif header: %+v", doc)
	}
	for _, r := range doc.Runs[0].Results {
		if len(r.Locations) != 1 || r.Locations[0].PhysicalLocation.Region.StartLine < 1 || r.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
			t.Errorf("result %s has no usable location", r.RuleID)
		}
		if r.Level != "error" && r.Level != "warning" && r.Level != "note" {
			t.Errorf("bad level %q", r.Level)
		}
	}
}

func TestMermaid(t *testing.T) {
	var b bytes.Buffer
	Mermaid(&b, demo(t))
	out := b.String()
	if !strings.HasPrefix(out, "flowchart LR") || !strings.Contains(out, "-->|assumes|") || !strings.Contains(out, ":::critical") {
		t.Errorf("mermaid output:\n%s", out)
	}
}

func TestJSONEmpty(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, &risk.Result{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"findings": []`) {
		t.Errorf("empty result should encode empty arrays: %s", b.String())
	}
}

func TestHTML(t *testing.T) {
	var b bytes.Buffer
	if err := HTML(&b, HTMLData{Scan: demo(t)}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"<svg class=\"reach\"", "Can it delete a database?", "Yes, including production", "role ops-admin", "FL103"} {
		if !strings.Contains(out, want) {
			t.Errorf("html missing %q", want)
		}
	}
	if strings.Contains(out, "<script") || strings.Contains(out, "AbCdEfGh") {
		t.Error("html must be script-free and must not leak secrets")
	}
}
