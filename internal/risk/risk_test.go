package risk

import (
	"strings"
	"testing"

	"github.com/mohitkumar/groot/internal/capability"
	"github.com/mohitkumar/groot/internal/inventory"
)

func demo(t *testing.T) *Result {
	t.Helper()
	inv, err := inventory.Discover("../../examples/demo-env")
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Warnings) != 0 {
		t.Fatalf("warnings: %v", inv.Warnings)
	}
	return Analyze(inv)
}

func find(r *Result, agent, rule string) (Finding, bool) {
	for _, f := range r.Findings {
		if strings.HasPrefix(f.Agent, agent) && f.Rule == rule {
			return f, true
		}
	}
	return Finding{}, false
}

func TestDemoSupportBot(t *testing.T) {
	r := demo(t)
	admin, ok := find(r, "support-bot", RuleAdmin)
	if !ok || admin.Severity != Critical {
		t.Fatalf("support-bot admin: %+v %v", admin, ok)
	}
	// Escalation runs through IRSA and an assume-role chain.
	want := []string{"support-bot", "sa support/support-bot", "role support-agent-role", "role ops-admin"}
	if strings.Join(admin.Path, "|") != strings.Join(want, "|") {
		t.Errorf("admin path = %v, want %v", admin.Path, want)
	}
	if d, ok := find(r, "support-bot", RuleDestroy); !ok || d.Severity != Critical || !strings.Contains(d.Detail, "production") {
		t.Errorf("destroy: %+v", d)
	}
	if _, ok := find(r, "support-bot", RuleTrifecta); !ok {
		t.Error("support-bot has private data (S3), untrusted input (fetch) and an external channel (slack)")
	}
	if s, ok := find(r, "support-bot", RuleSecret); !ok || strings.Contains(s.Detail, "AbCdEf") {
		t.Errorf("slack token must be reported and redacted: %+v", s)
	}
	if _, ok := find(r, "support-bot", RuleUnpinned); !ok {
		t.Error("uvx mcp-server-fetch is unpinned")
	}
}

func TestDemoReportWriterIsContained(t *testing.T) {
	r := demo(t)
	for _, f := range r.Findings {
		if f.Agent == "report-writer" && f.Severity >= High {
			t.Errorf("report-writer should have no high findings: %+v", f)
		}
	}
	for _, a := range r.Agents {
		if a.Name == "report-writer" {
			for _, c := range a.Capabilities {
				if c == capability.Secrets || c == capability.Admin {
					t.Errorf("automount is off and IAM is read-only; got %v", a.Capabilities)
				}
			}
		}
	}
}

func TestDemoIDEAssistant(t *testing.T) {
	r := demo(t)
	for _, rule := range []string{RuleTrifecta, RuleSecret, RuleUnpinned, RulePlainTxt, RuleUnknown} {
		if _, ok := find(r, "ide-assistant", rule); !ok {
			t.Errorf("ide-assistant missing %s", rule)
		}
	}
}

func TestNonAgentWorkloadsIgnored(t *testing.T) {
	for _, f := range demo(t).Findings {
		if strings.Contains(f.Agent, "checkout") {
			t.Errorf("checkout has cluster-admin but is not an agent: %+v", f)
		}
	}
}

func TestFindingsSortedAndComplete(t *testing.T) {
	r := demo(t)
	for i, f := range r.Findings {
		if i > 0 && f.Severity > r.Findings[i-1].Severity {
			t.Fatalf("not sorted at %d", i)
		}
		if f.Fix == "" || f.Title == "" || f.File == "" {
			t.Errorf("incomplete finding: %+v", f)
		}
	}
	if len(r.Notes) == 0 {
		t.Error("IAM simplification note missing")
	}
}

func TestSeverityParse(t *testing.T) {
	if s, err := ParseSeverity("HIGH"); err != nil || s != High {
		t.Errorf("got %v %v", s, err)
	}
	if _, err := ParseSeverity("severe"); err == nil {
		t.Error("want error")
	}
	if !IsProd("arn:aws:s3:::orders-prod/*") || !IsProd("production") || IsProd("product-catalog") {
		t.Error("IsProd")
	}
}

func TestAnswers(t *testing.T) {
	gs := []Grant{
		{Class: capability.Destroy, Text: "rds:DeleteDBInstance on * (admin)", Source: "aws", Via: "role a", Prod: true},
		{Class: capability.Exec, Text: "lambda:InvokeFunction on * (admin)", Source: "aws", Via: "role a"},
		{Class: capability.Destroy, Text: "delete pods in ns x (RoleBinding/x)", Source: "k8s", Via: "sa x"},
	}
	got := map[string]Answer{}
	for _, a := range Answers(gs) {
		got[a.Question] = a
	}
	for q, want := range map[string]bool{
		"Can it delete a database?": true, "Can it delete AWS resources?": true, "Can it delete Kubernetes resources?": true,
		"Can it run compute without a cap (Lambda, EC2, ECS, pods)?": true, "Can it read secrets?": false,
	} {
		if got[q].Yes != want {
			t.Errorf("%s = %v, want %v", q, got[q].Yes, want)
		}
	}
	if !got["Can it delete a database?"].Prod {
		t.Error("prod not carried")
	}
}
