package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseRejectsBadPolicies(t *testing.T) {
	bad := map[string]string{
		"version":     `{"version": 2}`,
		"mode":        `{"version": 1, "mode": "yolo"}`,
		"action":      `{"version": 1, "rules": [{"tool": "x", "action": "maybe"}]}`,
		"regex":       `{"version": 1, "rules": [{"tool": "x", "action": "deny", "args": {"a": {"match": "("}}}]}`,
		"glob":        `{"version": 1, "rules": [{"tool": "[", "action": "deny"}]}`,
		"unknown key": `{"version": 1, "rulez": []}`,
		"rate":        `{"version": 1, "rate_limits": [{"per_minute": 0}]}`,
		"chaos type":  `{"version": 1, "chaos": {"enabled": true, "faults": [{"type": "meteor", "probability": 1}]}}`,
		"chaos prob":  `{"version": 1, "chaos": {"enabled": true, "faults": [{"type": "error", "probability": 2}]}}`,
		"chaos delay": `{"version": 1, "chaos": {"enabled": true, "faults": [{"type": "latency", "probability": 1}]}}`,
	}
	for name, src := range bad {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: accepted %s", name, src)
		}
	}
}

func TestDefaultPolicyRoundTrips(t *testing.T) {
	b, err := json.Marshal(Default())
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(b)
	if err != nil {
		t.Fatalf("default policy does not validate: %v\n%s", err, b)
	}
	if p.Mode != DryRun {
		t.Error("default policy must start in dry-run")
	}
	cases := []struct {
		tool string
		args map[string]any
		want Action
	}{
		{"delete_order", nil, Deny},
		{"run_shell", nil, Deny},
		{"query", map[string]any{"sql": "select 1"}, Allow},
		{"query", map[string]any{"sql": "DROP TABLE x"}, Deny},
		{"send_email", nil, Approve},
		{"slack_post_message", nil, Approve},
		{"get_order", nil, Allow},
	}
	for _, c := range cases {
		if got := p.Decide("a", "s", c.tool, c.args).Action; got != c.want {
			t.Errorf("%s %v = %s, want %s", c.tool, c.args, got, c.want)
		}
	}
}

func TestAlwaysDenied(t *testing.T) {
	p, err := Parse([]byte(`{"version": 1, "rules": [
	  {"tool": "query", "args": {"sql": {"prefix": "select"}}, "action": "allow"},
	  {"tool": "query", "action": "deny"},
	  {"tool": "delete_*", "action": "deny"},
	  {"agent": "ops", "tool": "drop_*", "action": "allow"},
	  {"tool": "drop_*", "action": "deny"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.AlwaysDenied("a", "s", "query") {
		t.Error("query is allowed for some arguments")
	}
	if !p.AlwaysDenied("a", "s", "delete_x") {
		t.Error("delete_x is always denied")
	}
	if p.AlwaysDenied("ops", "s", "drop_x") || !p.AlwaysDenied("dev", "s", "drop_x") {
		t.Error("per-agent rules")
	}
}

func TestMatcherNonString(t *testing.T) {
	p, _ := Parse([]byte(`{"version": 1, "default": "deny", "rules": [{"tool": "pay", "args": {"amount": {"match": "^[0-9]{1,3}$"}}, "action": "allow"}]}`))
	if p.Decide("a", "s", "pay", map[string]any{"amount": 50.0}).Action != Allow {
		t.Error("numbers are matched on their JSON form")
	}
	if d := p.Decide("a", "s", "pay", map[string]any{"amount": 5000.0}); d.Action != Deny || !strings.Contains(d.Rule, "default") {
		t.Errorf("large amount: %+v", d)
	}
}
