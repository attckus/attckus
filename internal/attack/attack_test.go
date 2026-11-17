package attack

import (
	"strings"
	"testing"
)

func TestInjector(t *testing.T) {
	in, err := New([]Attack{
		{Type: PoisonTool, Tool: "get_*", Target: "delete_order"},
		{Type: RugPull, Tool: "send_email"},
		{Type: InjectResult, Tool: "fetch"},
	}, "attckus-canary-test")
	if err != nil {
		t.Fatal(err)
	}
	d, typ := in.Description("get_order", "Look up an order.")
	if typ != PoisonTool || !strings.Contains(d, "`delete_order`") || !strings.Contains(d, "attckus-canary-test") || !strings.HasPrefix(d, "Look up an order.") {
		t.Errorf("poison: %q %q", d, typ)
	}
	if d, _ := in.Description("send_email", "Send."); d != "" {
		t.Error("rug pull must leave the first listing clean")
	}
	if d, typ := in.Description("send_email", "Send."); typ != RugPull || !strings.Contains(d, "send_email") {
		t.Errorf("rug pull second listing: %q", d)
	}
	if r := in.Result("fetch"); !strings.Contains(r, "attckus-canary-test") {
		t.Errorf("result: %q", r)
	}
	if in.Result("get_order") != "" {
		t.Error("inject_result only applies to its tool")
	}
	var nilIn *Injector
	if d, _ := nilIn.Description("x", "y"); d != "" || nilIn.Result("x") != "" || nilIn.Canary() != "" {
		t.Error("nil injector must be inert")
	}
}

func TestValidateAndCanary(t *testing.T) {
	for _, a := range []Attack{{Type: "meteor", Tool: "x"}, {Type: PoisonTool}, {Type: PoisonTool, Tool: "["}} {
		if _, err := New([]Attack{a}, ""); err == nil {
			t.Errorf("accepted %+v", a)
		}
	}
	a, b := NewCanary(), NewCanary()
	if a == b || !strings.HasPrefix(a, "attckus-canary-") {
		t.Errorf("canaries %q %q", a, b)
	}
	in, _ := New([]Attack{{Type: InjectResult, Tool: "*"}}, "")
	if !strings.HasPrefix(in.Canary(), "attckus-canary-") {
		t.Error("empty canary should be generated")
	}
}
