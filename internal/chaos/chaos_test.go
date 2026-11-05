package chaos

import "testing"

func TestDeterministicAndProbabilistic(t *testing.T) {
	cfg := Config{Enabled: true, Seed: 42, Faults: []Fault{{Tool: "q*", Type: Error, Probability: 0.3}}}
	run := func() []bool {
		in, err := New(cfg, "staging")
		if err != nil {
			t.Fatal(err)
		}
		var out []bool
		for i := 0; i < 200; i++ {
			out = append(out, in.Pick("a", "query") != nil)
		}
		return out
	}
	a, b := run(), run()
	hits := 0
	for i := range a {
		if a[i] != b[i] {
			t.Fatal("same seed must give the same faults")
		}
		if a[i] {
			hits++
		}
	}
	if hits < 40 || hits > 80 {
		t.Errorf("30%% of 200 should be near 60, got %d", hits)
	}
	in, _ := New(cfg, "dev")
	if in.Pick("a", "get_order") != nil {
		t.Error("non-matching tool faulted")
	}
}

func TestDisabledAndProd(t *testing.T) {
	if in, err := New(Config{Enabled: false}, "prod"); in != nil || err != nil {
		t.Error("disabled chaos returns nil injector, no error")
	}
	var nilInjector *Injector
	if nilInjector.Pick("a", "b") != nil {
		t.Error("nil injector must be safe")
	}
	if _, err := New(Config{Enabled: true}, "production"); err == nil {
		t.Error("prod requires allow_prod")
	}
	if _, err := New(Config{Enabled: true, AllowProd: true}, "prod"); err != nil {
		t.Error(err)
	}
}
