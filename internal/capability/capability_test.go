package capability

import "testing"

func TestClassifyTool(t *testing.T) {
	cases := map[string]Class{
		"delete_order":       Destroy,
		"deleteOrder":        Destroy,
		"send_email":         External,
		"slack_post_message": External,
		"run_shell":          Exec,
		"execute_command":    Exec,
		"get_order":          Read,
		"query":              Read,
		"refund_order":       Write,
		"write_file":         Write,
		"fetch":              Untrusted,
		"get_secret":         Secrets,
		"assume_role":        Admin,
	}
	for name, want := range cases {
		got := ClassifyTool(name)
		if got.Strongest() != want {
			t.Errorf("%s: strongest = %q (all %v), want %q", name, got.Strongest(), got.Sorted(), want)
		}
	}
	if s := ClassifyTool("ping"); len(s) != 0 {
		t.Errorf("ping should be unclassified, got %v", s.Sorted())
	}
}

func TestTrifecta(t *testing.T) {
	if !Trifecta(NewSet(Read, Untrusted, External)) {
		t.Error("read + untrusted + external is the trifecta")
	}
	if Trifecta(NewSet(Untrusted, External)) {
		t.Error("no private data, no trifecta")
	}
	if Trifecta(NewSet(Read, Secrets, External)) {
		t.Error("no untrusted input, no trifecta")
	}
}

func TestProfileFor(t *testing.T) {
	cases := []struct {
		cmd  string
		args []string
		url  string
		kind string
	}{
		{"npx", []string{"-y", "@modelcontextprotocol/server-filesystem", "/data"}, "", "filesystem"},
		{"uvx", []string{"mcp-server-fetch"}, "", "fetch"},
		{"docker", []string{"run", "-i", "ghcr.io/github/github-mcp-server"}, "", "github"},
		{"npx", []string{"@wonderwhy-er/desktop-commander"}, "", "shell"},
		{"", nil, "https://mcp.slack.example.com/mcp", "slack"},
	}
	for _, c := range cases {
		p, ok := ProfileFor(c.cmd, c.args, c.url)
		if !ok || p.Kind != c.kind {
			t.Errorf("%s %v %s: got %q ok=%v, want %q", c.cmd, c.args, c.url, p.Kind, ok, c.kind)
		}
	}
	if _, ok := ProfileFor("./my-internal-server", nil, ""); ok {
		t.Error("unknown server should not match")
	}
}

func TestK8sClass(t *testing.T) {
	cases := []struct {
		verb, res string
		want      Class
	}{
		{"get", "secrets", Secrets},
		{"create", "pods/exec", Exec},
		{"create", "pods", Exec},
		{"bind", "clusterroles", Admin},
		{"delete", "deployments", Destroy},
		{"patch", "configmaps", Write},
		{"list", "pods", Read},
	}
	for _, c := range cases {
		if got, _ := K8sClass(c.verb, c.res); got != c.want {
			t.Errorf("%s %s = %q, want %q", c.verb, c.res, got, c.want)
		}
	}
}
