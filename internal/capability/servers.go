package capability

import "strings"

// ServerProfile describes what a known MCP server can do. Matching is on the
// package or command name, so it works for npx, uvx, docker and direct
// binaries alike.
type ServerProfile struct {
	Kind    string
	Classes Set
	Note    string
}

type serverRule struct {
	needles []string
	profile ServerProfile
}

// The order matters: the first rule with a matching needle wins.
var serverRules = []serverRule{
	{[]string{"desktop-commander", "server-shell", "mcp-shell", "shell-server", "terminal", "server-commands"},
		ServerProfile{"shell", NewSet(Exec, Write, Destroy, Read), "runs arbitrary commands on the host"}},
	{[]string{"kubernetes", "kubectl", "k8s"},
		ServerProfile{"kubernetes", NewSet(Exec, Write, Destroy, Secrets, Read), "uses the ambient kubeconfig"}},
	{[]string{"aws-api", "aws-mcp", "awslabs", "server-aws", "aws"},
		ServerProfile{"aws", NewSet(Write, Destroy, Read), "uses ambient AWS credentials"}},
	{[]string{"server-filesystem", "filesystem"},
		ServerProfile{"filesystem", NewSet(Read, Write), "reads and writes files under allowed directories"}},
	{[]string{"server-github", "github-mcp", "github"},
		ServerProfile{"github", NewSet(Read, Write, External, Untrusted), "issues and PRs are attacker-controllable; comments leave the company"}},
	{[]string{"gitlab"},
		ServerProfile{"gitlab", NewSet(Read, Write, External, Untrusted), "issues and MRs are attacker-controllable"}},
	{[]string{"server-slack", "slack"},
		ServerProfile{"slack", NewSet(Read, External), "reads channels and posts messages"}},
	{[]string{"gmail", "email", "imap", "smtp", "outlook"},
		ServerProfile{"email", NewSet(Read, External, Untrusted), "reads inbound mail and sends mail"}},
	{[]string{"server-fetch", "mcp-server-fetch", "fetch"},
		ServerProfile{"fetch", NewSet(Untrusted, External), "reads arbitrary web pages; request URLs can carry data out"}},
	{[]string{"puppeteer", "playwright", "browser", "brave-search", "tavily", "exa-mcp"},
		ServerProfile{"browser", NewSet(Untrusted, External), "browses or searches the web"}},
	{[]string{"server-postgres", "postgres", "mysql", "sqlite", "mongodb", "redis", "database", "supabase"},
		ServerProfile{"database", NewSet(Read, Write), "queries a database"}},
	{[]string{"stripe", "payments"},
		ServerProfile{"payments", NewSet(Read, Write, Destroy), "moves money"}},
}

// ProfileFor guesses a server profile from its command, args and URL.
// It returns ok=false for unknown servers, which the scanner reports as
// "unknown capabilities" rather than guessing.
func ProfileFor(command string, args []string, url string) (ServerProfile, bool) {
	hay := strings.ToLower(command + " " + strings.Join(args, " ") + " " + url)
	for _, r := range serverRules {
		for _, n := range r.needles {
			if strings.Contains(hay, n) {
				p := r.profile
				p.Classes = copySet(p.Classes)
				return p, true
			}
		}
	}
	return ServerProfile{}, false
}

func copySet(s Set) Set {
	out := Set{}
	out.Add(s)
	return out
}
