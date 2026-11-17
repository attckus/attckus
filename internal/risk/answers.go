package risk

import (
	"strings"

	"github.com/mohitkumar/attckus/internal/capability"
)

// Answer is the reply to one fixed question about what an agent can reach.
type Answer struct {
	Question string   `json:"question"`
	Yes      bool     `json:"yes"`
	Prod     bool     `json:"prod,omitempty"` // some matching grant covers production or all resources
	Evidence []string `json:"evidence,omitempty"`
	Via      string   `json:"via,omitempty"`
}

// question matches grants. Matching is on the action text, which is the
// concrete AWS action, the Kubernetes verb and resource, or the MCP server
// profile note.
type question struct {
	text  string
	match func(Grant) bool
}

func hasAny(s string, subs ...string) bool {
	s = strings.ToLower(s)
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

func fromSource(g Grant, src string, c capability.Class) bool {
	return g.Source == src && g.Class == c
}

var questions = []question{
	{"Can it delete a database?", func(g Grant) bool {
		switch g.Source {
		case "aws":
			return hasAny(g.Text, "rds:delete", "dynamodb:delete", "rds:modifydbinstance")
		case "k8s":
			return g.Class == capability.Destroy && hasAny(g.Text, "statefulsets", "persistentvolumeclaims", "persistentvolumes")
		case "mcp":
			return g.Class == capability.Destroy && hasAny(g.Text, "database")
		}
		return false
	}},
	{"Can it delete AWS resources?", func(g Grant) bool { return fromSource(g, "aws", capability.Destroy) }},
	{"Can it delete Kubernetes resources?", func(g Grant) bool { return fromSource(g, "k8s", capability.Destroy) }},
	{"Can it run compute without a cap (Lambda, EC2, ECS, pods)?", func(g Grant) bool {
		switch g.Source {
		case "aws":
			return hasAny(g.Text, "lambda:invokefunction", "lambda:createfunction", "lambda:updatefunctioncode", "ec2:runinstances", "ecs:runtask")
		case "k8s":
			return g.Class == capability.Exec && hasAny(g.Text, "create pods", "pods/exec", "pods/attach")
		}
		return false
	}},
	{"Can it run commands or code?", func(g Grant) bool { return g.Class == capability.Exec }},
	{"Can it read secrets?", func(g Grant) bool { return g.Class == capability.Secrets }},
	{"Can it give itself more access?", func(g Grant) bool { return g.Class == capability.Admin }},
	{"Can it send data outside the company?", func(g Grant) bool { return g.Class == capability.External }},
}

// Answers evaluates the fixed questions against an agent's grants.
func Answers(gs []Grant) []Answer {
	out := make([]Answer, 0, len(questions))
	for _, q := range questions {
		a := Answer{Question: q.text}
		for _, g := range gs {
			if !q.match(g) {
				continue
			}
			a.Yes = true
			a.Prod = a.Prod || g.Prod
			if a.Via == "" {
				a.Via = g.Via
			}
			if len(a.Evidence) < 3 {
				a.Evidence = append(a.Evidence, g.Text)
			}
		}
		out = append(out, a)
	}
	return out
}
