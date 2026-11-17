// Package report renders scan results as text, JSON, SARIF or Mermaid.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/attckus/attckus/internal/capability"
	"github.com/attckus/attckus/internal/graph"
	"github.com/attckus/attckus/internal/risk"
)

const toolURI = "https://github.com/attckus/attckus"

// Text prints findings grouped by agent.
func Text(w io.Writer, r *risk.Result) {
	if len(r.Agents) == 0 {
		fmt.Fprintln(w, "No agents or MCP servers found.")
		return
	}
	byAgent := map[string][]risk.Finding{}
	for _, f := range r.Findings {
		byAgent[f.Agent] = append(byAgent[f.Agent], f)
	}
	counts := map[risk.Severity]int{}
	for _, a := range r.Agents {
		fmt.Fprintf(w, "■ %s\n", a.Name)
		for _, s := range a.Sources {
			fmt.Fprintf(w, "  %s\n", s)
		}
		if len(a.Capabilities) > 0 {
			fmt.Fprintf(w, "  can: %s\n", joinClasses(a.Capabilities))
		}
		fs := byAgent[a.Name]
		if len(fs) == 0 {
			fmt.Fprintln(w, "  no findings")
		}
		for _, f := range fs {
			counts[f.Severity]++
			cond := ""
			if f.Conditional {
				cond = " (conditional)"
			}
			fmt.Fprintf(w, "\n  %-8s %s  %s%s\n", strings.ToUpper(f.Severity.String()), f.Rule, f.Detail, cond)
			if len(f.Path) > 0 {
				fmt.Fprintf(w, "           path: %s\n", strings.Join(f.Path, " → "))
			}
			for _, e := range f.Evidence {
				fmt.Fprintf(w, "           - %s\n", e)
			}
			fmt.Fprintf(w, "           fix: %s\n", f.Fix)
		}
		fmt.Fprintln(w)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "note: %s\n", n)
	}
	fmt.Fprintf(w, "%d agents, %d findings: %d critical, %d high, %d medium, %d low\n",
		len(r.Agents), len(r.Findings), counts[risk.Critical], counts[risk.High], counts[risk.Medium], counts[risk.Low])
}

func joinClasses(cs []capability.Class) string {
	parts := make([]string, len(cs))
	for i, c := range cs {
		parts[i] = string(c)
	}
	return strings.Join(parts, ", ")
}

// JSON writes the full result.
func JSON(w io.Writer, r *risk.Result) error {
	out := struct {
		Agents   []risk.AgentResult `json:"agents"`
		Findings []risk.Finding     `json:"findings"`
		Notes    []string           `json:"notes,omitempty"`
	}{r.Agents, r.Findings, r.Notes}
	if out.Agents == nil {
		out.Agents = []risk.AgentResult{}
	}
	if out.Findings == nil {
		out.Findings = []risk.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// SARIF writes SARIF 2.1.0 for GitHub code scanning.
func SARIF(w io.Writer, r *risk.Result, version string) error {
	type msg struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID               string            `json:"id"`
		Name             string            `json:"name"`
		ShortDescription msg               `json:"shortDescription"`
		Help             msg               `json:"help"`
		Properties       map[string]string `json:"properties,omitempty"`
	}
	type region struct {
		StartLine int `json:"startLine"`
	}
	type location struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region region `json:"region"`
		} `json:"physicalLocation"`
	}
	type result struct {
		RuleID    string     `json:"ruleId"`
		Level     string     `json:"level"`
		Message   msg        `json:"message"`
		Locations []location `json:"locations,omitempty"`
	}
	var rules []rule
	for _, ri := range risk.Rules {
		rules = append(rules, rule{ID: ri.ID, Name: ri.Name, ShortDescription: msg{ri.Title}, Help: msg{ri.Fix}})
	}
	var results []result
	for _, f := range r.Findings {
		text := f.Detail
		if len(f.Path) > 0 {
			text += ". Path: " + strings.Join(f.Path, " -> ")
		}
		if len(f.Evidence) > 0 {
			text += ". Evidence: " + strings.Join(f.Evidence, "; ")
		}
		res := result{RuleID: f.Rule, Level: level(f.Severity), Message: msg{text}}
		if f.File != "" {
			var loc location
			loc.PhysicalLocation.ArtifactLocation.URI = f.File
			loc.PhysicalLocation.Region = region{StartLine: max(f.Line, 1)}
			res.Locations = []location{loc}
		}
		results = append(results, res)
	}
	if results == nil {
		results = []result{}
	}
	doc := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []any{map[string]any{
			"tool": map[string]any{"driver": map[string]any{
				"name": "attckus", "version": version, "informationUri": toolURI, "rules": rules,
			}},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func level(s risk.Severity) string {
	switch s {
	case risk.Critical, risk.High:
		return "error"
	case risk.Medium:
		return "warning"
	}
	return "note"
}

var unsafeID = regexp.MustCompile(`[^A-Za-z0-9_]`)

// Mermaid draws each agent's reach: identities, MCP servers, and the most
// dangerous capability classes each one grants.
func Mermaid(w io.Writer, r *risk.Result) {
	fmt.Fprintln(w, "flowchart LR")
	fmt.Fprintln(w, "  classDef agent fill:#e8f0fe,stroke:#3367d6")
	fmt.Fprintln(w, "  classDef critical fill:#fde8e8,stroke:#c5221f")
	fmt.Fprintln(w, "  classDef high fill:#fef3e0,stroke:#e37400")
	drawn := map[string]bool{}
	edges := map[string]bool{}
	node := func(id, label, class string) string {
		mid := unsafeID.ReplaceAllString(id, "_")
		if !drawn[mid] {
			drawn[mid] = true
			fmt.Fprintf(w, "  %s[\"%s\"]", mid, escape(label))
			if class != "" {
				fmt.Fprintf(w, ":::%s", class)
			}
			fmt.Fprintln(w)
		}
		return mid
	}
	edge := func(from, to, label string) {
		key := from + ">" + to
		if edges[key] {
			return
		}
		edges[key] = true
		if label != "" {
			fmt.Fprintf(w, "  %s -->|%s| %s\n", from, label, to)
		} else {
			fmt.Fprintf(w, "  %s --> %s\n", from, to)
		}
	}
	for _, a := range r.Agents {
		node("agent:"+a.Name, a.Name, "agent")
		for _, reach := range a.Reach {
			for _, e := range reach.Path {
				from, _ := r.Graph.Node(e.From)
				to, _ := r.Graph.Node(e.To)
				edge(node(from.ID, label(from), kindClass(from)), node(to.ID, label(to), ""), string(e.Kind))
			}
			id := reach.Node.ID
			sums := r.Summaries[id]
			sort.SliceStable(sums, func(i, j int) bool { return sums[i].Class.Rank() < sums[j].Class.Rank() })
			for i, s := range sums {
				if i == 3 || s.Class == capability.Read && i > 0 {
					break
				}
				gid := id + "#" + string(s.Class)
				text := string(s.Class) + ": " + shorten(s.Example, 48)
				if s.Count > 1 {
					text += fmt.Sprintf(" (+%d)", s.Count-1)
				}
				edge(node(id, label(reach.Node), ""), node(gid, text, classFor(s)), "")
			}
		}
	}
}

func label(n graph.Node) string { return n.Label }

func kindClass(n graph.Node) string {
	if n.Kind == graph.Agent {
		return "agent"
	}
	return ""
}

func classFor(s risk.Summary) string {
	switch s.Class {
	case capability.Admin, capability.Exec:
		return "critical"
	case capability.Destroy:
		if s.Prod {
			return "critical"
		}
		return "high"
	case capability.Secrets, capability.External, capability.Untrusted:
		return "high"
	}
	return ""
}

func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func escape(s string) string {
	return strings.NewReplacer(`"`, "'", "<", "‹", ">", "›").Replace(s)
}
