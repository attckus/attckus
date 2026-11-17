// Package risk turns an inventory into findings: what each agent can reach
// and how bad that is.
package risk

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/mohitkumar/attckus/internal/capability"
	"github.com/mohitkumar/attckus/internal/graph"
	"github.com/mohitkumar/attckus/internal/inventory"
)

// Severity of a finding.
type Severity int

const (
	Low Severity = iota
	Medium
	High
	Critical
)

var sevNames = []string{"low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s >= Low && s <= Critical {
		return sevNames[s]
	}
	return fmt.Sprintf("severity(%d)", int(s))
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// ParseSeverity accepts low, medium, high or critical.
func ParseSeverity(v string) (Severity, error) {
	for i, n := range sevNames {
		if strings.EqualFold(v, n) {
			return Severity(i), nil
		}
	}
	return Low, fmt.Errorf("unknown severity %q (want low, medium, high or critical)", v)
}

// Rule IDs.
const (
	RuleAdmin    = "FL101"
	RuleExec     = "FL102"
	RuleDestroy  = "FL103"
	RuleSecrets  = "FL104"
	RuleWrite    = "FL105"
	RuleTrifecta = "FL110"
	RuleSecret   = "FL201"
	RuleUnpinned = "FL202"
	RulePlainTxt = "FL203"
	RuleUnknown  = "FL204"
)

// RuleInfo describes a rule for reports and SARIF.
type RuleInfo struct {
	ID, Name, Title, Fix string
}

var Rules = []RuleInfo{
	{RuleAdmin, "agent-can-escalate", "Agent can change permissions or assume other roles", "Remove permission-management and role-assumption rights; an agent should never be able to grant itself more access."},
	{RuleExec, "agent-can-execute", "Agent can execute arbitrary commands or code", "Remove command execution, or run it in a sandbox and gate it with an allowlist in the gateway."},
	{RuleDestroy, "agent-can-destroy", "Agent can delete data or infrastructure", "Scope access to read or write only, add an explicit deny for delete actions, and require approval for destructive tools in the gateway."},
	{RuleSecrets, "agent-can-read-secrets", "Agent can read secrets", "Grant only the specific secrets the agent needs (exact ARNs or resourceNames), never wildcards."},
	{RuleWrite, "agent-can-write", "Agent can modify data", "Narrow write access to the resources this agent owns."},
	{RuleTrifecta, "lethal-trifecta", "Agent has private data, untrusted input and an external channel", "Remove one leg: drop the external channel, move untrusted input to a separate agent with no data access, or require approval for outbound tools."},
	{RuleSecret, "hardcoded-credential", "Credential written into an MCP config", "Reference an environment variable or secret manager instead, and rotate the exposed credential."},
	{RuleUnpinned, "unpinned-mcp-server", "MCP server package is not pinned to a version", "Pin an exact version (pkg@1.2.3, pkg==1.2.3, image@sha256:...) so a compromised release is not pulled on the next start."},
	{RulePlainTxt, "mcp-over-plain-http", "Remote MCP server reached over plain HTTP", "Use https, or keep the server on localhost."},
	{RuleUnknown, "unknown-mcp-server", "MCP server with unknown capabilities", "Review this server's tools, or add a profile for it so it can be classified."},
}

func ruleInfo(id string) RuleInfo {
	for _, r := range Rules {
		if r.ID == id {
			return r
		}
	}
	return RuleInfo{ID: id}
}

// Finding is one risk, with the path that creates it.
type Finding struct {
	Rule        string   `json:"rule"`
	Severity    Severity `json:"severity"`
	Agent       string   `json:"agent"`
	Title       string   `json:"title"`
	Detail      string   `json:"detail"`
	Path        []string `json:"path,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
	File        string   `json:"file,omitempty"`
	Line        int      `json:"line,omitempty"`
	Fix         string   `json:"fix"`
	Conditional bool     `json:"conditional,omitempty"`
}

// Summary is one capability class an identity grants, for graph output.
type Summary struct {
	Class   capability.Class `json:"class"`
	Example string           `json:"example"`
	Count   int              `json:"count"`
	Prod    bool             `json:"prod"`
}

// AgentResult is everything known about one agent.
type AgentResult struct {
	Name         string             `json:"name"`
	Kind         string             `json:"kind"`
	Sources      []string           `json:"sources"`
	Capabilities []capability.Class `json:"capabilities"`
	Reach        []graph.Reach      `json:"-"`
	// Grants is every permission the agent can reach, with where it comes from.
	Grants []Grant `json:"grants,omitempty"`
	// Answers is the fixed list of "can it ...?" questions for this agent.
	Answers []Answer `json:"answers,omitempty"`
}

// Grant is one permission an agent can reach.
type Grant struct {
	Class       capability.Class `json:"class"`
	Text        string           `json:"text"`
	Source      string           `json:"source"` // aws, k8s or mcp
	Via         string           `json:"via"`    // the identity or server that holds it
	Prod        bool             `json:"prod,omitempty"`
	Conditional bool             `json:"conditional,omitempty"`
}

// Result of an analysis.
type Result struct {
	Agents    []AgentResult        `json:"agents"`
	Findings  []Finding            `json:"findings"`
	Notes     []string             `json:"notes,omitempty"`
	Graph     *graph.Graph         `json:"-"`
	Summaries map[string][]Summary `json:"-"` // by graph node ID
}

var prodRe = regexp.MustCompile(`(?i)(^|[^a-z])prod(uction)?([^a-z]|$)`)

// IsProd reports whether a resource or namespace name looks like production.
func IsProd(s string) bool { return prodRe.MatchString(s) }

// grant is a normalised permission from any source.
type grant struct {
	class       capability.Class
	text        string
	prod        bool
	conditional bool
	source      string // aws, k8s or mcp
}

// Analyze builds the graph and findings for an inventory.
func Analyze(inv *inventory.Inventory) *Result {
	b := &builder{inv: inv, g: graph.New(), grants: map[string][]grant{}, notes: map[string]bool{}}
	res := &Result{Graph: b.g, Summaries: map[string][]Summary{}}
	for _, a := range inv.Agents {
		b.addAgent(a)
	}
	for _, a := range inv.Agents {
		ar, fs := b.evaluate(a)
		res.Agents = append(res.Agents, ar)
		res.Findings = append(res.Findings, fs...)
		res.Findings = append(res.Findings, hygiene(a)...)
	}
	for id, gs := range b.grants {
		res.Summaries[id] = summarize(gs)
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		a, c := res.Findings[i], res.Findings[j]
		if a.Severity != c.Severity {
			return a.Severity > c.Severity
		}
		if a.Agent != c.Agent {
			return a.Agent < c.Agent
		}
		return a.Rule < c.Rule
	})
	if inv.AWS != nil {
		b.notes["IAM evaluation is simplified: SCPs, permission boundaries, session and resource-based policies are not modelled; conditional grants are marked."] = true
	}
	for n := range b.notes {
		res.Notes = append(res.Notes, n)
	}
	sort.Strings(res.Notes)
	return res
}

type builder struct {
	inv    *inventory.Inventory
	g      *graph.Graph
	grants map[string][]grant // by node ID
	notes  map[string]bool
}

func agentID(name string) string { return "agent:" + name }

func (b *builder) addAgent(a *inventory.Agent) {
	id := agentID(a.Name)
	b.g.AddNode(graph.Node{ID: id, Kind: graph.Agent, Label: a.Name})
	if w := a.Workload; w != nil {
		saID := "sa:" + w.Namespace + "/" + w.ServiceAccount
		b.g.AddNode(graph.Node{ID: saID, Kind: graph.ServiceAccount, Label: "sa " + w.Namespace + "/" + w.ServiceAccount})
		b.g.AddEdge(graph.Edge{From: id, To: saID, Kind: graph.RunsAs})
		if w.AutomountToken {
			b.addK8sGrants(saID, w.Namespace, w.ServiceAccount)
		}
		if arn := b.inv.K8s.IRSARole(w.Namespace, w.ServiceAccount); arn != "" {
			b.g.AddEdge(graph.Edge{From: saID, To: b.addRole(arn), Kind: graph.IRSA})
		}
	}
	for _, s := range a.Servers {
		sid := "mcp:" + a.Name + "/" + s.Name
		b.g.AddNode(graph.Node{ID: sid, Kind: graph.MCPServer, Label: "mcp " + s.Name})
		b.g.AddEdge(graph.Edge{From: id, To: sid, Kind: graph.Uses})
		if s.Known {
			for _, c := range s.Profile.Classes.Sorted() {
				b.grants[sid] = append(b.grants[sid], grant{class: c, text: s.Kind + " server: " + s.Profile.Note, source: "mcp"})
			}
		}
		if s.AWSRole != "" {
			b.g.AddEdge(graph.Edge{From: sid, To: b.addRole(s.AWSRole), Kind: graph.Credentials})
		}
	}
}

func (b *builder) addK8sGrants(saID, ns, name string) {
	if _, done := b.grants[saID]; done {
		return
	}
	b.grants[saID] = []grant{}
	for _, kg := range b.inv.K8s.Grants(ns, name) {
		scope := "cluster-wide"
		if kg.Namespace != "" {
			scope = "in ns " + kg.Namespace
		}
		res := kg.Resource
		if len(kg.ResourceNames) > 0 {
			res += "/" + strings.Join(kg.ResourceNames, ",")
		}
		b.grants[saID] = append(b.grants[saID], grant{
			class: kg.Class, text: fmt.Sprintf("%s %s %s (%s)", kg.Verb, res, scope, kg.Via),
			prod: kg.Namespace == "" || IsProd(kg.Namespace), source: "k8s",
		})
	}
}

// addRole adds a role node and, recursively, the roles it can assume.
func (b *builder) addRole(arn string) string {
	id := "role:" + arn
	if _, ok := b.g.Node(id); ok {
		return id
	}
	name := arn[strings.LastIndex(arn, "/")+1:]
	b.g.AddNode(graph.Node{ID: id, Kind: graph.AWSRole, Label: "role " + name})
	if b.inv.AWS == nil {
		b.notes["Agents use AWS roles but no IAM snapshot was found; export one with `aws iam get-account-authorization-details --output json` to resolve them."] = true
		return id
	}
	role, ok := b.inv.AWS.Role(arn)
	if !ok {
		b.notes[fmt.Sprintf("Role %s is referenced but not in the IAM snapshot.", arn)] = true
		return id
	}
	var gs []grant
	for _, ag := range b.inv.AWS.Grants(role) {
		gs = append(gs, grant{
			class: ag.Class, text: fmt.Sprintf("%s on %s (%s)", ag.Action, ag.Resource, ag.Via),
			prod:        ag.Resource == "*" || IsProd(ag.Resource) || IsProd(role.Tags["env"]) || IsProd(role.Tags["environment"]),
			conditional: ag.Conditional, source: "aws",
		})
	}
	b.grants[id] = gs
	for _, target := range b.inv.AWS.AssumableRoles(role) {
		b.g.AddEdge(graph.Edge{From: id, To: b.addRole(target.ARN), Kind: graph.Assumes})
	}
	return id
}

// classes that produce their own finding, most severe first.
var findingClasses = []struct {
	class capability.Class
	rule  string
}{
	{capability.Admin, RuleAdmin}, {capability.Exec, RuleExec}, {capability.Destroy, RuleDestroy},
	{capability.Secrets, RuleSecrets}, {capability.Write, RuleWrite},
}

func (b *builder) evaluate(a *inventory.Agent) (AgentResult, []finding) {
	file, line := a.Location()
	ar := AgentResult{Name: a.Name, Kind: a.Kind, Sources: sources(a)}
	reach := b.g.From(agentID(a.Name))
	ar.Reach = reach

	caps := capability.Set{}
	legs := map[capability.Class][]string{} // trifecta leg -> where it comes from
	candidates := map[capability.Class][]candidate{}
	var out []finding
	for _, r := range reach {
		gs := b.grants[r.Node.ID]
		if len(gs) == 0 {
			continue
		}
		byClass := map[capability.Class][]grant{}
		for _, g := range gs {
			ar.Grants = append(ar.Grants, Grant{Class: g.class, Text: g.text, Source: g.source, Via: r.Node.Label, Prod: g.prod, Conditional: g.conditional})
			byClass[g.class] = append(byClass[g.class], g)
			caps[g.class] = true
			legs[g.class] = appendOnce(legs[g.class], r.Node.Label)
		}
		for _, fc := range findingClasses {
			group := byClass[fc.class]
			if len(group) == 0 {
				continue
			}
			sev, prod, allCond := classSeverity(fc.class, group)
			candidates[fc.class] = append(candidates[fc.class], candidate{
				sev: sev, prod: prod, allCond: allCond, label: r.Node.Label,
				path: b.g.Labels(r.Path), group: group,
			})
		}
	}
	// One finding per risk class: the worst route, with the others listed.
	for _, fc := range findingClasses {
		cs := candidates[fc.class]
		if len(cs) == 0 {
			continue
		}
		sort.SliceStable(cs, func(i, j int) bool {
			if cs[i].sev != cs[j].sev {
				return cs[i].sev > cs[j].sev
			}
			return len(cs[i].group) > len(cs[j].group)
		})
		best := cs[0]
		info := ruleInfo(fc.rule)
		f := finding{
			Rule: fc.rule, Severity: best.sev, Agent: a.Name, Title: info.Title,
			Detail:   fmt.Sprintf("%s can %s via %s", a.Name, verbFor(fc.class), best.label),
			Path:     best.path,
			Evidence: evidence(best.group),
			File:     file, Line: line, Fix: info.Fix, Conditional: best.allCond,
		}
		if best.prod && (fc.class == capability.Destroy || fc.class == capability.Write) {
			f.Detail += ", including production resources"
		}
		if len(cs) > 1 {
			var others []string
			for _, c := range cs[1:] {
				others = append(others, c.label)
			}
			f.Detail += "; also via " + strings.Join(others, ", ")
		}
		out = append(out, f)
	}
	ar.Capabilities = caps.Sorted()
	ar.Answers = Answers(ar.Grants)
	if capability.Trifecta(caps) {
		private := append(append(append([]string{}, legs[capability.Read]...), legs[capability.Secrets]...), legs[capability.Destroy]...)
		info := ruleInfo(RuleTrifecta)
		out = append(out, finding{
			Rule: RuleTrifecta, Severity: Critical, Agent: a.Name, Title: info.Title,
			Detail: fmt.Sprintf("%s combines private data (%s), untrusted input (%s) and an external channel (%s); one injected document can make it read and send the data",
				a.Name, strings.Join(firstN(dedupe(private), 3), ", "), strings.Join(legs[capability.Untrusted], ", "), strings.Join(legs[capability.External], ", ")),
			File: file, Line: line, Fix: info.Fix,
		})
	}
	return ar, out
}

type finding = Finding

// candidate is one identity's contribution to a risk class.
type candidate struct {
	sev     Severity
	prod    bool
	allCond bool
	label   string
	path    []string
	group   []grant
}

func classSeverity(c capability.Class, gs []grant) (Severity, bool, bool) {
	prod, allCond := false, true
	for _, g := range gs {
		prod = prod || g.prod
		allCond = allCond && g.conditional
	}
	var sev Severity
	switch c {
	case capability.Admin, capability.Exec:
		sev = Critical
	case capability.Destroy:
		sev = High
		if prod {
			sev = Critical
		}
	case capability.Secrets:
		sev = High
	case capability.Write:
		sev = Medium
		if prod {
			sev = High
		}
	default:
		sev = Low
	}
	if allCond && sev > Low {
		sev-- // a condition may limit the grant; still reported
	}
	return sev, prod, allCond
}

func verbFor(c capability.Class) string {
	switch c {
	case capability.Admin:
		return "change permissions or assume other roles"
	case capability.Exec:
		return "execute commands"
	case capability.Destroy:
		return "delete data or infrastructure"
	case capability.Secrets:
		return "read secrets"
	case capability.Write:
		return "modify data"
	}
	return string(c)
}

func evidence(gs []grant) []string {
	var out []string
	for i, g := range gs {
		if i == 4 {
			out = append(out, fmt.Sprintf("and %d more", len(gs)-4))
			break
		}
		t := g.text
		if g.conditional {
			t += " [conditional]"
		}
		out = append(out, t)
	}
	return out
}

func summarize(gs []grant) []Summary {
	m := map[capability.Class]*Summary{}
	for _, g := range gs {
		s, ok := m[g.class]
		if !ok {
			s = &Summary{Class: g.class, Example: g.text}
			m[g.class] = s
		}
		s.Count++
		if g.prod && !s.Prod {
			s.Prod, s.Example = true, g.text
		}
	}
	var out []Summary
	for _, s := range m {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Class.Rank() < out[j].Class.Rank() })
	return out
}

// hygiene checks MCP config problems that do not depend on the graph.
func hygiene(a *inventory.Agent) []Finding {
	var out []Finding
	for _, s := range a.Servers {
		for _, sec := range s.Secrets {
			info := ruleInfo(RuleSecret)
			out = append(out, Finding{Rule: RuleSecret, Severity: High, Agent: a.Name, Title: info.Title,
				Detail: fmt.Sprintf("server %q has a literal credential in %s (%s)", s.Name, sec.Key, sec.Redacted),
				File:   s.File, Line: s.Line, Fix: info.Fix})
		}
		if !s.Pinned {
			info := ruleInfo(RuleUnpinned)
			out = append(out, Finding{Rule: RuleUnpinned, Severity: Medium, Agent: a.Name, Title: info.Title,
				Detail: fmt.Sprintf("server %q runs %s without a fixed version", s.Name, s.Package),
				File:   s.File, Line: s.Line, Fix: info.Fix})
		}
		if strings.HasPrefix(s.URL, "http://") && !isLocal(s.URL) {
			info := ruleInfo(RulePlainTxt)
			out = append(out, Finding{Rule: RulePlainTxt, Severity: Medium, Agent: a.Name, Title: info.Title,
				Detail: fmt.Sprintf("server %q at %s; tool calls and credentials travel unencrypted", s.Name, s.URL),
				File:   s.File, Line: s.Line, Fix: info.Fix})
		}
		if !s.Known {
			info := ruleInfo(RuleUnknown)
			target := s.Package
			if target == "" {
				target = s.Command + s.URL
			}
			out = append(out, Finding{Rule: RuleUnknown, Severity: Low, Agent: a.Name, Title: info.Title,
				Detail: fmt.Sprintf("server %q (%s) is not in the capability catalogue; its blast radius is not counted", s.Name, target),
				File:   s.File, Line: s.Line, Fix: info.Fix})
		}
	}
	return out
}

func isLocal(u string) bool {
	host := strings.TrimPrefix(u, "http://")
	host = strings.SplitN(host, "/", 2)[0]
	host = strings.SplitN(host, ":", 2)[0]
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]"
}

func sources(a *inventory.Agent) []string {
	var out []string
	if a.Code != nil {
		out = append(out, "code "+a.Code.Dir+" ("+strings.Join(append(append([]string{}, a.Code.Frameworks...), a.Code.Providers...), ", ")+")")
	}
	if w := a.Workload; w != nil {
		out = append(out, fmt.Sprintf("k8s %s %s/%s", w.Kind, w.Namespace, w.Name))
	}
	files := map[string]bool{}
	for _, s := range a.Servers {
		if !files[s.File] {
			files[s.File] = true
			out = append(out, "mcp config "+s.File)
		}
	}
	return out
}

func appendOnce(xs []string, x string) []string {
	for _, v := range xs {
		if v == x {
			return xs
		}
	}
	return append(xs, x)
}

func dedupe(xs []string) []string {
	var out []string
	for _, x := range xs {
		out = appendOnce(out, x)
	}
	return out
}

func firstN(xs []string, n int) []string {
	if len(xs) > n {
		return xs[:n]
	}
	return xs
}
