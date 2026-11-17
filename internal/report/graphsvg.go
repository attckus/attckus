package report

import (
	"fmt"
	"html/template"
	"sort"
	"strings"

	"github.com/attckus/attckus/internal/capability"
	"github.com/attckus/attckus/internal/graph"
	"github.com/attckus/attckus/internal/risk"
)

// Reach graph layout: a left-to-right tree of the shortest paths from the
// agent to every identity and server it can reach, with the capability
// classes each one grants in a final column. Rows are assigned depth first;
// a node's own capability rows come before its children's rows, so the long
// edges to the capability column never cross another node.
const (
	colW   = 190 // width of a node column, including the gap
	nodeW  = 165
	nodeH  = 30
	rowH   = 40
	chipW  = 290
	padX   = 12
	padY   = 12
	maxCap = 4 // capability chips per node
)

type svgNode struct {
	id, label, kind string
	depth           int
	children        []*svgNode
	chips           []risk.Summary
	top, rows       int // first row and row count of the node's block
	edge            graph.EdgeKind
}

// ReachSVG draws one agent's reach as an inline SVG.
func ReachSVG(r *risk.Result, a risk.AgentResult) template.HTML {
	root := &svgNode{id: "agent:" + a.Name, label: a.Name, kind: string(graph.Agent)}
	byID := map[string]*svgNode{root.id: root}
	maxDepth := 0
	for _, re := range a.Reach { // breadth-first, so parents come first
		if len(re.Path) == 0 {
			continue
		}
		last := re.Path[len(re.Path)-1]
		parent := byID[last.From]
		if parent == nil {
			continue
		}
		n := &svgNode{id: re.Node.ID, label: re.Node.Label, kind: string(re.Node.Kind), depth: len(re.Path), edge: last.Kind}
		parent.children = append(parent.children, n)
		byID[n.id] = n
		maxDepth = max(maxDepth, n.depth)
	}
	for _, n := range byID {
		n.chips = chipsFor(r.Summaries[n.id])
	}
	var place func(n *svgNode, top int) int
	place = func(n *svgNode, top int) int {
		n.top = top
		row := top + len(n.chips)
		for _, c := range n.children {
			row += place(c, row)
		}
		n.rows = max(1, row-top)
		return n.rows
	}
	rows := place(root, 0)

	capX := padX + (maxDepth+1)*colW
	width := capX + chipW + padX
	height := padY*2 + rows*rowH
	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="reach" viewBox="0 0 %d %d" width="%d" height="%d" role="img" aria-label="%s">`,
		width, height, width, height, template.HTMLEscapeString("What "+a.Name+" can reach"))
	b.WriteString(`<title>` + template.HTMLEscapeString("What "+a.Name+" can reach") + `</title>`)

	nodeY := func(n *svgNode) int { // vertical centre of the node's first row
		return padY + n.top*rowH + rowH/2
	}
	nodeX := func(n *svgNode) int { return padX + n.depth*colW }
	curve := func(x1, y1, x2, y2 int, class, title string) {
		mx := (x1 + x2) / 2
		fmt.Fprintf(&b, `<path class="edge %s" d="M%d %d C%d %d %d %d %d %d"><title>%s</title></path>`,
			class, x1, y1, mx, y1, mx, y2, x2, y2, template.HTMLEscapeString(title))
	}
	var draw func(n *svgNode)
	draw = func(n *svgNode) {
		x, y := nodeX(n), nodeY(n)
		for _, c := range n.children {
			curve(x+nodeW, y, nodeX(c), nodeY(c), "", string(c.edge)+": "+n.label+" → "+c.label)
			draw(c)
		}
		for i, s := range n.chips {
			cy := padY + (n.top+i)*rowH + rowH/2
			sev := chipSeverity(s)
			curve(x+nodeW, y, capX, cy, "cap", n.label+" grants "+string(s.Class))
			text := string(s.Class) + " · " + s.Example
			if s.Count > 1 {
				text += fmt.Sprintf(" (+%d)", s.Count-1)
			}
			fmt.Fprintf(&b, `<g class="chip sev-%s"><rect x="%d" y="%d" width="%d" height="%d" rx="4"/><text x="%d" y="%d">%s</text><title>%s</title></g>`,
				sev, capX, cy-nodeH/2, chipW, nodeH, capX+10, cy+4,
				template.HTMLEscapeString(shorten(text, 42)), template.HTMLEscapeString(sev+": "+text))
		}
		fmt.Fprintf(&b, `<g class="node kind-%s"><rect x="%d" y="%d" width="%d" height="%d" rx="6"/><text x="%d" y="%d">%s</text><title>%s</title></g>`,
			n.kind, x, y-nodeH/2, nodeW, nodeH, x+10, y+4,
			template.HTMLEscapeString(shorten(n.label, 24)), template.HTMLEscapeString(strings.ReplaceAll(n.kind, "_", " ")+": "+n.label))
	}
	draw(root)
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

// chipsFor picks the most dangerous classes a node grants; read is shown
// only when nothing else is.
func chipsFor(sums []risk.Summary) []risk.Summary {
	out := append([]risk.Summary(nil), sums...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Class.Rank() < out[j].Class.Rank() })
	if len(out) > 1 && out[len(out)-1].Class == capability.Read {
		out = out[:len(out)-1]
	}
	if len(out) > maxCap {
		out = out[:maxCap]
	}
	return out
}

// chipSeverity maps a capability to the report's status scale.
func chipSeverity(s risk.Summary) string {
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
	case capability.Write:
		return "medium"
	}
	return "low"
}
