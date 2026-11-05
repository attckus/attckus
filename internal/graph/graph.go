// Package graph is a small typed directed graph with shortest-path search.
// The risk engine builds one node per agent, MCP server, Kubernetes service
// account and AWS role, and searches outward from each agent.
package graph

import "sort"

type NodeKind string

const (
	Agent          NodeKind = "agent"
	MCPServer      NodeKind = "mcp_server"
	ServiceAccount NodeKind = "service_account"
	AWSRole        NodeKind = "aws_role"
)

type EdgeKind string

const (
	RunsAs      EdgeKind = "runs_as"     // workload -> service account
	IRSA        EdgeKind = "irsa"        // service account -> AWS role
	Assumes     EdgeKind = "assumes"     // role -> role
	Uses        EdgeKind = "uses"        // agent -> MCP server
	Credentials EdgeKind = "credentials" // MCP server -> AWS role (AWS_ROLE_ARN)
)

type Node struct {
	ID    string   `json:"id"`
	Kind  NodeKind `json:"kind"`
	Label string   `json:"label"`
}

type Edge struct {
	From string   `json:"from"`
	To   string   `json:"to"`
	Kind EdgeKind `json:"kind"`
}

type Graph struct {
	nodes map[string]Node
	out   map[string][]Edge
}

func New() *Graph { return &Graph{nodes: map[string]Node{}, out: map[string][]Edge{}} }

// AddNode inserts or replaces a node.
func (g *Graph) AddNode(n Node) { g.nodes[n.ID] = n }

// AddEdge adds an edge; both ends must exist, duplicates are ignored.
func (g *Graph) AddEdge(e Edge) bool {
	if _, ok := g.nodes[e.From]; !ok {
		return false
	}
	if _, ok := g.nodes[e.To]; !ok {
		return false
	}
	for _, x := range g.out[e.From] {
		if x == e {
			return true
		}
	}
	g.out[e.From] = append(g.out[e.From], e)
	return true
}

func (g *Graph) Node(id string) (Node, bool) {
	n, ok := g.nodes[id]
	return n, ok
}

// Reach is a node reachable from a start node, with the shortest path to it.
type Reach struct {
	Node Node
	Path []Edge
}

// From returns every node reachable from start (excluding start itself),
// with a shortest path to each, in breadth-first order. Cycles are safe.
func (g *Graph) From(start string) []Reach {
	if _, ok := g.nodes[start]; !ok {
		return nil
	}
	prev := map[string]Edge{}
	seen := map[string]bool{start: true}
	queue := []string{start}
	var order []string
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		edges := append([]Edge(nil), g.out[cur]...)
		sort.Slice(edges, func(i, j int) bool { return edges[i].To < edges[j].To })
		for _, e := range edges {
			if seen[e.To] {
				continue
			}
			seen[e.To] = true
			prev[e.To] = e
			order = append(order, e.To)
			queue = append(queue, e.To)
		}
	}
	out := make([]Reach, 0, len(order))
	for _, id := range order {
		var path []Edge
		for at := id; at != start; at = prev[at].From {
			path = append([]Edge{prev[at]}, path...)
		}
		out = append(out, Reach{Node: g.nodes[id], Path: path})
	}
	return out
}

// Labels turns a path into human-readable hops, starting with the origin.
func (g *Graph) Labels(path []Edge) []string {
	if len(path) == 0 {
		return nil
	}
	out := []string{g.nodes[path[0].From].Label}
	for _, e := range path {
		out = append(out, g.nodes[e.To].Label)
	}
	return out
}
