package graph

import (
	"reflect"
	"testing"
)

func TestFromShortestPathsAndCycles(t *testing.T) {
	g := New()
	for _, id := range []string{"agent", "sa", "r1", "r2", "r3", "mcp"} {
		g.AddNode(Node{ID: id, Label: id})
	}
	g.AddEdge(Edge{From: "agent", To: "sa", Kind: RunsAs})
	g.AddEdge(Edge{From: "agent", To: "mcp", Kind: Uses})
	g.AddEdge(Edge{From: "sa", To: "r1", Kind: IRSA})
	g.AddEdge(Edge{From: "r1", To: "r2", Kind: Assumes})
	g.AddEdge(Edge{From: "r2", To: "r1", Kind: Assumes}) // cycle
	g.AddEdge(Edge{From: "r2", To: "r3", Kind: Assumes})
	g.AddEdge(Edge{From: "mcp", To: "r3", Kind: Credentials}) // shorter route to r3
	if g.AddEdge(Edge{From: "agent", To: "ghost"}) {
		t.Error("edge to missing node accepted")
	}

	reach := g.From("agent")
	if len(reach) != 5 {
		t.Fatalf("reached %d nodes, want 5", len(reach))
	}
	var r3 Reach
	for _, r := range reach {
		if r.Node.ID == "r3" {
			r3 = r
		}
	}
	if got, want := g.Labels(r3.Path), []string{"agent", "mcp", "r3"}; !reflect.DeepEqual(got, want) {
		t.Errorf("path to r3 = %v, want shortest %v", got, want)
	}
	if g.From("nope") != nil {
		t.Error("unknown start should return nil")
	}
}
