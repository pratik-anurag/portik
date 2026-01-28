package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/pratik-anurag/portik/internal/graph"
	"github.com/pratik-anurag/portik/internal/render"
)

func runGraph(args []string) int {
	fs := flag.NewFlagSet("graph", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var portsStr string
	var localOnly bool
	var topN int
	var dotOut bool
	var jsonOut bool

	fs.StringVar(&portsStr, "ports", "", "focus only on these ports (comma-separated)")
	fs.BoolVar(&localOnly, "local-only", true, "only include local dependencies")
	fs.IntVar(&topN, "top", 50, "limit dependency edges (default 50)")
	fs.BoolVar(&dotOut, "dot", false, "output Graphviz DOT")
	fs.BoolVar(&jsonOut, "json", false, "output JSON")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "graph: unexpected arguments")
		return 2
	}

	var ports []int
	if portsStr != "" {
		p, err := parsePortsList(portsStr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "graph:", err)
			return 2
		}
		ports = p
	}

	g, deps, warns, err := graph.Build("tcp", graph.Options{
		Ports:     ports,
		LocalOnly: localOnly,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "graph:", err)
		return 1
	}

	if jsonOut {
		topDeps := graph.TopDependencies(deps, topN)
		g = filterGraphEdges(g, topDeps)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(g)
		for _, w := range warns {
			fmt.Fprintln(os.Stderr, "graph warning:", w)
		}
		return 0
	}

	if dotOut {
		fmt.Print(render.GraphDOT(deps, topN))
		for _, w := range warns {
			fmt.Fprintln(os.Stderr, "graph warning:", w)
		}
		return 0
	}

	fmt.Print(render.GraphText(g, deps, warns, render.GraphRenderOptions{Top: topN}))
	return 0
}

func filterGraphEdges(g graph.Graph, deps []graph.Dependency) graph.Graph {
	keepConnect := map[string]bool{}
	for _, d := range deps {
		key := d.Client.ID + "|" + d.Port.ID + "|" + string(graph.EdgeConnectsTo)
		keepConnect[key] = true
	}
	edges := make([]graph.Edge, 0, len(g.Edges))
	nodeUsed := map[string]bool{}
	for _, e := range g.Edges {
		if e.Type == graph.EdgeConnectsTo {
			key := e.From + "|" + e.To + "|" + string(e.Type)
			if !keepConnect[key] {
				continue
			}
		}
		edges = append(edges, e)
		nodeUsed[e.From] = true
		nodeUsed[e.To] = true
	}
	nodes := make([]graph.Node, 0, len(g.Nodes))
	for _, n := range g.Nodes {
		if nodeUsed[n.ID] {
			nodes = append(nodes, n)
		}
	}
	return graph.Graph{Nodes: nodes, Edges: edges}
}
