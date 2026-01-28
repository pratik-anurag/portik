package render

import (
	"fmt"
	"sort"
	"strings"

	"github.com/pratik-anurag/portik/internal/graph"
)

type GraphRenderOptions struct {
	Top int
}

func GraphText(g graph.Graph, deps []graph.Dependency, warns []string, opt GraphRenderOptions) string {
	var b strings.Builder
	b.WriteString("Local dependency graph (tcp)\n")

	if len(warns) > 0 {
		b.WriteString("\nWarnings:\n")
		for _, w := range warns {
			b.WriteString("  - " + w + "\n")
		}
	}

	listeners := graphListeners(g)
	b.WriteString("\nListeners:\n")
	if len(listeners) == 0 {
		b.WriteString("  (no listeners)\n")
	} else {
		for _, l := range listeners {
			name := l.procName
			if name == "" {
				name = "unknown"
			}
			fmt.Fprintf(&b, "  %-10s (pid %d) LISTEN %s:%d\n", trunc(name, 10), l.pid, fmtIP(l.ip), l.port)
		}
	}

	deps = graph.TopDependencies(deps, opt.Top)
	b.WriteString("\nDependencies:\n")
	if len(deps) == 0 {
		b.WriteString("  (no dependencies)\n")
	} else {
		for _, d := range deps {
			clientName := d.Client.ProcName
			if clientName == "" {
				clientName = "unknown"
			}
			serverName := d.Server.ProcName
			if serverName == "" {
				serverName = "unknown"
			}
			label := fmt.Sprintf("EST=%d", d.Established)
			if d.TimeWait > 0 {
				label = fmt.Sprintf("%s TW=%d", label, d.TimeWait)
			}
			fmt.Fprintf(&b, "  %s(pid %d) -> %s:%d   %s\n",
				trunc(clientName, 12), d.Client.PID,
				trunc(serverName, 12), d.Port.Port,
				label,
			)
		}
	}

	return b.String()
}

func GraphDOT(deps []graph.Dependency, top int) string {
	deps = graph.TopDependencies(deps, top)
	var b strings.Builder
	b.WriteString("digraph portik {\n")
	for _, d := range deps {
		clientName := d.Client.ProcName
		if clientName == "" {
			clientName = "unknown"
		}
		serverName := d.Server.ProcName
		if serverName == "" {
			serverName = "unknown"
		}
		client := fmt.Sprintf("%s (pid %d)", clientName, d.Client.PID)
		server := fmt.Sprintf("%s (pid %d)", serverName, d.Server.PID)
		label := fmt.Sprintf("%d (%d)", d.Port.Port, d.Established)
		if d.TimeWait > 0 {
			label = fmt.Sprintf("%s TW=%d", label, d.TimeWait)
		}
		fmt.Fprintf(&b, "  %q -> %q [label=%q];\n", client, server, label)
	}
	b.WriteString("}\n")
	return b.String()
}

type listenerRow struct {
	procName string
	pid      int32
	ip       string
	port     int
}

func graphListeners(g graph.Graph) []listenerRow {
	nodes := map[string]graph.Node{}
	for _, n := range g.Nodes {
		nodes[n.ID] = n
	}
	var rows []listenerRow
	for _, e := range g.Edges {
		if e.Type != graph.EdgeListensOn {
			continue
		}
		proc := nodes[e.From]
		port := nodes[e.To]
		if proc.Type != graph.NodeProcess || port.Type != graph.NodePort {
			continue
		}
		rows = append(rows, listenerRow{
			procName: proc.ProcName,
			pid:      proc.PID,
			ip:       port.LocalIP,
			port:     port.Port,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].port == rows[j].port {
			if rows[i].procName == rows[j].procName {
				return rows[i].pid < rows[j].pid
			}
			return rows[i].procName < rows[j].procName
		}
		return rows[i].port < rows[j].port
	})
	return rows
}
