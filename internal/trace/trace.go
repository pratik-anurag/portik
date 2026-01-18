package trace

import (
	"fmt"
	"sort"
	"strings"

	"github.com/pratik-anurag/portik/internal/model"
	"github.com/pratik-anurag/portik/internal/proctree"
)

type Step struct {
	Kind    string `json:"kind"`
	Summary string `json:"summary"`
	Details string `json:"details,omitempty"`
}

func Steps(rep model.Report, chain []proctree.Proc, started proctree.StartedBy) []Step {
	var out []Step

	if len(rep.Listeners) == 0 {
		return []Step{{Kind: "no-listener", Summary: "No listeners detected for this port"}}
	}

	if l, ok := rep.PrimaryListener(); ok {
		out = append(out, Step{
			Kind:    "listener",
			Summary: fmt.Sprintf("Listener pid=%d %s", l.PID, procLabel(l.ProcName, l.User)),
			Details: fmt.Sprintf("Address %s:%d %s", ipOrStar(l.LocalIP), l.LocalPort, strings.ToUpper(l.State)),
		})
		if isLoopback(l.LocalIP) {
			out = append(out, Step{
				Kind:    "loopback",
				Summary: "Listener is bound to loopback only",
				Details: "External hosts will not reach this port unless it binds to 0.0.0.0 or [::].",
			})
		}
	}

	if rep.Docker.Mapped {
		out = append(out, Step{
			Kind:    "docker",
			Summary: fmt.Sprintf("Docker mapping to %s (%s)", rep.Docker.ContainerName, rep.Docker.ContainerID),
			Details: fmt.Sprintf("Service=%s containerPort=%s", dash(rep.Docker.ComposeService), rep.Docker.ContainerPort),
		})
	}

	if len(chain) > 0 {
		out = append(out, Step{
			Kind:    "process-chain",
			Summary: "Process chain",
			Details: chainSummary(chain, 5),
		})
	}

	if started.Kind != "" && started.Kind != "unknown" {
		out = append(out, Step{
			Kind:    "started-by",
			Summary: fmt.Sprintf("Started by %s", started.Kind),
			Details: started.Details,
		})
	}

	if len(rep.Connections) > 0 {
		total := len(rep.Connections)
		top := topClients(rep.Connections, 3)
		out = append(out, Step{
			Kind:    "connections",
			Summary: fmt.Sprintf("%d active connections", total),
			Details: fmt.Sprintf("Top clients: %s", top),
		})
	}

	if l, ok := rep.PrimaryListener(); ok {
		if isDockerProxy(l.ProcName, l.Cmdline) {
			out = append(out, Step{
				Kind:    "proxy",
				Summary: "Docker proxy appears to own the listener",
				Details: "The real service may be inside the container.",
			})
		}
	}

	return out
}

func procLabel(name, user string) string {
	if name == "" {
		name = "unknown"
	}
	if user != "" {
		return fmt.Sprintf("%s (%s)", name, user)
	}
	return name
}

func ipOrStar(ip string) string {
	if strings.TrimSpace(ip) == "" {
		return "*"
	}
	return ip
}

func isLoopback(ip string) bool {
	if ip == "127.0.0.1" || ip == "::1" {
		return true
	}
	if strings.HasPrefix(ip, "127.") {
		return true
	}
	return false
}

func chainSummary(chain []proctree.Proc, max int) string {
	if len(chain) == 0 {
		return "-"
	}
	if max <= 0 || max > len(chain) {
		max = len(chain)
	}
	var parts []string
	for i := 0; i < max; i++ {
		p := chain[i]
		name := strings.TrimSpace(p.Name)
		if name == "" {
			name = "?"
		}
		parts = append(parts, fmt.Sprintf("%s(%d)", name, p.PID))
	}
	if max < len(chain) {
		parts = append(parts, "...")
	}
	return strings.Join(parts, " <- ")
}

func topClients(conns []model.Conn, limit int) string {
	counts := map[string]int{}
	for _, c := range conns {
		ip := strings.TrimSpace(c.RemoteIP)
		if ip == "" {
			ip = "(unknown)"
		}
		counts[ip]++
	}
	type kv struct {
		IP    string
		Count int
	}
	var rows []kv
	for ip, n := range counts {
		rows = append(rows, kv{IP: ip, Count: n})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count == rows[j].Count {
			return rows[i].IP < rows[j].IP
		}
		return rows[i].Count > rows[j].Count
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	var parts []string
	for _, r := range rows {
		parts = append(parts, fmt.Sprintf("%s(%d)", r.IP, r.Count))
	}
	return strings.Join(parts, ", ")
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func isDockerProxy(name, cmdline string) bool {
	name = strings.ToLower(name)
	cmdline = strings.ToLower(cmdline)
	return strings.Contains(name, "docker-proxy") || strings.Contains(cmdline, "docker-proxy")
}
