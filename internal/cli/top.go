package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/pratik-anurag/portik/internal/inspect"
	"github.com/pratik-anurag/portik/internal/model"
	"github.com/pratik-anurag/portik/internal/ports"
	"github.com/pratik-anurag/portik/internal/render"
)

type topRow struct {
	Port    int
	Proto   string
	Total   int
	Clients []render.TopClient
}

func runTop(args []string) int {
	fs := flag.NewFlagSet("top", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	c := parseCommon(fs)

	var portsSpec string
	var topN int
	var clientN int

	fs.StringVar(&portsSpec, "ports", "", "ports list/range (e.g., 80,443,3000-3010)")
	fs.IntVar(&topN, "top", 5, "top ports to show")
	fs.IntVar(&clientN, "clients", 3, "top clients per port")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(portsSpec) == "" {
		fmt.Fprintln(os.Stderr, "top: missing --ports")
		return 2
	}
	if c.Proto != "tcp" {
		fmt.Fprintln(os.Stderr, "top: only tcp is supported for connection counts")
		return 2
	}
	portsList, err := ports.ParseSpec(portsSpec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "top:", err)
		return 2
	}

	var rows []topRow
	for _, p := range portsList {
		rep, err := inspect.InspectPort(p, c.Proto, inspect.Options{
			EnableDocker:       c.Docker,
			IncludeConnections: true,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "top: %d: %v\n", p, err)
			continue
		}
		total := len(rep.Connections)
		if total == 0 {
			continue
		}
		clients := topClients(rep.Connections, clientN)
		rows = append(rows, topRow{
			Port:    p,
			Proto:   c.Proto,
			Total:   total,
			Clients: clients,
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Total == rows[j].Total {
			return rows[i].Port < rows[j].Port
		}
		return rows[i].Total > rows[j].Total
	})
	if topN > 0 && len(rows) > topN {
		rows = rows[:topN]
	}

	if c.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"proto": c.Proto,
			"rows":  rows,
		})
		return 0
	}

	opt := renderOptions(c)
	out := make([]render.TopRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, render.TopRow{
			Port:    r.Port,
			Proto:   r.Proto,
			Total:   r.Total,
			Clients: r.Clients,
		})
	}
	fmt.Print(render.TopTable(out, opt))
	return 0
}

func topClients(conns []model.Conn, limit int) []render.TopClient {
	counts := map[string]int{}
	for _, c := range conns {
		ip := strings.TrimSpace(c.RemoteIP)
		if ip == "" {
			ip = "(unknown)"
		}
		counts[ip]++
	}
	var out []render.TopClient
	for ip, n := range counts {
		out = append(out, render.TopClient{IP: ip, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].IP < out[j].IP
		}
		return out[i].Count > out[j].Count
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
