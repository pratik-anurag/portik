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
	"github.com/pratik-anurag/portik/internal/render"
)

type connAggRow struct {
	RemoteIP string         `json:"remote_ip"`
	Total    int            `json:"total"`
	ByState  map[string]int `json:"by_state,omitempty"`
	Samples  []string       `json:"samples,omitempty"` // remote:port examples (optional)
}

func runConn(args []string) int {
	fs := flag.NewFlagSet("conn", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	// reuse your common flags pattern if present; otherwise keep local
	var proto string
	var docker bool
	var jsonOut bool
	var topN int
	var stateFilter string

	fs.StringVar(&proto, "proto", "tcp", "protocol: tcp|udp (default tcp)")
	fs.BoolVar(&docker, "docker", false, "enable docker mapping (optional)")
	fs.BoolVar(&jsonOut, "json", false, "output JSON")
	fs.IntVar(&topN, "top", 10, "top remote IPs to show")
	fs.StringVar(&stateFilter, "state", "", "filter by TCP state (e.g. ESTABLISHED,TIME_WAIT)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "conn: missing <port>")
		fmt.Fprintln(os.Stderr, "Usage: portik conn <port> [--top 10] [--state ESTABLISHED] [--proto tcp]")
		return 2
	}
	if proto != "tcp" && proto != "udp" {
		fmt.Fprintln(os.Stderr, "conn: invalid --proto (tcp|udp)")
		return 2
	}
	port, err := parsePort(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "conn:", err)
		return 2
	}

	sf := parseStateFilter(stateFilter)

	// Important: IncludeConnections=true to pull established/time_wait/etc
	rep, err := inspect.InspectPort(port, proto, inspect.Options{
		EnableDocker:       docker,
		IncludeConnections: true,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "conn:", err)
		return 1
	}

	agg := aggregateConnections(rep, sf)

	// sort + top
	sort.Slice(agg, func(i, j int) bool {
		if agg[i].Total == agg[j].Total {
			return agg[i].RemoteIP < agg[j].RemoteIP
		}
		return agg[i].Total > agg[j].Total
	})
	if topN > 0 && len(agg) > topN {
		agg = agg[:topN]
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"port":  port,
			"proto": proto,
			"rows":  agg,
		})
		return 0
	}

	fmt.Print(render.ConnTable(port, proto, toRenderConnRows(agg)))

	return 0
}

func parseStateFilter(s string) map[string]bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	out := map[string]bool{}
	for _, t := range strings.Split(s, ",") {
		t = strings.ToUpper(strings.TrimSpace(t))
		if t != "" {
			out[t] = true
		}
	}
	return out
}

func aggregateConnections(rep model.Report, stateFilter map[string]bool) []connAggRow {
	// We avoid tight coupling to the exact connection struct by extracting connections via reflection-ish helpers.
	conns := extractConnectionsAny(rep)

	m := map[string]*connAggRow{}
	for _, c := range conns {
		state := strings.ToUpper(strings.TrimSpace(connState(c)))
		if state == "" {
			state = "UNKNOWN"
		}
		if stateFilter != nil && !stateFilter[state] {
			continue
		}

		rip := strings.TrimSpace(connRemoteIP(c))
		if rip == "" {
			rip = "(unknown)"
		}

		row := m[rip]
		if row == nil {
			row = &connAggRow{RemoteIP: rip, ByState: map[string]int{}}
			m[rip] = row
		}
		row.Total++
		row.ByState[state]++

		// keep a few example endpoints (remote ip:port)
		if len(row.Samples) < 3 {
			rp := connRemotePort(c)
			if rp > 0 {
				row.Samples = append(row.Samples, fmt.Sprintf("%s:%d", rip, rp))
			}
		}
	}

	out := make([]connAggRow, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	return out
}

func toRenderConnRows(in []connAggRow) []render.ConnAggRow {
	out := make([]render.ConnAggRow, 0, len(in))
	for _, r := range in {
		out = append(out, render.ConnAggRow{
			RemoteIP: r.RemoteIP,
			Total:    r.Total,
			ByState:  r.ByState,
			Samples:  r.Samples,
		})
	}
	return out
}
