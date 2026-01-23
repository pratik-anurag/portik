package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/pratik-anurag/portik/internal/inspect"
	"github.com/pratik-anurag/portik/internal/model"
	"github.com/pratik-anurag/portik/internal/ports"
	"github.com/pratik-anurag/portik/internal/render"
	"github.com/pratik-anurag/portik/internal/sockets"
)

type scanRow struct {
	Port      int    `json:"port"`
	Proto     string `json:"proto"`
	Status    string `json:"status"` // free|in-use|unknown|error
	Owner     string `json:"owner,omitempty"`
	PID       int32  `json:"pid,omitempty"`
	Addr      string `json:"addr,omitempty"`
	Docker    string `json:"docker,omitempty"`
	Hint      string `json:"hint,omitempty"`
	Error     string `json:"error,omitempty"`
	Signature string `json:"signature,omitempty"`
}

func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	c := parseCommon(fs)

	var portsSpec string
	var concurrency int
	var all bool
	var owner string
	var minPort, maxPort int
	fs.StringVar(&portsSpec, "ports", "", "ports spec: e.g. 5432,6379,3000-3010")
	fs.BoolVar(&all, "all", false, "scan all listening ports on the system")
	fs.IntVar(&concurrency, "concurrency", 0, "number of concurrent checks (default: CPU count, max 32)")
	fs.StringVar(&owner, "owner", "", "filter by owner/process name")
	fs.IntVar(&minPort, "min-port", 0, "minimum port in results (after discovery)")
	fs.IntVar(&maxPort, "max-port", 65535, "maximum port in results (after discovery)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if portsSpec == "" && !all {
		fmt.Fprintln(os.Stderr, "scan: missing --ports or --all (e.g. --ports 5432,6379,3000-3010 or --all)")
		return 2
	}
	if portsSpec != "" && all {
		fmt.Fprintln(os.Stderr, "scan: cannot use both --ports and --all")
		return 2
	}
	if c.Proto != "tcp" && c.Proto != "udp" {
		fmt.Fprintln(os.Stderr, "scan: invalid --proto (tcp|udp)")
		return 2
	}

	var portsList []int
	var err error

	if all {
		// Auto-discover all listening ports
		portsList, err = getAllListeningPorts(c.Proto, minPort, maxPort)
		if err != nil {
			fmt.Fprintf(os.Stderr, "scan: failed to discover ports: %v\n", err)
			return 2
		}
		if len(portsList) == 0 {
			if c.JSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				_ = enc.Encode(map[string]any{
					"proto": c.Proto,
					"ports": []int{},
					"rows":  []scanRow{},
					"count": 0,
				})
			} else {
				fmt.Printf("No %s listeners found in range %d-%d\n", c.Proto, minPort, maxPort)
			}
			return 0
		}
	} else {
		portsList, err = ports.ParseSpec(portsSpec)
		if err != nil {
			fmt.Fprintln(os.Stderr, "scan:", err)
			return 2
		}
	}

	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
	}
	if concurrency > 32 {
		concurrency = 32
	}

	rows := scanPorts(portsList, c.Proto, c.Docker, concurrency)

	// Apply owner filter if specified
	if owner != "" {
		var filtered []scanRow
		for _, r := range rows {
			if strings.Contains(strings.ToLower(r.Owner), strings.ToLower(owner)) {
				filtered = append(filtered, r)
			}
		}
		rows = filtered
	}

	if c.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"proto": c.Proto,
			"ports": portsList,
			"rows":  rows,
			"count": len(rows),
		})
		return 0
	}

	if all {
		inUse := 0
		for _, r := range rows {
			if r.Status == "in-use" {
				inUse++
			}
		}
		fmt.Printf("%d ports in use (discovered via --all)\n\n", inUse)
	}

	fmt.Print(render.ScanTableRows(toRenderRows(rows)))
	return 0
}

func scanPorts(portsList []int, proto string, docker bool, conc int) []scanRow {
	type job struct {
		port int
	}
	jobs := make(chan job)
	out := make([]scanRow, 0, len(portsList))
	var mu sync.Mutex
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		for j := range jobs {
			rep, err := inspect.InspectPort(j.port, proto, inspect.Options{
				EnableDocker:       docker,
				IncludeConnections: false, // fast scan
			})
			row := reportToScanRow(rep, err)
			mu.Lock()
			out = append(out, row)
			mu.Unlock()
		}
	}

	for i := 0; i < conc; i++ {
		wg.Add(1)
		go worker()
	}

	for _, p := range portsList {
		jobs <- job{port: p}
	}
	close(jobs)
	wg.Wait()

	// sort output stable by port
	sortScanRows(out)
	return out
}

func reportToScanRow(rep model.Report, err error) scanRow {
	if err != nil {
		return scanRow{
			Port:   rep.Port,
			Proto:  rep.Proto,
			Status: "error",
			Error:  err.Error(),
		}
	}

	row := scanRow{
		Port:      rep.Port,
		Proto:     rep.Proto,
		Status:    "free",
		Signature: rep.Signature(),
	}

	if l, ok := rep.PrimaryListener(); ok && l.PID > 0 && strings.ToUpper(l.State) == "LISTEN" {
		row.Status = "in-use"
		row.PID = l.PID
		row.Owner = ownerShort(l)
		row.Addr = addrShort(l.LocalIP, l.LocalPort)
	} else if len(rep.Listeners) > 0 {
		row.Status = "unknown"
	}

	if rep.Docker.Mapped {
		if rep.Docker.ComposeService != "" {
			row.Docker = rep.Docker.ContainerName + " (svc=" + rep.Docker.ComposeService + ")"
		} else {
			row.Docker = rep.Docker.ContainerName
		}
	}

	row.Hint = scanHint(rep.Diagnostics)
	return row
}

func scanHint(diags []model.Diagnostic) string {
	// keep scan output short: pick first warn/error, else first info
	for _, d := range diags {
		if d.Severity == "warn" || d.Severity == "error" {
			return d.Summary
		}
	}
	for _, d := range diags {
		if d.Severity == "info" {
			return d.Summary
		}
	}
	return ""
}

func ownerShort(l model.Listener) string {
	if l.ProcName == "" && l.PID > 0 {
		return fmt.Sprintf("pid:%d", l.PID)
	}
	if l.User != "" {
		return l.ProcName + " (" + l.User + ")"
	}
	return l.ProcName
}

func addrShort(ip string, port int) string {
	if strings.TrimSpace(ip) == "" {
		return fmt.Sprintf("*:%d", port)
	}
	if strings.Contains(ip, ":") && !strings.HasPrefix(ip, "[") {
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

func sortScanRows(rows []scanRow) {
	// tiny custom sorter to avoid extra imports in this file
	for i := 0; i < len(rows); i++ {
		for j := i + 1; j < len(rows); j++ {
			if rows[j].Port < rows[i].Port {
				rows[i], rows[j] = rows[j], rows[i]
			}
		}
	}
}

func toRenderRows(in []scanRow) render.ScanRows {
	out := make(render.ScanRows, 0, len(in))
	for _, r := range in {
		out = append(out, struct {
			Port   int
			Proto  string
			Status string
			Owner  string
			PID    int32
			Addr   string
			Docker string
			Hint   string
			Error  string
		}{
			Port: r.Port, Proto: r.Proto, Status: r.Status, Owner: r.Owner,
			PID: r.PID, Addr: r.Addr, Docker: r.Docker, Hint: r.Hint, Error: r.Error,
		})
	}
	return out
}

// getAllListeningPorts discovers all listening ports via OS socket inspection
// and optionally filters by minPort/maxPort range.
func getAllListeningPorts(proto string, minPort, maxPort int) ([]int, error) {
	listeners, err := sockets.ListListeners(proto)
	if err != nil {
		return nil, err
	}

	// Extract unique ports within range, avoiding duplicates
	portMap := make(map[int]bool)
	for _, l := range listeners {
		p := l.LocalPort
		if p >= minPort && p <= maxPort {
			portMap[p] = true
		}
	}

	// Convert to sorted slice
	var result []int
	for p := range portMap {
		result = append(result, p)
	}

	// Simple sort
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j] < result[i] {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	return result, nil
}
