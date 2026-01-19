package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/pratik-anurag/portik/internal/model"
	"github.com/pratik-anurag/portik/internal/proc"
	"github.com/pratik-anurag/portik/internal/render"
	"github.com/pratik-anurag/portik/internal/sockets"
)

type listenerWithProto struct {
	Proto string
	L     model.Listener
}

func runLint(args []string) int {
	fs := flag.NewFlagSet("lint", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var proto string
	var jsonOut bool
	var severity string

	fs.StringVar(&proto, "proto", "tcp", "protocol: tcp|udp|all")
	fs.BoolVar(&jsonOut, "json", false, "output JSON")
	fs.StringVar(&severity, "min-severity", "info", "minimum severity: info|warn|error")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	var protos []string
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "tcp", "udp":
		protos = []string{strings.ToLower(proto)}
	case "all":
		protos = []string{"tcp", "udp"}
	default:
		fmt.Fprintln(os.Stderr, "lint: invalid --proto (tcp|udp|all)")
		return 2
	}

	minRank, ok := sevRank(severity)
	if !ok {
		fmt.Fprintln(os.Stderr, "lint: invalid --min-severity (info|warn|error)")
		return 2
	}

	// Gather listeners for selected protos
	var listeners []listenerWithProto
	for _, p := range protos {
		ls, err := sockets.ListListeners(p)
		if err != nil {
			fmt.Fprintln(os.Stderr, "lint:", err)
			return 1
		}
		for i := range ls {
			proc.Enrich(&ls[i])
			listeners = append(listeners, listenerWithProto{Proto: p, L: ls[i]})
		}
	}

	findings := lintListeners(listeners)
	// apply min severity filter
	filtered := findings[:0]
	for _, f := range findings {
		r, _ := sevRank(f.Severity)
		if r >= minRank {
			filtered = append(filtered, f)
		}
	}
	findings = filtered

	// stable sort for JSON/table
	sort.Slice(findings, func(i, j int) bool {
		ri, _ := sevRank(findings[i].Severity)
		rj, _ := sevRank(findings[j].Severity)
		if ri != rj {
			return ri > rj // error(2) comes first
		}
		if findings[i].Port != findings[j].Port {
			return findings[i].Port < findings[j].Port
		}
		if findings[i].Proto != findings[j].Proto {
			return findings[i].Proto < findings[j].Proto
		}
		return findings[i].Code < findings[j].Code
	})

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"findings": findings,
		})
		return 0
	}

	fmt.Print(render.LintTable(findings))
	if len(findings) == 0 {
		return 0
	}
	// non-zero if warn/error exists
	max := 0
	for _, f := range findings {
		r, _ := sevRank(f.Severity)
		if r > max {
			max = r
		}
	}
	if max >= 2 {
		return 1
	}
	return 0
}

func sevRank(s string) (int, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "info":
		return 0, true
	case "warn", "warning":
		return 1, true
	case "error":
		return 2, true
	default:
		return 0, false
	}
}

func lintListeners(ls []listenerWithProto) []model.LintFinding {
	// Build indices to support cross-family checks per (proto,port)
	byKey := map[string][]model.Listener{}
	for _, x := range ls {
		k := fmt.Sprintf("%s|%d", x.Proto, x.L.LocalPort)
		byKey[k] = append(byKey[k], x.L)
	}

	var out []model.LintFinding
	for _, x := range ls {
		l := x.L
		p := x.Proto
		port := l.LocalPort
		bind := normalizeBind(l.LocalIP)
		public := isPublicBind(bind)

		// 1) Visibility
		if l.PID <= 0 {
			out = append(out, model.LintFinding{
				Severity: "info",
				Code:     "NO_PID",
				Summary:  "PID not visible (try running with sudo for full details)",
				Proto:    p,
				Port:     port,
				LocalIP:  bind,
				PID:      l.PID,
				ProcName: l.ProcName,
				User:     l.User,
			})
		}

		// 2) Privileged port usage
		if port > 0 && port < 1024 {
			if l.User != "" && !isRootUser(l.User) {
				out = append(out, model.LintFinding{
					Severity: "info",
					Code:     "PRIV_PORT",
					Summary:  "Privileged port in use (<1024)",
					Details:  "Binding to ports below 1024 typically requires root or CAP_NET_BIND_SERVICE.",
					Action:   "If this is expected, ignore. Otherwise consider using a port >=1024.",
					Proto:    p,
					Port:     port,
					LocalIP:  bind,
					PID:      l.PID,
					ProcName: l.ProcName,
					User:     l.User,
				})
			}
		}

		// 3) Public exposure for commonly sensitive services
		if public {
			if isSensitivePort(port) {
				out = append(out, model.LintFinding{
					Severity: "warn",
					Code:     "PUBLIC_SENSITIVE",
					Summary:  "Sensitive service port is publicly bound",
					Details:  "Listener is bound to all interfaces; this may expose the service to your network.",
					Action:   "Bind to 127.0.0.1/::1 or restrict with a firewall/security group.",
					Proto:    p,
					Port:     port,
					LocalIP:  bind,
					PID:      l.PID,
					ProcName: l.ProcName,
					User:     l.User,
				})
			} else if isCommonDevPort(port) {
				out = append(out, model.LintFinding{
					Severity: "info",
					Code:     "PUBLIC_DEV",
					Summary:  "Dev-style port is publicly bound",
					Action:   "Bind to 127.0.0.1/::1 if you only need local access.",
					Proto:    p,
					Port:     port,
					LocalIP:  bind,
					PID:      l.PID,
					ProcName: l.ProcName,
					User:     l.User,
				})
			}
		}

		// 4) Dynamic port range used by long-running services (heuristic)
		if port >= 49152 && port <= 65535 {
			if looksLikeService(l.ProcName) {
				out = append(out, model.LintFinding{
					Severity: "info",
					Code:     "DYNAMIC_RANGE",
					Summary:  "Service is listening on a dynamic/ephemeral port range",
					Details:  "Ports 49152–65535 are commonly used as ephemeral client ports (RFC 6335 range classes).",
					Action:   "Consider using a stable registered port (1024–49151) if clients depend on it.",
					Proto:    p,
					Port:     port,
					LocalIP:  bind,
					PID:      l.PID,
					ProcName: l.ProcName,
					User:     l.User,
				})
			}
		}

		// 5) IPv6-only LISTEN (common confusion)
		if p == "tcp" {
			k := fmt.Sprintf("%s|%d", p, port)
			all := byKey[k]
			if isIPv6Only(all) {
				out = append(out, model.LintFinding{
					Severity: "info",
					Code:     "IPV6_ONLY",
					Summary:  "Port appears to be IPv6-only",
					Details:  "Some clients might fail if they try IPv4 (127.0.0.1) and the service only listens on IPv6.",
					Action:   "If needed, bind on 0.0.0.0/127.0.0.1 too, or enable dual-stack.",
					Proto:    p,
					Port:     port,
					LocalIP:  bind,
					PID:      l.PID,
					ProcName: l.ProcName,
					User:     l.User,
				})
			}
		}
	}

	return dedupeLint(out)
}

func normalizeBind(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return "*"
	}
	return ip
}

func isPublicBind(ip string) bool {
	// "*" comes from wildcard binds in our parsers.
	if ip == "*" {
		return true
	}
	ip = strings.TrimSpace(ip)
	return ip == "0.0.0.0" || ip == "::" || ip == "[::]"
}

func isRootUser(user string) bool {
	user = strings.TrimSpace(user)
	if user == "" {
		return false
	}
	// linux: "root", mac: might show "root"
	if user == "root" {
		return true
	}
	// sometimes ps returns UID 0
	return user == "0"
}

func looksLikeService(procName string) bool {
	p := strings.ToLower(strings.TrimSpace(procName))
	if p == "" {
		return false
	}
	// Ignore common short-lived helpers
	skip := []string{"ssh", "sshd", "systemd", "launchd"}
	for _, s := range skip {
		if p == s {
			return false
		}
	}
	return true
}

func isSensitivePort(port int) bool {
	// A pragmatic list of ports that are commonly sensitive when exposed.
	sensitive := map[int]bool{
		5432:  true, // postgres
		3306:  true, // mysql
		6379:  true, // redis
		9200:  true, // elasticsearch
		27017: true, // mongodb
		11211: true, // memcached
		15672: true, // rabbitmq mgmt
		5672:  true, // rabbitmq
		9092:  true, // kafka
		2181:  true, // zookeeper
	}
	return sensitive[port]
}

func isCommonDevPort(port int) bool {
	dev := map[int]bool{
		3000: true,
		3001: true,
		5173: true,
		8000: true,
		8080: true,
		8081: true,
		5000: true,
		4000: true,
		9229: true, // node inspector
	}
	return dev[port]
}

func isIPv6Only(ls []model.Listener) bool {
	if len(ls) == 0 {
		return false
	}
	hasV4 := false
	hasV6 := false
	for _, l := range ls {
		ip := strings.TrimSpace(l.LocalIP)
		if ip == "" || ip == "0.0.0.0" {
			hasV4 = true
		}
		if strings.Contains(ip, ":") || ip == "::" {
			hasV6 = true
		}
	}
	return hasV6 && !hasV4
}

func dedupeLint(in []model.LintFinding) []model.LintFinding {
	seen := map[string]bool{}
	out := make([]model.LintFinding, 0, len(in))
	for _, f := range in {
		k := fmt.Sprintf("%s|%s|%d|%s|%s", f.Code, f.Proto, f.Port, f.LocalIP, f.ProcName)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	return out
}
