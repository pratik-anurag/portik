package render

import (
	"fmt"
	"strings"

	"portik/internal/model"
	"portik/internal/proctree"
	"portik/internal/sys"
)

type Options struct {
	Color   bool
	Summary bool
	Verbose bool
	NoHints bool
}

func Who(rep model.Report, opt Options) string {
	opt = normalizeOptions(opt)
	var b strings.Builder
	fmt.Fprintf(&b, "%s %d/%s\n", label("Port", opt), rep.Port, rep.Proto)

	if len(rep.Listeners) == 0 {
		b.WriteString("  (no listeners found)\n")
	} else {
		if opt.Summary {
			l, ok := rep.PrimaryListener()
			if ok {
				fmt.Fprintf(&b, "%-7s %-24s pid=%d  user=%s  %-12s\n",
					stateLabel(l.State, opt),
					fmt.Sprintf("%s:%d", fmtIP(l.LocalIP), l.LocalPort),
					l.PID,
					dash(l.User),
					dash(l.ProcName),
				)
			}
		} else {
			for _, l := range rep.Listeners {
				fmt.Fprintf(&b, "%-7s %-24s pid=%d  user=%s  %-12s %s\n",
					stateLabel(l.State, opt),
					fmt.Sprintf("%s:%d", fmtIP(l.LocalIP), l.LocalPort),
					l.PID,
					dash(l.User),
					dash(l.ProcName),
					dash(l.Cmdline),
				)
			}
		}
		if !opt.Summary {
			maxDepth := 4
			if opt.Verbose {
				maxDepth = 6
			}
			if l, ok := rep.PrimaryListener(); ok && l.PID > 0 {
				chain, _ := proctree.Build(l.PID, maxDepth)
				if len(chain) > 1 {
					fmt.Fprintf(&b, "\nOwner chain (best-effort): %s\n", fmtProcChain(chain, maxDepth))
				}
			}
		}
	}

	if rep.Docker.Checked {
		if rep.Docker.Mapped {
			fmt.Fprintf(&b, "\nDocker: mapped from %s (%s) service=%s containerPort=%s\n",
				rep.Docker.ContainerID, rep.Docker.ContainerName, dash(rep.Docker.ComposeService), rep.Docker.ContainerPort)
		} else {
			b.WriteString("\nDocker: not mapped\n")
		}
	}

	return b.String()
}

func Explain(rep model.Report, opt Options) string {
	opt = normalizeOptions(opt)
	var b strings.Builder
	b.WriteString(Who(rep, opt))

	if opt.NoHints {
		return b.String()
	}

	b.WriteString("\nSummary\n")
	if len(rep.Diagnostics) == 0 {
		b.WriteString("- No hints available\n")
	} else {
		for _, d := range rep.Diagnostics {
			fmt.Fprintf(&b, "- %s %s\n", severityLabel(d.Severity, opt), d.Summary)
		}
	}

	if opt.Summary {
		return b.String()
	}

	sections := groupDiagnostics(rep.Diagnostics)
	if len(sections) > 0 {
		b.WriteString("\nLikely causes\n")
		for _, s := range sections {
			if len(s.Items) == 0 {
				continue
			}
			fmt.Fprintf(&b, "\n%s\n", sectionTitle(s.Title, opt))
			for _, d := range s.Items {
				fmt.Fprintf(&b, "• %s\n", d.Summary)
				if d.Details != "" {
					fmt.Fprintf(&b, "  %s\n", d.Details)
				}
			}
		}
	}

	actions := dedupeActions(rep.Diagnostics)
	if len(actions) > 0 {
		b.WriteString("\nNext actions\n")
		for _, a := range actions {
			fmt.Fprintf(&b, "- %s\n", a)
		}
	}
	return b.String()
}

func Blame(rep model.Report, chain []proctree.Proc, started proctree.StartedBy) string {
	var b strings.Builder
	b.WriteString(Who(rep))
	b.WriteString("\nProcess tree (child → parents)\n")
	for i, p := range chain {
		prefix := "└─"
		if i < len(chain)-1 {
			prefix = "├─"
		}
		fmt.Fprintf(&b, "%s pid=%d ppid=%d user=%s name=%s\n", prefix, p.PID, p.PPID, dash(p.User), dash(p.Name))
		if p.Cmdline != "" {
			fmt.Fprintf(&b, "   cmd: %s\n", p.Cmdline)
		}
	}
	b.WriteString("\nWho started this? (best-effort)\n")
	fmt.Fprintf(&b, "- %s", strings.ToUpper(started.Kind))
	if started.Details != "" {
		fmt.Fprintf(&b, ": %s", started.Details)
	}
	b.WriteString("\n")
	if rep.Docker.Mapped {
		b.WriteString("- Port is mapped from Docker; the owning process may be docker-proxy or inside the container.\n")
	}
	return b.String()
}

func ActionResult(r sys.ActionResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", r.Summary)
	if r.Details != "" {
		fmt.Fprintf(&b, "%s\n", r.Details)
	}
	return b.String()
}

func fmtIP(ip string) string {
	if ip == "" {
		return "*"
	}
	if strings.Contains(ip, ":") && !strings.HasPrefix(ip, "[") {
		return "[" + ip + "]"
	}
	return ip
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func fmtProcChain(chain []proctree.Proc, max int) string {
	if len(chain) == 0 {
		return "-"
	}
	if max <= 0 || max > len(chain) {
		max = len(chain)
	}
	var parts []string
	for i := 0; i < max; i++ {
		p := chain[i]
		name := dash(p.Name)
		if name == "-" {
			name = "?"
		}
		parts = append(parts, fmt.Sprintf("%s(%d)", name, p.PID))
	}
	if max < len(chain) {
		parts = append(parts, "...")
	}
	return strings.Join(parts, " <- ")
}

type diagSection struct {
	Title string
	Items []model.Diagnostic
}

func groupDiagnostics(in []model.Diagnostic) []diagSection {
	ordered := []string{"Port & process", "Network & reachability", "Environment", "Other"}
	buckets := map[string][]model.Diagnostic{}
	for _, d := range in {
		buckets[diagCategory(d.Kind)] = append(buckets[diagCategory(d.Kind)], d)
	}
	var out []diagSection
	for _, title := range ordered {
		if len(buckets[title]) == 0 {
			continue
		}
		out = append(out, diagSection{Title: title, Items: buckets[title]})
	}
	return out
}

func diagCategory(kind string) string {
	switch kind {
	case "permission", "in-use", "time-wait", "zombie", "pid-missing", "multi-listener":
		return "Port & process"
	case "ipv6-only", "loopback-only", "firewall":
		return "Network & reachability"
	case "docker", "env", "vm":
		return "Environment"
	default:
		return "Other"
	}
}

func dedupeActions(in []model.Diagnostic) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range in {
		if strings.TrimSpace(d.Action) == "" {
			continue
		}
		if seen[d.Action] {
			continue
		}
		seen[d.Action] = true
		out = append(out, d.Action)
	}
	return out
}

func normalizeOptions(opt Options) Options {
	if opt.Verbose && opt.Summary {
		opt.Summary = false
	}
	return opt
}

func label(s string, opt Options) string {
	if !opt.Color {
		return s
	}
	return ansiBold + s + ansiReset
}

func stateLabel(state string, opt Options) string {
	if !opt.Color {
		return state
	}
	switch strings.ToUpper(state) {
	case "LISTEN":
		return ansiGreen + state + ansiReset
	case "BOUND":
		return ansiYellow + state + ansiReset
	default:
		return ansiBlue + state + ansiReset
	}
}

func severityLabel(sev string, opt Options) string {
	tag := strings.ToUpper(sev)
	if !opt.Color {
		return "[" + tag + "]"
	}
	switch sev {
	case "warn":
		return ansiYellow + "[" + tag + "]" + ansiReset
	case "error":
		return ansiRed + "[" + tag + "]" + ansiReset
	default:
		return ansiBlue + "[" + tag + "]" + ansiReset
	}
}

func sectionTitle(s string, opt Options) string {
	if !opt.Color {
		return s
	}
	return ansiCyan + s + ansiReset
}

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiBlue   = "\x1b[34m"
	ansiCyan   = "\x1b[36m"
)
