package render

import (
	"fmt"
	"sort"
	"strings"

	"github.com/pratik-anurag/portik/internal/model"
)

func LintTable(findings []model.LintFinding) string {
	if len(findings) == 0 {
		return "No lint findings.\n"
	}

	// sort by severity (error>warn>info), then port
	sevRank := func(s string) int {
		s = strings.ToLower(strings.TrimSpace(s))
		switch s {
		case "error":
			return 0
		case "warn", "warning":
			return 1
		default:
			return 2
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		ri, rj := sevRank(findings[i].Severity), sevRank(findings[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if findings[i].Port != findings[j].Port {
			return findings[i].Port < findings[j].Port
		}
		if findings[i].Proto != findings[j].Proto {
			return findings[i].Proto < findings[j].Proto
		}
		return findings[i].Code < findings[j].Code
	})

	var b strings.Builder
	b.WriteString("SEV   PORT/PROTO  BIND              PID     PROCESS            SUMMARY\n")
	b.WriteString("────  ─────────  ───────────────  ──────  ───────────────  ─────────────────────────────────────────\n")

	for _, f := range findings {
		bind := f.LocalIP
		if bind == "" {
			bind = "*"
		}
		fmt.Fprintf(&b, "%-4s  %-9s  %-15s  %-6s  %-15s  %s\n",
			strings.ToUpper(f.Severity),
			fmt.Sprintf("%d/%s", f.Port, f.Proto),
			trunc(bind, 15),
			pidStr(f.PID),
			trunc(nonEmpty(f.ProcName, "-"), 15),
			trunc(f.Summary, 56),
		)
		if f.Action != "" {
			fmt.Fprintf(&b, "      ↳ %s\n", f.Action)
		}
	}
	return b.String()
}

func pidStr(pid int32) string {
	if pid <= 0 {
		return "-"
	}
	return fmt.Sprintf("%d", pid)
}

func nonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
