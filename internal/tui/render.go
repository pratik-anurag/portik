package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/pratik-anurag/portik/internal/history"
)

func renderUI(m modelTUI) string {
	var b strings.Builder
	width := clamp(m.width, 40, 140)

	styles := tuiStyles(width)

	modeLabel := "who"
	if m.mode == viewExplain {
		modeLabel = "explain"
	}
	last := "-"
	if !m.lastRefresh.IsZero() {
		last = m.lastRefresh.Format("15:04:05")
	}
	header := fmt.Sprintf("portik TUI  mode=%s  proto=%s  interval=%s  last=%s", modeLabel, m.opts.Proto, m.opts.Interval, last)
	if m.opts.Docker {
		header += "  docker=on"
	} else {
		header += "  docker=off"
	}
	if m.opts.Actions {
		header += "  actions=on (K=kill, R=restart)"
	} else {
		header += "  actions=off (run with --actions)"
	}

	b.WriteString(styles.header.Width(width).Render(header))
	b.WriteString("\n")

	if m.filtering {
		b.WriteString(styles.filter.Render(fmt.Sprintf("Filter: %s▌  (Enter to apply, Esc to clear)", m.filter)))
		b.WriteString("\n")
	} else if strings.TrimSpace(m.filter) != "" {
		b.WriteString(styles.filter.Render(fmt.Sprintf("Filter: %s  (Esc to clear, / to edit)", m.filter)))
		b.WriteString("\n")
	} else {
		b.WriteString(styles.filter.Render("Filter: (press / to search)"))
		b.WriteString("\n")
	}

	b.WriteString(styles.rule.Render(strings.Repeat("─", width)))
	b.WriteString("\n")

	rows := m.filteredRows()
	if len(rows) == 0 {
		b.WriteString("(no rows; adjust filter)\n")
		return b.String()
	}

	sel := m.selected
	if sel < 0 {
		sel = 0
	}
	if sel >= len(rows) {
		sel = len(rows) - 1
	}

	b.WriteString(styles.tableHeader.Render("PORT   OWNER                    PID     ADDR                  DOCKER            Δ  SPARK"))
	b.WriteString("\n")
	b.WriteString(styles.rule.Render(strings.Repeat("─", width)))
	b.WriteString("\n")

	for i, r := range rows {
		prefix := " "
		if i == sel {
			prefix = ">"
		}
		changed := " "
		if r.Changed && !r.LastChange.IsZero() && time.Since(r.LastChange) < 5*time.Second {
			changed = styles.changed.Render("*")
		}
		owner := trunc(r.Owner, 23)
		addr := trunc(r.Addr, 20)
		dk := trunc(r.Docker, 16)
		spark := trunc(r.Spark, 12)
		if r.Err != "" {
			owner = styles.err.Render(trunc("ERR: "+r.Err, 23))
		}
		if strings.TrimSpace(dk) != "" {
			dk = styles.docker.Render(dk)
		}
		line := fmt.Sprintf("%s%-5s %-23s %-7s %-20s %-16s %s  %-12s",
			prefix,
			fmt.Sprintf("%d", r.Port),
			owner,
			pidStr(r.PID),
			addr,
			dk,
			changed,
			spark,
		)
		if i == sel {
			line = styles.selected.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(styles.rule.Render(strings.Repeat("─", width)))
	b.WriteString("\n")

	row := rows[sel]

	title := "Details"
	if m.mode == viewExplain {
		title = "Explain"
	}
	b.WriteString(styles.section.Render(fmt.Sprintf("%s (Tab toggle, w=who, e=explain)", title)))
	b.WriteString("\n")
	b.WriteString(truncLines(detailsForRow(row, m.mode), 18))
	b.WriteString("\n")

	b.WriteString(styles.rule.Render(strings.Repeat("─", width)))
	b.WriteString("\n")
	b.WriteString(styles.section.Render("History (last 20)"))
	b.WriteString("\n")
	b.WriteString(renderHistoryLast20(m, row.Port))
	b.WriteString("\n")

	if m.confirming {
		b.WriteString("\n")
		b.WriteString(styles.rule.Render(strings.Repeat("─", width)))
		b.WriteString("\n")
		b.WriteString(styles.confirm.Render("CONFIRM: " + m.confirmMsg))
		b.WriteString("\n")
	} else {
		b.WriteString("\n")
		b.WriteString(styles.status.Width(width).Render("Status: " + m.status))
		b.WriteString("\n")
		if m.showHelp {
			b.WriteString(styles.help.Render(helpText(m)))
			b.WriteString("\n")
		} else {
			keys := "Keys: ↑/↓ select, Tab toggle, r refresh, / filter, Esc clear, q quit, ? help"
			if m.opts.Actions {
				keys += ", K kill, R restart"
			}
			b.WriteString(styles.keys.Render(keys))
			b.WriteString("\n")
		}
	}

	return b.String()
}

type tuiStyleSet struct {
	header      lipgloss.Style
	filter      lipgloss.Style
	rule        lipgloss.Style
	tableHeader lipgloss.Style
	selected    lipgloss.Style
	changed     lipgloss.Style
	err         lipgloss.Style
	docker      lipgloss.Style
	section     lipgloss.Style
	confirm     lipgloss.Style
	status      lipgloss.Style
	keys        lipgloss.Style
	help        lipgloss.Style
}

func tuiStyles(width int) tuiStyleSet {
	return tuiStyleSet{
		header:      lipgloss.NewStyle().Background(lipgloss.Color("#1F6F8B")).Foreground(lipgloss.Color("#F8F4E3")).Padding(0, 1),
		filter:      lipgloss.NewStyle().Foreground(lipgloss.Color("#A7F3D0")),
		rule:        lipgloss.NewStyle().Foreground(lipgloss.Color("#2DD4BF")),
		tableHeader: lipgloss.NewStyle().Foreground(lipgloss.Color("#F59E0B")).Bold(true),
		selected:    lipgloss.NewStyle().Background(lipgloss.Color("#1D4ED8")).Foreground(lipgloss.Color("#F8FAFC")),
		changed:     lipgloss.NewStyle().Foreground(lipgloss.Color("#F97316")).Bold(true),
		err:         lipgloss.NewStyle().Foreground(lipgloss.Color("#EF4444")).Bold(true),
		docker:      lipgloss.NewStyle().Foreground(lipgloss.Color("#22D3EE")).Bold(true),
		section:     lipgloss.NewStyle().Foreground(lipgloss.Color("#93C5FD")).Bold(true),
		confirm:     lipgloss.NewStyle().Background(lipgloss.Color("#7C2D12")).Foreground(lipgloss.Color("#FEF3C7")).Padding(0, 1),
		status:      lipgloss.NewStyle().Background(lipgloss.Color("#111827")).Foreground(lipgloss.Color("#F9FAFB")).Padding(0, 1).Width(width),
		keys:        lipgloss.NewStyle().Foreground(lipgloss.Color("#94A3B8")),
		help:        lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("#22C55E")).Foreground(lipgloss.Color("#DCFCE7")).Padding(1, 2).Width(width - 2),
	}
}

func helpText(m modelTUI) string {
	lines := []string{
		"Navigation: ↑/↓ (or j/k), Tab toggle, w who, e explain",
		"Refresh: r, Filter: / then type, Esc clear",
		"View: ? toggle help, q quit",
	}
	if m.opts.Actions {
		lines = append(lines, "Actions: K kill, R restart (confirm with y/Enter, cancel with n/Esc)")
	} else {
		lines = append(lines, "Actions: disabled (run with --actions)")
	}
	return "Help\n" + strings.Join(lines, "\n")
}

func renderHistoryLast20(m modelTUI, port int) string {
	if m.store == nil {
		return "  (no history loaded)\n"
	}
	key := fmt.Sprintf("%d/%s", port, m.opts.Proto)
	evs := m.store.Ports[key]
	if len(evs) == 0 {
		for _, k := range []string{fmt.Sprintf("%d/tcp", port), fmt.Sprintf("%d/udp", port)} {
			if len(m.store.Ports[k]) > 0 {
				evs = m.store.Ports[k]
				break
			}
		}
	}
	if len(evs) == 0 {
		return "  (no events)\n"
	}
	start := 0
	if len(evs) > 20 {
		start = len(evs) - 20
	}
	var b strings.Builder
	for _, e := range evs[start:] {
		lbl := ownerLabelEvent(e)
		b.WriteString(fmt.Sprintf("  %s  %s\n", e.At.Format("01-02 15:04:05"), trunc(lbl, 48)))
	}
	return b.String()
}

func ownerLabelEvent(e history.OwnershipEvent) string {
	if e.DockerMapped {
		if e.ComposeService != "" {
			return fmt.Sprintf("docker:%s (svc=%s)", e.ContainerName, e.ComposeService)
		}
		return "docker:" + e.ContainerName
	}
	if e.ProcName != "" {
		if e.User != "" {
			return fmt.Sprintf("%s (%s)", e.ProcName, e.User)
		}
		return e.ProcName
	}
	if e.PID > 0 {
		return fmt.Sprintf("pid:%d", e.PID)
	}
	return "none"
}

func pidStr(pid int32) string {
	if pid <= 0 {
		return "-"
	}
	return fmt.Sprintf("%d", pid)
}

func trunc(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func truncLines(s string, maxLines int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= maxLines {
		return s
	}
	return strings.Join(lines[:maxLines], "\n") + "\n…\n"
}

func clamp(v, lo, hi int) int {
	if v == 0 {
		return 100
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
