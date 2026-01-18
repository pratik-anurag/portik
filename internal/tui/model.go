package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/pratik-anurag/portik/internal/history"
	"github.com/pratik-anurag/portik/internal/inspect"
	"github.com/pratik-anurag/portik/internal/model"
	"github.com/pratik-anurag/portik/internal/render"
	"github.com/pratik-anurag/portik/internal/sys"
)

type viewMode int

const (
	viewWho viewMode = iota
	viewExplain
)

type actionKind int

const (
	actionNone actionKind = iota
	actionKill
	actionRestart
)

type portRow struct {
	Port       int
	Proto      string
	Owner      string
	PID        int32
	Addr       string
	State      string
	Docker     string
	Changed    bool
	Spark      string
	LastSig    string
	LastChange time.Time
	Report     model.Report
	Err        string
}

type modelTUI struct {
	opts Options

	rows      []portRow
	selected  int
	mode      viewMode
	filter    string
	filtering bool
	showHelp  bool

	width  int
	height int

	lastRefresh time.Time
	status      string

	confirming bool
	confirmAct actionKind
	confirmMsg string

	store *history.Store
}

type tickMsg time.Time
type refreshMsg struct {
	rows  []portRow
	store *history.Store
	err   error
}
type actionDoneMsg struct {
	res sys.ActionResult
	err error
}

func newModel(opts Options) modelTUI {
	rows := make([]portRow, 0, len(opts.Ports))
	for _, p := range opts.Ports {
		rows = append(rows, portRow{Port: p, Proto: opts.Proto})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Port < rows[j].Port })

	return modelTUI{
		opts:      opts,
		rows:      rows,
		selected:  0,
		mode:      viewWho,
		status:    "Starting…",
		store:     nil,
		filter:    "",
		filtering: false,
	}
}

func (m modelTUI) Init() tea.Cmd {
	return tea.Batch(m.refreshCmd(), tick(m.opts.Interval))
}

func tick(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m modelTUI) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch x := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = x.Width
		m.height = x.Height
		return m, nil

	case tickMsg:
		return m, tea.Batch(m.refreshCmd(), tick(m.opts.Interval))

	case refreshMsg:
		if x.err != nil {
			m.status = "Refresh failed: " + x.err.Error()
			return m, nil
		}
		m.lastRefresh = time.Now()
		m.store = x.store
		m.status = fmt.Sprintf("Refreshed %s", m.lastRefresh.Format("15:04:05"))

		prevByPort := map[int]portRow{}
		for _, r := range m.rows {
			prevByPort[r.Port] = r
		}
		m.rows = x.rows
		for i := range m.rows {
			prev := prevByPort[m.rows[i].Port]
			if prev.LastSig != "" && m.rows[i].LastSig != "" && prev.LastSig != m.rows[i].LastSig {
				m.rows[i].Changed = true
				m.rows[i].LastChange = time.Now()
			}
		}
		return m, nil

	case tea.KeyMsg:
		if m.confirming {
			switch x.String() {
			case "y", "Y", "enter":
				return m, m.runActionCmd(m.confirmAct)
			case "n", "N", "esc":
				m.confirming = false
				m.confirmAct = actionNone
				m.confirmMsg = ""
				m.status = "Cancelled"
				return m, nil
			default:
				return m, nil
			}
		}

		if m.filtering {
			switch x.Type {
			case tea.KeyEsc:
				m.filtering = false
				m.filter = ""
				return m, nil
			case tea.KeyEnter:
				m.filtering = false
				return m, nil
			case tea.KeyBackspace, tea.KeyDelete:
				if len(m.filter) > 0 {
					m.filter = m.filter[:len(m.filter)-1]
				}
				return m, nil
			default:
				if x.Type == tea.KeyRunes {
					m.filter += x.String()
					return m, nil
				}
			}
		}

		switch x.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "?", "h":
			m.showHelp = !m.showHelp
			return m, nil
		case "up", "k":
			m.selected = max(0, m.selected-1)
			return m, nil
		case "down", "j":
			m.selected = min(len(m.filteredRows())-1, m.selected+1)
			return m, nil
		case "tab":
			if m.mode == viewWho {
				m.mode = viewExplain
			} else {
				m.mode = viewWho
			}
			return m, nil
		case "w":
			m.mode = viewWho
			return m, nil
		case "e":
			m.mode = viewExplain
			return m, nil
		case "r":
			return m, m.refreshCmd()
		case "/":
			m.filtering = true
			return m, nil
		case "esc":
			m.filter = ""
			return m, nil
		case "K":
			if !m.opts.Actions {
				m.status = "Actions disabled (run with --actions)"
				return m, nil
			}
			m.beginConfirm(actionKill)
			return m, nil
		case "R":
			if !m.opts.Actions {
				m.status = "Actions disabled (run with --actions)"
				return m, nil
			}
			m.beginConfirm(actionRestart)
			return m, nil
		}

	case actionDoneMsg:
		if x.err != nil {
			m.status = "Action failed: " + x.err.Error()
		} else {
			m.status = x.res.Summary
			if x.res.Details != "" {
				m.status += " — " + x.res.Details
			}
		}
		m.confirming = false
		m.confirmAct = actionNone
		m.confirmMsg = ""
		return m, m.refreshCmd()
	}
	return m, nil
}

func (m *modelTUI) beginConfirm(kind actionKind) {
	row, ok := m.selectedRow()
	if !ok {
		m.status = "No selection"
		return
	}
	switch kind {
	case actionKill:
		if row.PID <= 0 {
			m.status = "No PID to kill"
			return
		}
		m.confirmMsg = fmt.Sprintf("Kill pid %d (%s) on %d/%s? [y/N]", row.PID, dash(row.Owner), row.Port, row.Proto)
	case actionRestart:
		if row.PID <= 0 {
			m.status = "No PID to restart"
			return
		}
		l, ok2 := row.Report.PrimaryListener()
		if !ok2 || strings.TrimSpace(l.Cmdline) == "" {
			m.status = "Cannot restart: missing cmdline (try sudo)"
			return
		}
		m.confirmMsg = fmt.Sprintf("Restart pid %d (%s)? [y/N]", row.PID, dash(row.Owner))
	}
	m.confirming = true
	m.confirmAct = kind
}

func (m modelTUI) View() string {
	return renderUI(m)
}

func (m modelTUI) refreshCmd() tea.Cmd {
	opts := m.opts
	ports := make([]int, len(m.opts.Ports))
	copy(ports, m.opts.Ports)

	prevByPort := map[int]string{}
	for _, r := range m.rows {
		prevByPort[r.Port] = r.LastSig
	}

	return func() tea.Msg {
		st, _ := history.Load()

		rows := make([]portRow, 0, len(ports))
		for _, p := range ports {
			row := portRow{Port: p, Proto: opts.Proto}
			rep, err := inspect.InspectPort(p, opts.Proto, inspect.Options{EnableDocker: opts.Docker, IncludeConnections: true})
			if err != nil {
				row.Err = err.Error()
				rows = append(rows, row)
				continue
			}
			_ = history.Record(rep)
			row.Report = rep

			l, ok := rep.PrimaryListener()
			if ok {
				row.PID = l.PID
				row.Owner = ownerFromListener(l)
				row.State = l.State
				row.Addr = fmt.Sprintf("%s:%d", ipOrStar(l.LocalIP), l.LocalPort)
			} else {
				row.Owner = "(none)"
				row.State = "-"
				row.Addr = fmt.Sprintf("*:%d", p)
			}
			if rep.Docker.Mapped {
				row.Docker = rep.Docker.ContainerName
			}

			row.LastSig = rep.Signature()

			if st != nil {
				// Next-level feature (already included): sparkline of changes over last 24h
				row.Spark = sparkForPort(st, p, opts.Proto, 24*time.Hour, 12)
			}

			rows = append(rows, row)
		}

		sort.Slice(rows, func(i, j int) bool { return rows[i].Port < rows[j].Port })

		for i := range rows {
			if ps := prevByPort[rows[i].Port]; ps != "" {
				if rows[i].LastSig != "" && rows[i].LastSig != ps {
					rows[i].Changed = true
					rows[i].LastChange = time.Now()
				}
			}
		}

		return refreshMsg{rows: rows, store: st, err: nil}
	}
}

func (m modelTUI) runActionCmd(kind actionKind) tea.Cmd {
	row, ok := m.selectedRow()
	if !ok {
		return nil
	}
	timeout := 10 * time.Second

	return func() tea.Msg {
		switch kind {
		case actionKill:
			if row.PID <= 0 {
				return actionDoneMsg{err: fmt.Errorf("no pid")}
			}
			if !m.opts.Force {
				if err := sys.EnsureSameUser(row.PID); err != nil {
					return actionDoneMsg{err: err}
				}
			}
			res := sys.TerminateProcess(row.PID, timeout)
			return actionDoneMsg{res: res}
		case actionRestart:
			l, ok := row.Report.PrimaryListener()
			if !ok || l.PID <= 0 {
				return actionDoneMsg{err: fmt.Errorf("no pid")}
			}
			if strings.TrimSpace(l.Cmdline) == "" {
				return actionDoneMsg{err: fmt.Errorf("missing cmdline (try sudo)")}
			}
			if !m.opts.Force {
				if err := sys.EnsureSameUser(l.PID); err != nil {
					return actionDoneMsg{err: err}
				}
			}
			res := sys.SmartRestart(l.PID, l.Cmdline, timeout)
			return actionDoneMsg{res: res}
		default:
			return actionDoneMsg{err: fmt.Errorf("unknown action")}
		}
	}
}

func (m modelTUI) filteredRows() []portRow {
	if strings.TrimSpace(m.filter) == "" {
		return m.rows
	}
	f := strings.ToLower(strings.TrimSpace(m.filter))
	var out []portRow
	for _, r := range m.rows {
		if strings.Contains(fmt.Sprintf("%d", r.Port), f) ||
			strings.Contains(strings.ToLower(r.Owner), f) ||
			strings.Contains(strings.ToLower(r.Docker), f) ||
			strings.Contains(strings.ToLower(r.Err), f) {
			out = append(out, r)
		}
	}
	return out
}

func (m modelTUI) selectedRow() (portRow, bool) {
	rows := m.filteredRows()
	if len(rows) == 0 {
		return portRow{}, false
	}
	sel := m.selected
	if sel < 0 {
		sel = 0
	}
	if sel >= len(rows) {
		sel = len(rows) - 1
	}
	return rows[sel], true
}

func ownerFromListener(l model.Listener) string {
	if l.ProcName != "" {
		if l.User != "" {
			return fmt.Sprintf("%s (%s)", l.ProcName, l.User)
		}
		return l.ProcName
	}
	if l.PID > 0 {
		return fmt.Sprintf("pid:%d", l.PID)
	}
	return "(unknown)"
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func detailsForRow(row portRow, mode viewMode) string {
	if row.Err != "" {
		return "Error:\n" + row.Err + "\n"
	}
	if mode == viewExplain {
		return render.Explain(row.Report, render.Options{})
	}
	return render.Who(row.Report, render.Options{})
}

func ipOrStar(ip string) string {
	if strings.TrimSpace(ip) == "" {
		return "*"
	}
	return ip
}
