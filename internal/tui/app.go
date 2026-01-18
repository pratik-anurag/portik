package tui

import (
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

type Options struct {
	Ports    []int
	Proto    string
	Interval time.Duration
	Docker   bool
	Actions  bool
	Force    bool
}

func Run(opts Options) error {
	if err := opts.validate(); err != nil {
		return err
	}
	m := newModel(opts)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func (o Options) validate() error {
	if len(o.Ports) == 0 {
		return fmt.Errorf("no ports provided")
	}
	if o.Proto != "tcp" && o.Proto != "udp" {
		return fmt.Errorf("invalid proto")
	}
	if o.Interval <= 0 {
		return fmt.Errorf("invalid interval")
	}
	return nil
}
