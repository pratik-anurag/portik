package cli

import (
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/pratik-anurag/portik/internal/history"
	"github.com/pratik-anurag/portik/internal/render"
)

func renderOptions(c *commonFlags) render.Options {
	opt := render.Options{
		Summary: c.Summary,
		Verbose: c.Verbose,
		NoHints: c.NoHints,
		Color:   resolveColor(c.Color),
	}
	if c.JSON {
		opt.Color = false
	}
	return opt
}

func resolveColor(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "always":
		return true
	case "never":
		return false
	default:
		return term.IsTerminal(int(os.Stdout.Fd()))
	}
}

func recentOwners(port int, proto string, n int) []render.OwnerEvent {
	s, err := history.Load()
	if err != nil || s == nil {
		return nil
	}
	evs := s.RecentOwners(port, proto, n)
	if len(evs) == 0 {
		return nil
	}
	out := make([]render.OwnerEvent, 0, len(evs))
	for _, e := range evs {
		out = append(out, render.OwnerEvent{
			At:    e.At,
			Label: history.OwnerLabel(e),
		})
	}
	return out
}
