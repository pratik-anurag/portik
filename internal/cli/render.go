package cli

import (
	"os"
	"strings"

	"golang.org/x/term"

	"portik/internal/render"
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
