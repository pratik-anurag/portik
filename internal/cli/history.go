package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/pratik-anurag/portik/internal/history"
)

func runHistory(args []string) int {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var sinceStr string
	var jsonOut bool
	var detect bool
	fs.StringVar(&sinceStr, "since", "7d", "how far back: 24h|7d|30d")
	fs.BoolVar(&jsonOut, "json", false, "output JSON")
	fs.BoolVar(&detect, "detect-patterns", false, "detect simple time patterns")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "history: missing <port>")
		return 2
	}
	port, err := parsePort(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "history:", err)
		return 2
	}
	dur, err := parseSince(sinceStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "history: invalid --since")
		return 2
	}
	cutoff := time.Now().Add(-dur)

	s, err := history.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	view := s.ViewPortSince(port, cutoff, detect)

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(view)
		return 0
	}
	fmt.Print(history.RenderView(view))
	return 0
}
