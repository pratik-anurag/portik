package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"portik/internal/history"
	"portik/internal/inspect"
	"portik/internal/render"
)

func runWho(args []string) int {
	fs := flag.NewFlagSet("who", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	c := parseCommon(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "who: missing <port>")
		return 2
	}
	port, err := parsePort(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "who:", err)
		return 2
	}

	rep, err := inspect.InspectPort(port, c.Proto, inspect.Options{EnableDocker: c.Docker, IncludeConnections: false})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	_ = history.Record(rep)

	if c.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		return 0
	}

	fmt.Print(render.Who(rep, renderOptions(c)))
	return 0
}
