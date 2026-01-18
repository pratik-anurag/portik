package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/pratik-anurag/portik/internal/inspect"
	"github.com/pratik-anurag/portik/internal/proctree"
	"github.com/pratik-anurag/portik/internal/render"
)

func runBlame(args []string) int {
	fs := flag.NewFlagSet("blame", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	c := parseCommon(fs)

	var depth int
	fs.IntVar(&depth, "depth", 10, "max parent depth")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "blame: missing <port>")
		return 2
	}
	port, err := parsePort(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "blame:", err)
		return 2
	}

	rep, err := inspect.InspectPort(port, c.Proto, inspect.Options{EnableDocker: c.Docker, IncludeConnections: false})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	l, ok := rep.PrimaryListener()
	if !ok || l.PID <= 0 {
		fmt.Fprintln(os.Stderr, "No listening process found for this port.")
		if rep.Docker.Mapped {
			fmt.Fprintln(os.Stderr, "Note: port maps to Docker container; try `portik who <port> --docker`.")
		}
		return 1
	}

	tree, started := proctree.Build(l.PID, depth)

	if c.JSON {
		out := map[string]any{
			"report":       rep,
			"process_tree": tree,
			"started_by":   started,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return 0
	}

	fmt.Print(render.Blame(rep, tree, started))
	return 0
}
