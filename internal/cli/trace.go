package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/pratik-anurag/portik/internal/inspect"
	"github.com/pratik-anurag/portik/internal/proctree"
	"github.com/pratik-anurag/portik/internal/render"
	"github.com/pratik-anurag/portik/internal/trace"
)

type traceOutput struct {
	Port  int          `json:"port"`
	Proto string       `json:"proto"`
	Steps []trace.Step `json:"steps"`
}

func runTrace(args []string) int {
	fs := flag.NewFlagSet("trace", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	c := parseCommon(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "trace: missing <port>")
		return 2
	}
	port, err := parsePort(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "trace:", err)
		return 2
	}

	rep, err := inspect.InspectPort(port, c.Proto, inspect.Options{EnableDocker: c.Docker, IncludeConnections: true})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	var chain []proctree.Proc
	var started proctree.StartedBy
	if l, ok := rep.PrimaryListener(); ok && l.PID > 0 {
		chain, started = proctree.Build(l.PID, 8)
	}
	steps := trace.Steps(rep, chain, started)

	if c.JSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(traceOutput{Port: port, Proto: c.Proto, Steps: steps})
		return 0
	}

	fmt.Print(render.Trace(port, c.Proto, steps, renderOptions(c)))
	return 0
}
