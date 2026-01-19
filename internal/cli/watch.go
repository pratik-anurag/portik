package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/pratik-anurag/portik/internal/history"
	"github.com/pratik-anurag/portik/internal/inspect"
	"github.com/pratik-anurag/portik/internal/render"
)

func runWatch(args []string) int {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	c := parseCommon(fs)

	var intervalStr string
	fs.StringVar(&intervalStr, "interval", "10s", "poll interval")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "watch: missing <port>")
		return 2
	}
	port, err := parsePort(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "watch:", err)
		return 2
	}
	interval, err := time.ParseDuration(intervalStr)
	if err != nil || interval < time.Second {
		fmt.Fprintln(os.Stderr, "watch: invalid --interval")
		return 2
	}

	var lastSig string
	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		rep, err := inspect.InspectPort(port, c.Proto, inspect.Options{EnableDocker: c.Docker, IncludeConnections: false})
		if err == nil {
			_ = history.Record(rep)
			sig := rep.Signature()
			if sig != lastSig {
				lastSig = sig
				if c.JSON {
					enc := json.NewEncoder(os.Stdout)
					enc.SetIndent("", "  ")
					_ = enc.Encode(rep)
				} else {
					fmt.Print(render.Who(rep, renderOptions(c)))
					fmt.Println("---")
				}
			}
		}
		<-t.C
	}
}
