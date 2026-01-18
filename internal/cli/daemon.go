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

func runDaemon(args []string) int {
	fs := flag.NewFlagSet("daemon", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	c := parseCommon(fs)

	var portsStr string
	var intervalStr string
	var quiet bool
	fs.StringVar(&portsStr, "ports", "", "comma-separated ports to monitor (e.g., 5432,6379,8080)")
	fs.StringVar(&intervalStr, "interval", "30s", "poll interval")
	fs.BoolVar(&quiet, "quiet", false, "do not print periodic status (only errors)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if portsStr == "" {
		fmt.Fprintln(os.Stderr, "daemon: missing --ports (e.g., --ports 5432,6379)")
		return 2
	}
	ports, err := parsePortsList(portsStr)
	if err != nil || len(ports) == 0 {
		fmt.Fprintln(os.Stderr, "daemon: invalid --ports:", err)
		return 2
	}
	interval, err := time.ParseDuration(intervalStr)
	if err != nil || interval < time.Second {
		fmt.Fprintln(os.Stderr, "daemon: invalid --interval")
		return 2
	}

	fmt.Fprintf(os.Stderr, "portik daemon: monitoring %d ports every %s (history at ~/.portik/history.json)\n", len(ports), interval)

	type last struct{ sig string }
	lastByPort := map[int]last{}

	t := time.NewTicker(interval)
	defer t.Stop()

	runOnce := func() {
		for _, p := range ports {
			rep, err := inspect.InspectPort(p, c.Proto, inspect.Options{EnableDocker: c.Docker, IncludeConnections: false})
			if err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				continue
			}
			_ = history.Record(rep)
			sig := rep.Signature()
			prev := lastByPort[p]
			if sig != prev.sig {
				lastByPort[p] = last{sig: sig}
				if quiet {
					continue
				}
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
	}

	runOnce()
	for {
		<-t.C
		runOnce()
	}
}
