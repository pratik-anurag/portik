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

func runWho(args []string) int {
	fs := flag.NewFlagSet("who", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	c := parseCommon(fs)
	var follow bool
	var intervalStr string
	fs.BoolVar(&follow, "follow", false, "stream changes (delta-only)")
	fs.StringVar(&intervalStr, "interval", "2s", "poll interval for --follow")
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

	if follow {
		interval, err := time.ParseDuration(intervalStr)
		if err != nil || interval < 200*time.Millisecond {
			fmt.Fprintln(os.Stderr, "who: invalid --interval")
			return 2
		}
		return followWho(port, c, interval)
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

	opt := renderOptions(c)
	opt.RecentOwners = recentOwners(port, c.Proto, 3)
	fmt.Print(render.Who(rep, opt))
	return 0
}

func followWho(port int, c *commonFlags, interval time.Duration) int {
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
					opt := renderOptions(c)
					opt.RecentOwners = recentOwners(port, c.Proto, 3)
					fmt.Print(changeBanner(opt.Color, port, c.Proto))
					fmt.Print(render.Who(rep, opt))
					fmt.Println("---")
				}
			}
		}
		<-t.C
	}
}

func changeBanner(color bool, port int, proto string) string {
	msg := fmt.Sprintf("Change @ %s for %d/%s\n", time.Now().Format("15:04:05"), port, proto)
	if !color {
		return msg
	}
	return "\x1b[35m" + msg + "\x1b[0m"
}
