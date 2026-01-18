//go:build tui

package cli

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/pratik-anurag/portik/internal/tui"
)

func runTUI(args []string) int {
	fs := flag.NewFlagSet("tui", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var portsStr string
	var intervalStr string
	var proto string
	var docker bool
	var actions bool
	var force bool

	fs.StringVar(&portsStr, "ports", "", "comma-separated ports to monitor (e.g., 5432,6379,8080)")
	fs.StringVar(&intervalStr, "interval", "2s", "poll interval")
	fs.StringVar(&proto, "proto", "tcp", "protocol: tcp|udp")
	fs.BoolVar(&docker, "docker", false, "enable docker mapping")
	fs.BoolVar(&actions, "actions", false, "enable kill/restart actions (with confirm)")
	fs.BoolVar(&force, "force", false, "allow actions on non-owned processes (danger; requires --actions)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if portsStr == "" {
		fmt.Fprintln(os.Stderr, "tui: missing --ports (e.g., --ports 5432,6379)")
		return 2
	}
	ports, err := parsePortsList(portsStr)
	if err != nil || len(ports) == 0 {
		fmt.Fprintln(os.Stderr, "tui: invalid --ports:", err)
		return 2
	}
	if proto != "tcp" && proto != "udp" {
		fmt.Fprintln(os.Stderr, "tui: invalid --proto (tcp|udp)")
		return 2
	}
	interval, err := time.ParseDuration(intervalStr)
	if err != nil || interval < 200*time.Millisecond {
		fmt.Fprintln(os.Stderr, "tui: invalid --interval (>=200ms)")
		return 2
	}
	if force && !actions {
		fmt.Fprintln(os.Stderr, "tui: --force requires --actions")
		return 2
	}

	opts := tui.Options{
		Ports:    ports,
		Proto:    proto,
		Interval: interval,
		Docker:   docker,
		Actions:  actions,
		Force:    force,
	}
	if err := tui.Run(opts); err != nil {
		fmt.Fprintln(os.Stderr, "tui:", err)
		return 1
	}
	return 0
}
