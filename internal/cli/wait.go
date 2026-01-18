package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pratik-anurag/portik/internal/inspect"
	"github.com/pratik-anurag/portik/internal/model"
)

func runWait(args []string) int {
	fs := flag.NewFlagSet("wait", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var proto string
	var docker bool
	var timeoutStr string
	var intervalStr string
	var wantListening bool
	var wantFree bool
	var quiet bool

	fs.StringVar(&proto, "proto", "tcp", "protocol: tcp|udp (default tcp)")
	fs.BoolVar(&docker, "docker", false, "enable docker mapping (optional; not required)")
	fs.StringVar(&timeoutStr, "timeout", "30s", "max time to wait")
	fs.StringVar(&intervalStr, "interval", "500ms", "poll interval")
	fs.BoolVar(&wantListening, "listening", false, "wait until port is LISTENING")
	fs.BoolVar(&wantFree, "free", false, "wait until port is FREE (no listener)")
	fs.BoolVar(&quiet, "quiet", false, "no output (exit code only)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "wait: missing <port>")
		fmt.Fprintln(os.Stderr, "Usage: portik wait <port> --listening|--free [--timeout 30s] [--interval 500ms]")
		return 2
	}
	if proto != "tcp" && proto != "udp" {
		fmt.Fprintln(os.Stderr, "wait: invalid --proto (tcp|udp)")
		return 2
	}

	// default mode: listening
	if !wantListening && !wantFree {
		wantListening = true
	}
	if wantListening && wantFree {
		fmt.Fprintln(os.Stderr, "wait: choose only one of --listening or --free")
		return 2
	}

	port, err := parsePort(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "wait:", err)
		return 2
	}

	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil || timeout <= 0 {
		fmt.Fprintln(os.Stderr, "wait: invalid --timeout")
		return 2
	}
	interval, err := time.ParseDuration(intervalStr)
	if err != nil || interval <= 0 {
		fmt.Fprintln(os.Stderr, "wait: invalid --interval")
		return 2
	}

	deadline := time.Now().Add(timeout)
	for {
		rep, err := inspect.InspectPort(port, proto, inspect.Options{
			EnableDocker:       docker,
			IncludeConnections: false,
		})
		if err == nil {
			ok := false
			if wantListening {
				ok = isListening(rep)
			} else {
				ok = isFree(rep)
			}
			if ok {
				if !quiet {
					if wantListening {
						fmt.Printf("%d/%s is LISTENING\n", port, proto)
					} else {
						fmt.Printf("%d/%s is FREE\n", port, proto)
					}
				}
				return 0
			}
		}

		if time.Now().After(deadline) {
			if !quiet {
				mode := "LISTENING"
				if wantFree {
					mode = "FREE"
				}
				fmt.Fprintf(os.Stderr, "wait: timeout waiting for %d/%s to be %s\n", port, proto, mode)
			}
			return 1
		}
		time.Sleep(interval)
	}
}

func isListening(rep model.Report) bool {
	l, ok := rep.PrimaryListener()
	if !ok || l.PID <= 0 {
		return false
	}
	return strings.ToUpper(strings.TrimSpace(l.State)) == "LISTEN"
}

func isFree(rep model.Report) bool {
	// Free means no LISTEN listeners. Keep it conservative.
	if l, ok := rep.PrimaryListener(); ok {
		if strings.ToUpper(strings.TrimSpace(l.State)) == "LISTEN" {
			return false
		}
	}
	// if any listener exists, not free
	for _, l := range rep.Listeners {
		if strings.ToUpper(strings.TrimSpace(l.State)) == "LISTEN" {
			return false
		}
	}
	return true
}
