package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pratik-anurag/portik/internal/reserve"
)

func runReserve(args []string) int {
	fs := flag.NewFlagSet("reserve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var proto string
	var bind string
	var forStr string
	var jsonOut bool

	fs.StringVar(&proto, "proto", "tcp", "protocol: tcp|udp")
	fs.StringVar(&bind, "bind", "127.0.0.1", "bind address (default 127.0.0.1)")
	fs.StringVar(&forStr, "for", "30s", "how long to hold the reservation (e.g. 10s, 2m)")
	fs.BoolVar(&jsonOut, "json", false, "output JSON")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if proto != "tcp" && proto != "udp" {
		fmt.Fprintln(os.Stderr, "reserve: invalid --proto (tcp|udp)")
		return 2
	}
	hold, err := time.ParseDuration(forStr)
	if err != nil || hold <= 0 {
		fmt.Fprintln(os.Stderr, "reserve: invalid --for")
		return 2
	}

	port := 0
	if fs.NArg() >= 1 {
		p, err := parsePort(fs.Arg(0))
		if err != nil {
			fmt.Fprintln(os.Stderr, "reserve:", err)
			return 2
		}
		port = p
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// stop on Ctrl+C
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigc
		cancel()
	}()

	ctxHold, cancelHold := context.WithTimeout(ctx, hold)
	defer cancelHold()

	res, h, err := reserve.Reserve(ctxHold, proto, bind, port)
	if err != nil {
		fmt.Fprintln(os.Stderr, "reserve:", err)
		return 1
	}
	defer h.Close()

	res.Until = time.Now().Add(hold)

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else {
		fmt.Printf("Reserved %d/%s on %s until %s\n", res.Port, res.Proto, res.Bind, res.Until.Format(time.RFC3339))
		fmt.Printf("(holding for %s; Ctrl+C to release)\n", hold)
	}

	<-ctxHold.Done()
	return 0
}
