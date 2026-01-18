package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/pratik-anurag/portik/internal/ports"
	"github.com/pratik-anurag/portik/internal/reserve"
)

func runFree(args []string) int {
	fs := flag.NewFlagSet("free", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var proto string
	var bind string
	var rangeSpec string
	var attempts int
	var jsonOut bool

	fs.StringVar(&proto, "proto", "tcp", "protocol: tcp|udp")
	fs.StringVar(&bind, "bind", "127.0.0.1", "bind address to test (default 127.0.0.1)")
	fs.StringVar(&rangeSpec, "ports", "", "ports spec (range recommended): e.g. 30000-40000")
	fs.IntVar(&attempts, "attempts", 64, "random attempts before linear scan (range mode)")
	fs.BoolVar(&jsonOut, "json", false, "output JSON")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if proto != "tcp" && proto != "udp" {
		fmt.Fprintln(os.Stderr, "free: invalid --proto (tcp|udp)")
		return 2
	}

	opt := reserve.FreeOptions{Proto: proto, Bind: bind, Attempts: attempts}

	var port int
	var err error

	if rangeSpec == "" {
		port, err = reserve.FindFreeEphemeral(opt)
	} else {
		plist, perr := ports.ParseSpec(rangeSpec)
		if perr != nil {
			fmt.Fprintln(os.Stderr, "free:", perr)
			return 2
		}
		// if user passed multiple discrete ports, we treat min-max as range (simple)
		start := plist[0]
		end := plist[len(plist)-1]
		opt.RangeStart, opt.RangeEnd = start, end
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		port, err = reserve.FindFreeInRange(ctx, opt)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "free:", err)
		return 1
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"port":  port,
			"proto": proto,
			"bind":  bind,
		})
		return 0
	}

	fmt.Println(port)
	return 0
}
