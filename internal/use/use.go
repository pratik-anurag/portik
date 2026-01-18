package use

import (
	"context"
	"fmt"
	"time"

	"github.com/pratik-anurag/portik/internal/ports"
	"github.com/pratik-anurag/portik/internal/reserve"
)

type PickOptions struct {
	Proto     string
	Bind      string
	PortsSpec string // "", or e.g. "3000-3999"
	Attempts  int
	Timeout   time.Duration
}

func PickFreePort(opt PickOptions) (int, error) {
	if opt.Bind == "" {
		opt.Bind = "127.0.0.1"
	}
	if opt.Proto != "tcp" && opt.Proto != "udp" {
		return 0, fmt.Errorf("invalid proto: %s", opt.Proto)
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 3 * time.Second
	}

	freeOpt := reserve.FreeOptions{
		Proto:    opt.Proto,
		Bind:     opt.Bind,
		Attempts: opt.Attempts,
	}

	// No range specified → ephemeral
	if opt.PortsSpec == "" {
		return reserve.FindFreeEphemeral(freeOpt)
	}

	plist, err := ports.ParseSpec(opt.PortsSpec)
	if err != nil {
		return 0, err
	}
	start := plist[0]
	end := plist[len(plist)-1]

	freeOpt.RangeStart = start
	freeOpt.RangeEnd = end

	ctx, cancel := context.WithTimeout(context.Background(), opt.Timeout)
	defer cancel()

	return reserve.FindFreeInRange(ctx, freeOpt)
}
