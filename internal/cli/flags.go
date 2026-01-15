package cli

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"
)

type commonFlags struct {
	Proto   string
	Docker  bool
	JSON    bool
	Yes     bool
	Summary bool
	Verbose bool
	NoHints bool
	Color   string
}

func parseCommon(fs *flag.FlagSet) *commonFlags {
	c := &commonFlags{}
	fs.StringVar(&c.Proto, "proto", "tcp", "protocol: tcp|udp")
	fs.BoolVar(&c.Docker, "docker", false, "enable docker mapping")
	fs.BoolVar(&c.JSON, "json", false, "output JSON (if available)")
	fs.BoolVar(&c.Yes, "yes", false, "skip confirmation prompts")
	fs.BoolVar(&c.Summary, "summary", false, "short output (where supported)")
	fs.BoolVar(&c.Verbose, "verbose", false, "verbose output (where supported)")
	fs.BoolVar(&c.NoHints, "no-hints", false, "suppress diagnostic hints (where supported)")
	fs.StringVar(&c.Color, "color", "auto", "color: auto|always|never")
	return c
}

func parsePort(s string) (int, error) {
	var p int
	if _, err := fmt.Sscanf(s, "%d", &p); err != nil {
		return 0, err
	}
	if p <= 0 || p > 65535 {
		return 0, errors.New("invalid port range")
	}
	return p, nil
}

func parsePortsList(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	var out []int
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		port, err := parsePort(p)
		if err != nil {
			return nil, err
		}
		out = append(out, port)
	}
	return out, nil
}

func parseSince(s string) (time.Duration, error) {
	if s == "" {
		return 0, errors.New("empty since")
	}
	// Support "7d"
	if len(s) > 1 && s[len(s)-1] == 'd' {
		var n int
		if _, err := fmt.Sscanf(s[:len(s)-1], "%d", &n); err != nil {
			return 0, err
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
