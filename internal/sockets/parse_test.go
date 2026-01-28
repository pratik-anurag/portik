package sockets

import (
	"os"
	"strings"
	"testing"
)

func TestParseSSFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/ss.txt")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected fixture lines")
	}
	parsed, ok := parseSSLine(lines[1])
	if !ok {
		t.Fatalf("expected parse ok for ss line")
	}
	if parsed.proc != "api" || parsed.pid != 2210 || parsed.state != "ESTAB" {
		t.Fatalf("unexpected ss parse: %+v", parsed)
	}
	if parsed.raddr == "" || !strings.Contains(parsed.raddr, ":5432") {
		t.Fatalf("expected remote addr to include :5432, got %q", parsed.raddr)
	}
}

func TestParseLsofFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/lsof.txt")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected fixture lines")
	}
	parsed, ok := parseLsofLine(lines[2])
	if !ok {
		t.Fatalf("expected parse ok for lsof line")
	}
	if parsed.cmd != "api" || parsed.pid != 2210 || parsed.state != "ESTABLISHED" {
		t.Fatalf("unexpected lsof parse: %+v", parsed)
	}
	lip, lp, rip, rp := parseLsofConn(parsed.addr)
	if lip == "" || rip == "" || lp == 0 || rp == 0 {
		t.Fatalf("expected parsed connection endpoints, got lip=%q lp=%d rip=%q rp=%d", lip, lp, rip, rp)
	}
}
