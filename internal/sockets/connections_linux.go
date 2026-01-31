//go:build linux

package sockets

import (
	"os/exec"
	"strings"

	"github.com/pratik-anurag/portik/internal/model"
)

func listConnections(proto string) ([]model.Conn, error) {
	args := []string{"-H", "-tanp"}
	out, err := exec.Command("ss", args...).Output()
	if err != nil {
		return nil, err
	}

	var conns []model.Conn
	for _, line := range splitLines(out) {
		parsed, ok := parseSSLine(line)
		if !ok {
			continue
		}
		lip, lp := splitHostPort(parsed.laddr)
		rip, rp := splitHostPort(parsed.raddr)
		conns = append(conns, model.Conn{
			LocalIP:    lip,
			LocalPort:  lp,
			RemoteIP:   strings.TrimSpace(rip),
			RemotePort: rp,
			Family:     familyFromIP(lip),
			State:      parsed.state,
			PID:        int32(parsed.pid),
			ProcName:   parsed.proc,
		})
	}
	return conns, nil
}
