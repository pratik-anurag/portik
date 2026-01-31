//go:build darwin

package sockets

import (
	"os/exec"
	"strings"

	"github.com/pratik-anurag/portik/internal/model"
)

func listConnections(proto string) ([]model.Conn, error) {
	args := []string{"-nP", "-iTCP"}
	out, err := exec.Command("lsof", args...).Output()
	if err != nil {
		return nil, err
	}

	var conns []model.Conn
	for _, line := range splitLines(out) {
		parsed, ok := parseLsofLine(line)
		if !ok {
			continue
		}
		if !strings.Contains(parsed.addr, "->") {
			continue
		}
		lip, lp, rip, rp := parseLsofConn(parsed.addr)
		conns = append(conns, model.Conn{
			LocalIP:    lip,
			LocalPort:  lp,
			RemoteIP:   rip,
			RemotePort: rp,
			Family:     familyFromIP(lip),
			State:      parsed.state,
			PID:        int32(parsed.pid),
			ProcName:   parsed.cmd,
		})
	}
	return conns, nil
}
