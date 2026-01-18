//go:build darwin

package sockets

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"portik/internal/model"
)

func listListeners(proto string) ([]model.Listener, error) {
	// lsof filtering:
	// -iTCP -sTCP:LISTEN
	// -iUDP (no LISTEN concept, but UDP sockets bound)
	args := []string{"-nP"}
	if proto == "tcp" {
		args = append(args, "-iTCP", "-sTCP:LISTEN")
	} else {
		args = append(args, "-iUDP")
	}
	out, err := exec.Command("lsof", args...).Output()
	if err != nil {
		return nil, err
	}

	var listeners []model.Listener
	for _, line := range strings.Split(strings.TrimSpace(string(bytes.TrimSpace(out))), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "COMMAND") {
			continue
		}
		m := reLsof.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		cmd := m[reLsof.SubexpIndex("cmd")]
		user := m[reLsof.SubexpIndex("user")]
		state := strings.ToUpper(strings.TrimSpace(m[reLsof.SubexpIndex("state")]))
		addr := m[reLsof.SubexpIndex("addr")]

		var pid int
		_, _ = fmt.Sscanf(m[reLsof.SubexpIndex("pid")], "%d", &pid)

		ip, p := parseLsofAddr(addr)
		if p == 0 {
			continue
		}

		listeners = append(listeners, model.Listener{
			LocalIP:   ip,
			LocalPort: p,
			Family:    familyFromIP(ip),
			State:     state,
			PID:       int32(pid),
			ProcName:  cmd,
			User:      user,
		})
	}
	return listeners, nil
}
