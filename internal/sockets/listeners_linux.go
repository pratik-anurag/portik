//go:build linux

package sockets

import (
	"bytes"
	"os/exec"
	"strings"

	"portik/internal/model"
)

func listListeners(proto string) ([]model.Listener, error) {
	ssArgs := []string{"-H"}
	if proto == "tcp" {
		ssArgs = append(ssArgs, "-ltnp")
	} else {
		ssArgs = append(ssArgs, "-lunp")
	}

	out, err := exec.Command("ss", ssArgs...).Output()
	if err != nil {
		return nil, err
	}

	var listeners []model.Listener
	for _, line := range strings.Split(strings.TrimSpace(string(bytes.TrimSpace(out))), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		m := reSS.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		state := strings.ToUpper(m[reSS.SubexpIndex("state")])
		// For UDP, ss still shows UNCONN, but we treat as listener-like.
		laddr := m[reSS.SubexpIndex("laddr")]
		pid, pname := parseUsers(m[reSS.SubexpIndex("users")])
		ip, p := splitHostPort(laddr)
		if p == 0 {
			continue
		}
		listeners = append(listeners, model.Listener{
			LocalIP:   ip,
			LocalPort: p,
			Family:    familyFromIP(ip),
			State:     state,
			PID:       int32(pid),
			ProcName:  pname,
		})
	}
	return listeners, nil
}
