//go:build linux

package sockets

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/pratik-anurag/portik/internal/model"
)

func inspectLinux(port int, proto string, includeConnections bool) ([]model.Listener, []model.Conn, error) {
	var listeners []model.Listener
	var conns []model.Conn

	ssArgs := []string{"-H"}
	if proto == "tcp" {
		ssArgs = append(ssArgs, "-ltnp")
	} else {
		ssArgs = append(ssArgs, "-lunp")
	}
	ssArgs = append(ssArgs, fmt.Sprintf("sport = :%d", port))

	out, _ := exec.Command("ss", ssArgs...).Output()
	for _, line := range splitLines(out) {
		parsed, ok := parseSSLine(line)
		if !ok {
			continue
		}
		ip, p := splitHostPort(parsed.laddr)
		cwd := getCwd(parsed.pid)

		listeners = append(listeners, model.Listener{
			LocalIP:    ip,
			LocalPort:  p,
			Family:     familyFromIP(ip),
			State:      parsed.state,
			PID:        int32(parsed.pid),
			ProcName:   parsed.proc,
			WorkingDir: cwd,
		})
	}

	if includeConnections && proto == "tcp" {
		args := []string{"-H", "-tanp", fmt.Sprintf("( sport = :%d or dport = :%d )", port, port)}
		out2, _ := exec.Command("ss", args...).Output()
		for _, line := range splitLines(out2) {
			parsed, ok := parseSSLine(line)
			if !ok {
				continue
			}
			lip, lp := splitHostPort(parsed.laddr)
			rip, rp := splitHostPort(parsed.raddr)

			conns = append(conns, model.Conn{
				LocalIP:    lip,
				LocalPort:  lp,
				RemoteIP:   rip,
				RemotePort: rp,
				Family:     familyFromIP(lip),
				State:      parsed.state,
				PID:        int32(parsed.pid),
				ProcName:   parsed.proc,
			})
		}
	}

	return listeners, conns, nil
}

func splitLines(b []byte) []string {
	s := strings.TrimSpace(string(bytes.TrimSpace(b)))
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func splitHostPort(addr string) (string, int) {
	addr = strings.TrimSpace(addr)

	if strings.HasPrefix(addr, "[") {
		i := strings.LastIndex(addr, "]:")
		if i > 0 {
			ip := addr[1:i]
			p := parseInt(addr[i+2:])
			return ip, p
		}
	}
	if strings.HasPrefix(addr, "*:") {
		p := parseInt(strings.TrimPrefix(addr, "*:"))
		return "", p
	}
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return addr, 0
	}
	ip := addr[:i]
	p := parseInt(addr[i+1:])
	return ip, p
}

func familyFromIP(ip string) string {
	if strings.Contains(ip, ":") {
		return "ipv6"
	}
	if ip == "" {
		return "unknown"
	}
	return "ipv4"
}

func getCwd(pid int) string {
	// $ pwdx <pid>
	//   <pid>: <path>
	args := []string{strconv.Itoa(pid)}
	out, err := exec.Command("pwdx", args...).Output()
	if err != nil {
		return ""
	}
	parts := strings.SplitN(string(out), ": ", 2)
	return strings.TrimSpace(parts[1])
}
