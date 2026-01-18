//go:build darwin

package sockets

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/pratik-anurag/portik/internal/model"
)

// lsof -nP -iTCP:5432
// postgres 8123 me  6u  IPv6 ... TCP [::1]:5432 (LISTEN)
var reLsof = regexp.MustCompile(`^(?P<cmd>\S+)\s+(?P<pid>\d+)\s+(?P<user>\S+)\s+.*\sTCP\s+(?P<addr>\S+)\s+\((?P<state>[^)]+)\)\s*$`)

func inspectDarwin(port int, proto string, includeConnections bool) ([]model.Listener, []model.Conn, error) {
	var listeners []model.Listener
	var conns []model.Conn

	args := []string{"-nP", fmt.Sprintf("-i%s:%d", strings.ToUpper(proto), port)}
	out, _ := exec.Command("lsof", args...).Output()

	for _, line := range splitLines(out) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "COMMAND") {
			continue
		}
		m := reLsof.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		cmd := m[reLsof.SubexpIndex("cmd")]
		pid, err := strconv.Atoi(m[reLsof.SubexpIndex("pid")])
		if err != nil {
			continue
		}
		user := m[reLsof.SubexpIndex("user")]
		addr := m[reLsof.SubexpIndex("addr")]
		state := strings.ToUpper(strings.TrimSpace(m[reLsof.SubexpIndex("state")]))

		ip, p := parseLsofAddr(addr)
		fam := familyFromIP(ip)

		if state == "LISTEN" && p == port {
			listeners = append(listeners, model.Listener{
				LocalIP:   ip,
				LocalPort: p,
				Family:    fam,
				State:     "LISTEN",
				PID:       int32(pid),
				ProcName:  cmd,
				User:      user,
			})
		} else if includeConnections {
			lip, lp, rip, rp := parseLsofConn(addr)
			conns = append(conns, model.Conn{
				LocalIP:    lip,
				LocalPort:  lp,
				RemoteIP:   rip,
				RemotePort: rp,
				Family:     familyFromIP(lip),
				State:      state,
				PID:        int32(pid),
				ProcName:   cmd,
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

func parseLsofAddr(addr string) (string, int) {
	if i := strings.Index(addr, "->"); i >= 0 {
		addr = addr[:i]
	}
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

func parseLsofConn(addr string) (lip string, lp int, rip string, rp int) {
	parts := strings.Split(addr, "->")
	if len(parts) != 2 {
		lip, lp = parseLsofAddr(addr)
		return
	}
	lip, lp = parseLsofAddr(parts[0])
	rip, rp = parseLsofAddr(parts[1])
	return
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
