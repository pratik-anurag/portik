//go:build linux

package sockets

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"portik/internal/model"
)

// ss -H -ltnp 'sport = :5432'
// LISTEN 0 4096 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=8123,fd=7))
var (
	reSS        = regexp.MustCompile(`^(?P<state>\S+)\s+\d+\s+\d+\s+(?P<laddr>\S+)\s+(?P<raddr>\S+)\s*(?P<users>users:\(\(.*\)\))?$`)
	reUsersPid  = regexp.MustCompile(`pid=(\d+)`)
	reUsersProc = regexp.MustCompile(`\(\("([^"]+)"`)
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
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		m := reSS.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		laddr := m[reSS.SubexpIndex("laddr")]
		state := strings.ToUpper(m[reSS.SubexpIndex("state")])
		pid, pname := parseUsers(m[reSS.SubexpIndex("users")])
		ip, p := splitHostPort(laddr)

		listeners = append(listeners, model.Listener{
			LocalIP:   ip,
			LocalPort: p,
			Family:    familyFromIP(ip),
			State:     state,
			PID:       int32(pid),
			ProcName:  pname,
		})
	}

	if includeConnections && proto == "tcp" {
		args := []string{"-H", "-tanp", fmt.Sprintf("( sport = :%d or dport = :%d )", port, port)}
		out2, _ := exec.Command("ss", args...).Output()
		for _, line := range splitLines(out2) {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			m := reSS.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			state := strings.ToUpper(m[reSS.SubexpIndex("state")])
			laddr := m[reSS.SubexpIndex("laddr")]
			raddr := m[reSS.SubexpIndex("raddr")]
			pid, pname := parseUsers(m[reSS.SubexpIndex("users")])
			lip, lp := splitHostPort(laddr)
			rip, rp := splitHostPort(raddr)

			conns = append(conns, model.Conn{
				LocalIP:    lip,
				LocalPort:  lp,
				RemoteIP:   rip,
				RemotePort: rp,
				Family:     familyFromIP(lip),
				State:      state,
				PID:        int32(pid),
				ProcName:   pname,
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

func parseUsers(users string) (pid int, proc string) {
	if users == "" {
		return 0, ""
	}
	if m := reUsersPid.FindStringSubmatch(users); m != nil {
		pid = parseInt(m[1])
	}
	if m := reUsersProc.FindStringSubmatch(users); m != nil {
		proc = m[1]
	}
	return
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
