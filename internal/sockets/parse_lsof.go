package sockets

import (
	"regexp"
	"strings"
)

// lsof -nP -iTCP:5432
// postgres 8123 me  6u  IPv6 ... TCP [::1]:5432 (LISTEN)
var reLsof = regexp.MustCompile(`^(?P<cmd>\S+)\s+(?P<pid>\d+)\s+(?P<user>\S+)\s+.*\sTCP\s+(?P<addr>\S+)\s+\((?P<state>[^)]+)\)\s*$`)

type lsofLine struct {
	cmd   string
	user  string
	addr  string
	state string
	pid   int
}

func parseLsofLine(line string) (lsofLine, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "COMMAND") {
		return lsofLine{}, false
	}
	m := reLsof.FindStringSubmatch(line)
	if m == nil {
		return lsofLine{}, false
	}
	cmd := m[reLsof.SubexpIndex("cmd")]
	user := m[reLsof.SubexpIndex("user")]
	addr := m[reLsof.SubexpIndex("addr")]
	state := strings.ToUpper(strings.TrimSpace(m[reLsof.SubexpIndex("state")]))
	pid := parseInt(m[reLsof.SubexpIndex("pid")])
	if pid <= 0 {
		return lsofLine{}, false
	}
	return lsofLine{cmd: cmd, user: user, addr: addr, state: state, pid: pid}, true
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
