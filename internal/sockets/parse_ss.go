package sockets

import (
	"regexp"
	"strings"
)

// ss -H -ltnp 'sport = :5432'
// LISTEN 0 4096 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=8123,fd=7))
var (
	reSS        = regexp.MustCompile(`^(?P<state>\S+)\s+\d+\s+\d+\s+(?P<laddr>\S+)\s+(?P<raddr>\S+)\s*(?P<users>users:\(\(.*\)\))?$`)
	reUsersPid  = regexp.MustCompile(`pid=(\d+)`)
	reUsersProc = regexp.MustCompile(`\(\("([^"]+)"`)
)

type ssLine struct {
	state string
	laddr string
	raddr string
	pid   int
	proc  string
}

func parseSSLine(line string) (ssLine, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return ssLine{}, false
	}
	m := reSS.FindStringSubmatch(line)
	if m == nil {
		return ssLine{}, false
	}
	state := strings.ToUpper(m[reSS.SubexpIndex("state")])
	laddr := m[reSS.SubexpIndex("laddr")]
	raddr := m[reSS.SubexpIndex("raddr")]
	pid, pname := parseUsers(m[reSS.SubexpIndex("users")])
	return ssLine{state: state, laddr: laddr, raddr: raddr, pid: pid, proc: pname}, true
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
	return pid, proc
}
