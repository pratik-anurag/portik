//go:build darwin

package sockets

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/pratik-anurag/portik/internal/model"
)

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
		parsed, ok := parseLsofLine(line)
		if !ok {
			continue
		}
		cwd := getCwd(parsed.pid)
		ip, p := parseLsofAddr(parsed.addr)
		fam := familyFromIP(ip)

		if parsed.state == "LISTEN" && p == port {
			listeners = append(listeners, model.Listener{
				LocalIP:    ip,
				LocalPort:  p,
				Family:     fam,
				State:      "LISTEN",
				PID:        int32(parsed.pid),
				ProcName:   parsed.cmd,
				WorkingDir: cwd,
				User:       parsed.user,
			})
		} else if includeConnections {
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
	// $ lsof -a -p <pid> -d cwd -Fn
	//   p<pid>
	//   fcwd
	//   n<path>
	args := []string{"-a", "-p", strconv.Itoa(pid), "-d", "cwd", "-Fn"}
	out, err := exec.Command("lsof", args...).Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) < 3 || len(lines[2]) < 2 {
		return ""
	}
	return strings.TrimSpace(lines[2][1:])
}
