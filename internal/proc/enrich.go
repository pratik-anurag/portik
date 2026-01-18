package proc

import (
	"bytes"
	"os/exec"
	"strings"

	"github.com/pratik-anurag/portik/internal/model"
)

func Enrich(l *model.Listener) {
	if l.PID <= 0 {
		return
	}
	l.ProcName = firstNonEmpty(l.ProcName, psField(l.PID, "comm="))
	l.User = firstNonEmpty(l.User, psField(l.PID, "user="))
	l.Cmdline = firstNonEmpty(l.Cmdline, compact(psField(l.PID, "command=")))
	l.IsZombie = strings.Contains(strings.ToUpper(psField(l.PID, "stat=")), "Z")
}

func EnrichConn(c *model.Conn) {
	if c.PID <= 0 {
		return
	}
	c.ProcName = firstNonEmpty(c.ProcName, psField(c.PID, "comm="))
}

func psField(pid int32, format string) string {
	cmd := exec.Command("ps", "-p", itoa32(pid), "-o", format)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	_ = cmd.Run()
	return strings.TrimSpace(buf.String())
}

func compact(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 400 {
		return s[:400] + "…"
	}
	return s
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return strings.TrimSpace(b)
}

func itoa32(n int32) string {
	if n == 0 {
		return "0"
	}
	x := int(n)
	var b [32]byte
	i := len(b)
	for x > 0 {
		i--
		b[i] = byte('0' + x%10)
		x /= 10
	}
	return string(b[i:])
}
