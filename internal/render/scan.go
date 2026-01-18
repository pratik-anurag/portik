package render

import (
	"fmt"
	"strings"
)

type ScanRows []struct {
	Port   int
	Proto  string
	Status string
	Owner  string
	PID    int32
	Addr   string
	Docker string
	Hint   string
	Error  string
}

func ScanTableRows(rows ScanRows) string {
	var b strings.Builder

	b.WriteString("PORT   STATUS   OWNER                 PID     ADDR                 DOCKER              HINT\n")
	b.WriteString("────   ──────   ────────────────────  ──────  ───────────────────  ──────────────────  ─────────────────────\n")

	for _, r := range rows {
		owner := trunc(r.Owner, 20)
		addr := trunc(r.Addr, 19)
		docker := trunc(r.Docker, 18)
		hint := trunc(r.Hint, 20)
		if r.Error != "" {
			hint = trunc("ERR: "+r.Error, 20)
		}
		pid := "-"
		if r.PID > 0 {
			pid = fmt.Sprintf("%d", r.PID)
		}
		fmt.Fprintf(&b, "%-5d  %-7s  %-20s  %-6s  %-19s  %-18s  %-20s\n",
			r.Port, r.Status, owner, pid, addr, docker, hint)
	}
	return b.String()
}
