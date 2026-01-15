//go:build darwin

package platform

import (
	"os/exec"
	"strings"
)

type FirewallInfo struct {
	Active  bool
	Name    string
	Details string
}

func FirewallStatus() FirewallInfo {
	if _, err := exec.LookPath("pfctl"); err != nil {
		return FirewallInfo{}
	}
	out, err := exec.Command("pfctl", "-s", "info").Output()
	if err != nil {
		return FirewallInfo{}
	}
	txt := strings.ToLower(string(out))
	if strings.Contains(txt, "status: enabled") {
		return FirewallInfo{Active: true, Name: "pf"}
	}
	return FirewallInfo{}
}
