//go:build darwin

package platform

import (
	"os/exec"
	"strings"
)

type FirewallStatus struct {
	Active  bool
	Name    string
	Details string
}

func FirewallStatus() FirewallStatus {
	if _, err := exec.LookPath("pfctl"); err != nil {
		return FirewallStatus{}
	}
	out, err := exec.Command("pfctl", "-s", "info").Output()
	if err != nil {
		return FirewallStatus{}
	}
	txt := strings.ToLower(string(out))
	if strings.Contains(txt, "status: enabled") {
		return FirewallStatus{Active: true, Name: "pf"}
	}
	return FirewallStatus{}
}
