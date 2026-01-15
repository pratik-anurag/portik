//go:build linux

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
	if _, err := exec.LookPath("ufw"); err == nil {
		out, err := exec.Command("ufw", "status").Output()
		if err == nil && strings.Contains(strings.ToLower(string(out)), "status: active") {
			return FirewallStatus{Active: true, Name: "ufw"}
		}
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		out, err := exec.Command("firewall-cmd", "--state").Output()
		if err == nil && strings.Contains(strings.ToLower(string(out)), "running") {
			return FirewallStatus{Active: true, Name: "firewalld"}
		}
	}
	return FirewallStatus{}
}
