//go:build linux

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
	if _, err := exec.LookPath("ufw"); err == nil {
		out, err := exec.Command("ufw", "status").Output()
		if err == nil && strings.Contains(strings.ToLower(string(out)), "status: active") {
			return FirewallInfo{Active: true, Name: "ufw"}
		}
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		out, err := exec.Command("firewall-cmd", "--state").Output()
		if err == nil && strings.Contains(strings.ToLower(string(out)), "running") {
			return FirewallInfo{Active: true, Name: "firewalld"}
		}
	}
	return FirewallInfo{}
}
