//go:build !linux && !darwin

package platform

type FirewallInfo struct {
	Active  bool
	Name    string
	Details string
}

func FirewallStatus() FirewallInfo {
	return FirewallInfo{}
}
