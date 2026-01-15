//go:build !linux && !darwin

package platform

type FirewallStatus struct {
	Active  bool
	Name    string
	Details string
}

func FirewallStatus() FirewallStatus {
	return FirewallStatus{}
}
