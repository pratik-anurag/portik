package inspect

import (
	"fmt"
	"os/user"

	"github.com/pratik-anurag/portik/internal/model"
	"github.com/pratik-anurag/portik/internal/platform"
)

func Diagnose(rep model.Report) []model.Diagnostic {
	var out []model.Diagnostic

	// privileged port
	if rep.Port < 1024 {
		if u, err := user.Current(); err == nil && u.Uid != "0" {
			out = append(out, model.Diagnostic{
				Kind:     "permission",
				Severity: "info",
				Summary:  "Privileged port may require admin/root",
				Details:  fmt.Sprintf("Port %d is < 1024. On many systems binding requires root/admin privileges.", rep.Port),
				Action:   "Try running with sudo or choose a higher port.",
			})
		}
	}

	// in-use
	if l, ok := rep.PrimaryListener(); ok && l.PID > 0 && l.State == "LISTEN" {
		out = append(out, model.Diagnostic{
			Kind:     "in-use",
			Severity: "info",
			Summary:  "Port is in use",
			Details:  fmt.Sprintf("pid %d (%s) is listening on %d/%s", l.PID, l.ProcName, rep.Port, rep.Proto),
			Action:   "Stop it: portik kill <port>  |  Restart it: portik restart <port>",
		})
	}

	// missing pid
	pidCount := 0
	for _, l := range rep.Listeners {
		if l.PID > 0 {
			pidCount++
		}
	}
	if len(rep.Listeners) > 0 && pidCount == 0 {
		out = append(out, model.Diagnostic{
			Kind:     "pid-missing",
			Severity: "warn",
			Summary:  "Process details unavailable",
			Details:  "Port has listeners but no owning PID/cmdline was found. This can happen without elevated privileges.",
			Action:   "Re-run with sudo/admin, or check OS-specific permissions.",
		})
	}

	// multiple listeners
	if len(rep.Listeners) > 1 {
		pids := map[int32]bool{}
		for _, l := range rep.Listeners {
			if l.PID > 0 {
				pids[l.PID] = true
			}
		}
		if len(pids) > 1 {
			out = append(out, model.Diagnostic{
				Kind:     "multi-listener",
				Severity: "info",
				Summary:  "Multiple processes are listening on the same port",
				Details:  "More than one PID owns listeners for this port. This is common with SO_REUSEPORT or multiple instances.",
				Action:   "Check if multiple instances were started, or if the service is configured to share the port.",
			})
		}
	}

	// ipv6-only
	hasV4 := false
	hasV6 := false
	for _, l := range rep.Listeners {
		if l.Family == "ipv4" {
			hasV4 = true
		}
		if l.Family == "ipv6" {
			hasV6 = true
		}
	}
	if hasV6 && !hasV4 && rep.Proto == "tcp" && len(rep.Listeners) > 0 {
		out = append(out, model.Diagnostic{
			Kind:     "ipv6-only",
			Severity: "warn",
			Summary:  "Only IPv6 listener detected (IPv4 bind confusion)",
			Details:  "A process is listening on IPv6 only. Binding on 0.0.0.0:<port> may fail or appear unreachable from IPv4.",
			Action:   "Bind to [::] or enable dual-stack, or ensure the app listens on IPv4 too.",
		})
	}

	// loopback-only
	loopbackOnly := listenersLoopbackOnly(rep.Listeners)
	if loopbackOnly {
		out = append(out, model.Diagnostic{
			Kind:     "loopback-only",
			Severity: "info",
			Summary:  "Service is bound to loopback only",
			Details:  "The listener is bound to 127.0.0.1 or ::1. It will not accept connections from other hosts.",
			Action:   "Bind to 0.0.0.0 or [::] if you need external access.",
		})
	}

	// firewall
	if len(rep.Listeners) > 0 && !loopbackOnly {
		fw := platform.FirewallStatus()
		if fw.Active {
			summary := "Host firewall appears to be active"
			if fw.Name != "" {
				summary = fmt.Sprintf("Host firewall appears to be active (%s)", fw.Name)
			}
			out = append(out, model.Diagnostic{
				Kind:     "firewall",
				Severity: "info",
				Summary:  summary,
				Details:  "A local firewall is running; inbound connections to this port may be blocked even though the service is listening.",
				Action:   "Check firewall rules and allow the port if external access is required.",
			})
		}
	}

	// TIME_WAIT
	timeWait := 0
	for _, c := range rep.Connections {
		if c.State == "TIME_WAIT" && c.LocalPort == rep.Port {
			timeWait++
		}
	}
	if timeWait > 0 {
		out = append(out, model.Diagnostic{
			Kind:     "time-wait",
			Severity: "info",
			Summary:  "TIME_WAIT sockets present",
			Details:  fmt.Sprintf("Found %d TIME_WAIT connections involving local port %d. Rapid restarts can cause transient address-in-use errors.", timeWait, rep.Port),
			Action:   "Wait a few seconds and retry, or ensure the service uses SO_REUSEADDR where appropriate.",
		})
	}

	// zombie
	for _, l := range rep.Listeners {
		if l.IsZombie {
			out = append(out, model.Diagnostic{
				Kind:     "zombie",
				Severity: "warn",
				Summary:  "Zombie process detected owning the port",
				Details:  fmt.Sprintf("pid %d (%s) appears to be a zombie. Parent process must reap it.", l.PID, l.ProcName),
				Action:   "Restart the parent process, or reboot if the zombie cannot be reaped.",
			})
			break
		}
	}

	// docker
	if rep.Docker.Mapped {
		out = append(out, model.Diagnostic{
			Kind:     "docker",
			Severity: "info",
			Summary:  "Port is mapped from a Docker container",
			Details: fmt.Sprintf("Host port %d/%s is mapped to %s (%s) service=%s containerPort=%s",
				rep.Port, rep.Proto, rep.Docker.ContainerID, rep.Docker.ContainerName, rep.Docker.ComposeService, rep.Docker.ContainerPort),
			Action: "Use: portik restart <port> --docker --container",
		})
	}

	// env hints
	if platform.InContainer() {
		out = append(out, model.Diagnostic{
			Kind:     "env",
			Severity: "info",
			Summary:  "Running inside a container",
			Details:  "Socket-to-process mapping can be limited across container/host boundaries.",
			Action:   "Run portik on the host; use --docker if relevant.",
		})
	}
	if platform.InWSL() {
		out = append(out, model.Diagnostic{
			Kind:     "env",
			Severity: "info",
			Summary:  "Running in WSL",
			Details:  "WSL networking can differ from native Linux across Windows/WSL boundary.",
			Action:   "Check if the port is bound in Windows or inside WSL; run portik in both contexts if needed.",
		})
	}
	if platform.InVM() {
		out = append(out, model.Diagnostic{
			Kind:     "vm",
			Severity: "info",
			Summary:  "Running inside a VM",
			Details:  "Mapping host ports to services across VM boundaries is limited without hypervisor integration.",
			Action:   "Run portik in the same OS context where the service is running (host vs guest).",
		})
	}

	return model.DedupeDiagnostics(out)
}

func isLoopbackAddr(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1" || (len(ip) > 4 && ip[:4] == "127.")
}

func isAnyAddr(ip string) bool {
	switch ip {
	case "", "0.0.0.0", "::", "*":
		return true
	default:
		return false
	}
}

func listenersLoopbackOnly(listeners []model.Listener) bool {
	if len(listeners) == 0 {
		return false
	}
	for _, l := range listeners {
		if isAnyAddr(l.LocalIP) || !isLoopbackAddr(l.LocalIP) {
			return false
		}
	}
	return true
}
