//go:build linux

package sockets

import "github.com/pratik-anurag/portik/internal/model"

func inspect(port int, proto string, includeConnections bool) ([]model.Listener, []model.Conn, error) {
	return inspectLinux(port, proto, includeConnections)
}
