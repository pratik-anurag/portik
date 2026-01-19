package sockets

import "github.com/pratik-anurag/portik/internal/model"

// Inspect returns listeners (and optionally connections) for a given port/proto.
// Implementations are OS-specific (linux/darwin).
func Inspect(port int, proto string, includeConnections bool) ([]model.Listener, []model.Conn, error) {
	return inspect(port, proto, includeConnections)
}
