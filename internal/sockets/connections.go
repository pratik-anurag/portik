package sockets

import (
	"fmt"

	"github.com/pratik-anurag/portik/internal/model"
)

// ListConnections returns all TCP connections.
// proto: tcp only for now.
func ListConnections(proto string) ([]model.Conn, error) {
	if proto != "tcp" {
		return nil, fmt.Errorf("unsupported proto: %s", proto)
	}
	return listConnections(proto)
}
