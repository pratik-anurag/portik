package sockets

import (
	"fmt"

	"portik/internal/model"
)

// ListListeners returns all LISTEN listeners for the given proto.
// proto: tcp|udp
func ListListeners(proto string) ([]model.Listener, error) {
	if proto != "tcp" && proto != "udp" {
		return nil, fmt.Errorf("unsupported proto: %s", proto)
	}
	return listListeners(proto)
}
