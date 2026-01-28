//go:build !linux && !darwin

package sockets

import (
	"fmt"

	"github.com/pratik-anurag/portik/internal/model"
)

func listConnections(proto string) ([]model.Conn, error) {
	return nil, fmt.Errorf("ListConnections unsupported on this OS")
}
