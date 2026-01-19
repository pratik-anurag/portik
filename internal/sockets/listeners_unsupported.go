//go:build !linux && !darwin

package sockets

import (
	"fmt"

	"github.com/pratik-anurag/portik/internal/model"
)

func listListeners(proto string) ([]model.Listener, error) {
	return nil, fmt.Errorf("ListListeners unsupported on this OS")
}
