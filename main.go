package main

import (
	"os"

	"github.com/pratik-anurag/portik/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
