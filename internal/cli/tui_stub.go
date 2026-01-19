//go:build !tui

package cli

import (
	"fmt"
	"os"
)

func runTUI(args []string) int {
	fmt.Fprintln(os.Stderr, "portik was built without TUI support.")
	fmt.Fprintln(os.Stderr, "Rebuild with: go build -tags tui .")
	return 2
}
