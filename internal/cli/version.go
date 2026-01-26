package cli

import "fmt"

// These variables can be overridden at build time via -ldflags
var (
	version = "dev"
	commit  = ""
)

func runVersion() int {
	if commit != "" {
		fmt.Printf("portik %s (commit %s)\n", version, commit)
	} else {
		fmt.Printf("portik %s\n", version)
	}
	return 0
}
