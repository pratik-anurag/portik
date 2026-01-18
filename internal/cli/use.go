package cli

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/pratik-anurag/portik/internal/reserve"
	"github.com/pratik-anurag/portik/internal/use"
)

// portik use --ports 3000-3999 -- <cmd> [args...]
// Exposes PORT=<picked> to the child process.
// Optionally replaces "{PORT}" in argv (no shell needed) or runs via `sh -lc` (shell expansion).
func runUse(args []string) int {
	fs := flag.NewFlagSet("use", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var portsSpec string
	var proto string
	var bind string
	var attempts int
	var template bool
	var shell bool
	var printOnly bool
	var timeoutStr string

	fs.StringVar(&portsSpec, "ports", "", "ports spec (recommended range): e.g. 3000-3999. If omitted, uses ephemeral port")
	fs.StringVar(&proto, "proto", "tcp", "protocol: tcp|udp (default tcp)")
	fs.StringVar(&bind, "bind", "127.0.0.1", "bind address used to test availability (default 127.0.0.1)")
	fs.IntVar(&attempts, "attempts", 64, "random attempts before linear scan (range mode)")
	fs.BoolVar(&template, "template", false, "replace {PORT} occurrences in args before exec (no shell)")
	fs.BoolVar(&shell, "shell", false, "run command through `sh -lc` (enables $PORT expansion)")
	fs.BoolVar(&printOnly, "print", false, "print chosen port and exit (do not run command)")
	fs.StringVar(&timeoutStr, "timeout", "3s", "max time allowed to find a free port")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if proto != "tcp" && proto != "udp" {
		fmt.Fprintln(os.Stderr, "use: invalid --proto (tcp|udp)")
		return 2
	}

	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil || timeout <= 0 {
		fmt.Fprintln(os.Stderr, "use: invalid --timeout")
		return 2
	}

	cmdArgs := fs.Args()
	if !printOnly && len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "use: missing command. Example:")
		fmt.Fprintln(os.Stderr, "  portik use --ports 3000-3999 -- npm run dev")
		return 2
	}

	// Pick a free port (range if provided, else ephemeral).
	port, err := use.PickFreePort(use.PickOptions{
		Proto:     proto,
		Bind:      bind,
		PortsSpec: portsSpec,
		Attempts:  attempts,
		Timeout:   timeout,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "use:", err)
		return 1
	}

	if printOnly {
		fmt.Println(port)
		return 0
	}

	// Run the child process with PORT set.
	code, err := use.RunWithPort(use.RunOptions{
		Port:        port,
		Proto:       proto,
		Bind:        bind,
		Args:        cmdArgs,
		Template:    template,
		Shell:       shell,
		EnvVarName:  "PORT",
		ExtraEnv:    nil,
		ReserveHint: reserve.FreeOptions{Proto: proto, Bind: bind, Attempts: attempts},
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		Stdin:       os.Stdin,
	})
	if err != nil {
		// Preserve exit code if available
		if code != 0 {
			return code
		}
		fmt.Fprintln(os.Stderr, "use:", err)
		return 1
	}
	return code
}
