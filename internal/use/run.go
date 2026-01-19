package use

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/pratik-anurag/portik/internal/reserve"
)

type RunOptions struct {
	Port       int
	Proto      string
	Bind       string
	Args       []string // command + args
	Template   bool     // replace {PORT} in args
	Shell      bool     // run using sh -lc
	EnvVarName string   // default "PORT"

	ExtraEnv []string // additional env KEY=VAL

	// not used to "reserve" (would block child bind); kept for future extensions
	ReserveHint reserve.FreeOptions

	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader
}

// RunWithPort runs a child process with PORT=<port> set.
// - If Shell=true: runs `sh -lc "<cmd...>"` so $PORT works.
// - Else: execs Args directly; if Template=true replaces "{PORT}" in args.
func RunWithPort(opt RunOptions) (int, error) {
	if opt.Port <= 0 || opt.Port > 65535 {
		return 0, fmt.Errorf("invalid port: %d", opt.Port)
	}
	if len(opt.Args) == 0 {
		return 0, fmt.Errorf("missing command args")
	}
	if opt.EnvVarName == "" {
		opt.EnvVarName = "PORT"
	}

	var cmd *exec.Cmd

	if opt.Shell {
		// join args into a shell command string (safe enough for dev usage)
		cmdStr := shellJoin(opt.Args)
		cmd = exec.Command("sh", "-lc", cmdStr)
	} else {
		argv := make([]string, len(opt.Args))
		copy(argv, opt.Args)
		if opt.Template {
			p := fmt.Sprintf("%d", opt.Port)
			for i := range argv {
				argv[i] = strings.ReplaceAll(argv[i], "{PORT}", p)
			}
		}
		cmd = exec.Command(argv[0], argv[1:]...)
	}

	// stdio
	if opt.Stdout != nil {
		cmd.Stdout = opt.Stdout
	}
	if opt.Stderr != nil {
		cmd.Stderr = opt.Stderr
	}
	if opt.Stdin != nil {
		cmd.Stdin = opt.Stdin
	}

	// env
	env := os.Environ()
	env = append(env, fmt.Sprintf("%s=%d", opt.EnvVarName, opt.Port))
	env = append(env, opt.ExtraEnv...)
	cmd.Env = env

	err := cmd.Run()
	if err == nil {
		return 0, nil
	}

	// Propagate child exit code if possible.
	if ee, ok := err.(*exec.ExitError); ok {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
			if ws.Signaled() {
				// Common convention: 128 + signal
				return 128 + int(ws.Signal()), err
			}
			return ws.ExitStatus(), err
		}
		return 1, err
	}

	return 1, err
}

// shellJoin minimally joins argv into a single shell line.
// This is intentionally simple; for safer quoting, prefer Template mode.
func shellJoin(argv []string) string {
	var b strings.Builder
	for i, a := range argv {
		if i > 0 {
			b.WriteByte(' ')
		}
		// naive quoting: wrap in single quotes and escape existing single quotes
		if strings.ContainsAny(a, " \t\n\"'\\$") {
			b.WriteByte('\'')
			b.WriteString(strings.ReplaceAll(a, "'", `'\''`))
			b.WriteByte('\'')
		} else {
			b.WriteString(a)
		}
	}
	return b.String()
}
