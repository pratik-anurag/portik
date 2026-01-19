package cli

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/pratik-anurag/portik/internal/history"
	"github.com/pratik-anurag/portik/internal/inspect"
	"github.com/pratik-anurag/portik/internal/render"
	"github.com/pratik-anurag/portik/internal/sys"
)

func runKill(args []string) int {
	fs := flag.NewFlagSet("kill", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	c := parseCommon(fs)

	var timeoutStr string
	var force bool
	fs.StringVar(&timeoutStr, "timeout", "5s", "grace period before SIGKILL")
	fs.BoolVar(&force, "force", false, "allow killing processes not owned by your user (danger)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "kill: missing <port>")
		return 2
	}
	port, err := parsePort(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "kill:", err)
		return 2
	}
	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "kill: invalid --timeout")
		return 2
	}

	rep, err := inspect.InspectPort(port, c.Proto, inspect.Options{EnableDocker: c.Docker, IncludeConnections: false})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	_ = history.Record(rep)

	target, ok := rep.PrimaryListener()
	if !ok || target.PID <= 0 {
		fmt.Fprintln(os.Stderr, "No listening process found for this port.")
		return 1
	}

	if !force {
		if err := sys.EnsureSameUser(target.PID); err != nil {
			fmt.Fprintln(os.Stderr, "Refusing to kill process not owned by your user. Use --force to override.")
			fmt.Fprintln(os.Stderr, "Details:", err)
			return 1
		}
	}

	if !c.Yes {
		fmt.Printf("Kill pid %d (%s) listening on %d/%s? [y/N]: ", target.PID, target.ProcName, port, c.Proto)
		var resp string
		_, _ = fmt.Fscanln(os.Stdin, &resp)
		if resp != "y" && resp != "Y" {
			fmt.Println("Aborted.")
			return 0
		}
	}

	res := sys.TerminateProcess(target.PID, timeout)
	fmt.Print(render.ActionResult(res))
	return res.ExitCode
}
