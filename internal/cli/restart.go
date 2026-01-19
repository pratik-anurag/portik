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

func runRestart(args []string) int {
	fs := flag.NewFlagSet("restart", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	c := parseCommon(fs)

	var timeoutStr string
	var force bool
	var container bool
	fs.StringVar(&timeoutStr, "timeout", "10s", "grace period before force kill")
	fs.BoolVar(&force, "force", false, "allow restarting processes not owned by your user (danger)")
	fs.BoolVar(&container, "container", false, "restart mapped docker container instead (requires --docker)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "restart: missing <port>")
		return 2
	}
	port, err := parsePort(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "restart:", err)
		return 2
	}
	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "restart: invalid --timeout")
		return 2
	}

	rep, err := inspect.InspectPort(port, c.Proto, inspect.Options{EnableDocker: c.Docker, IncludeConnections: false})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	_ = history.Record(rep)

	if c.Docker && rep.Docker.Mapped && container {
		if !c.Yes {
			fmt.Printf("Restart Docker container %s (%s) mapping %d/%s? [y/N]: ",
				rep.Docker.ContainerID, rep.Docker.ContainerName, port, c.Proto)
			var resp string
			_, _ = fmt.Fscanln(os.Stdin, &resp)
			if resp != "y" && resp != "Y" {
				fmt.Println("Aborted.")
				return 0
			}
		}
		res := sys.RestartDockerContainer(rep.Docker.ContainerID, timeout)
		fmt.Print(render.ActionResult(res))
		return res.ExitCode
	}

	target, ok := rep.PrimaryListener()
	if !ok || target.PID <= 0 {
		fmt.Fprintln(os.Stderr, "No listening process found for this port.")
		if c.Docker && rep.Docker.Mapped {
			fmt.Fprintln(os.Stderr, "Note: port maps to Docker container; rerun with --container to restart it.")
		}
		return 1
	}
	if target.Cmdline == "" {
		fmt.Fprintln(os.Stderr, "Cannot restart: command line not available. Try running with sudo.")
		return 1
	}

	if !force {
		if err := sys.EnsureSameUser(target.PID); err != nil {
			fmt.Fprintln(os.Stderr, "Refusing to restart process not owned by your user. Use --force to override.")
			fmt.Fprintln(os.Stderr, "Details:", err)
			return 1
		}
	}

	if !c.Yes {
		fmt.Printf("Restart pid %d (%s)? This will stop and re-run:\n  %s\nProceed? [y/N]: ",
			target.PID, target.ProcName, target.Cmdline)
		var resp string
		_, _ = fmt.Fscanln(os.Stdin, &resp)
		if resp != "y" && resp != "Y" {
			fmt.Println("Aborted.")
			return 0
		}
	}

	res := sys.SmartRestart(target.PID, target.Cmdline, timeout)
	fmt.Print(render.ActionResult(res))
	return res.ExitCode
}
