//go:build !windows

package sys

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"syscall"
	"time"

	"github.com/pratik-anurag/portik/internal/model"
)

type ActionResult struct {
	ExitCode int    `json:"exit_code"`
	Summary  string `json:"summary"`
	Details  string `json:"details,omitempty"`
}

func EnsureSameUser(pid int32) error {
	cur, err := user.Current()
	if err != nil {
		return err
	}
	owner := psField(pid, "user=")
	if owner == "" {
		return errors.New("cannot determine process owner")
	}
	if cur.Uid == "0" {
		return nil
	}
	if !sameUser(cur.Username, owner) {
		return fmt.Errorf("process user %q != current user %q", owner, cur.Username)
	}
	return nil
}

func TerminateProcess(pid int32, timeout time.Duration) ActionResult {
	p, err := os.FindProcess(int(pid))
	if err != nil {
		return ActionResult{ExitCode: 1, Summary: "Failed to find process", Details: err.Error()}
	}
	_ = p.Signal(syscall.SIGTERM)

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return ActionResult{ExitCode: 0, Summary: "Process terminated"}
		}
		time.Sleep(150 * time.Millisecond)
	}
	_ = p.Signal(syscall.SIGKILL)
	time.Sleep(200 * time.Millisecond)
	if processAlive(pid) {
		return ActionResult{ExitCode: 1, Summary: "Failed to kill process", Details: "process still alive after SIGKILL"}
	}
	return ActionResult{ExitCode: 0, Summary: "Process killed (SIGKILL after timeout)"}
}

func SmartRestart(l model.Listener, timeout time.Duration) ActionResult {
	killRes := TerminateProcess(l.PID, timeout)
	if killRes.ExitCode != 0 {
		return ActionResult{ExitCode: 1, Summary: "Failed to stop process", Details: killRes.Summary + ": " + killRes.Details}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-lc", l.Cmdline)
	cmd.Dir = l.WorkingDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		return ActionResult{ExitCode: 1, Summary: "Failed to start process", Details: err.Error()}
	}
	return ActionResult{ExitCode: 0, Summary: "Process restarted", Details: fmt.Sprintf("Started pid %d", cmd.Process.Pid)}
}

func RestartDockerContainer(containerID string, timeout time.Duration) ActionResult {
	if containerID == "" {
		return ActionResult{ExitCode: 1, Summary: "Missing container ID"}
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return ActionResult{ExitCode: 1, Summary: "docker not found", Details: err.Error()}
	}
	sec := int(timeout.Seconds())
	if sec < 1 {
		sec = 1
	}
	out, err := exec.Command("docker", "restart", "-t", fmt.Sprintf("%d", sec), containerID).CombinedOutput()
	if err != nil {
		return ActionResult{ExitCode: 1, Summary: "docker restart failed", Details: string(bytes.TrimSpace(out))}
	}
	return ActionResult{ExitCode: 0, Summary: "Container restarted", Details: string(bytes.TrimSpace(out))}
}

func processAlive(pid int32) bool {
	cmd := exec.Command("ps", "-p", itoa32(pid))
	return cmd.Run() == nil
}

func psField(pid int32, format string) string {
	cmd := exec.Command("ps", "-p", itoa32(pid), "-o", format)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	_ = cmd.Run()
	return strings.TrimSpace(buf.String())
}

func itoa32(n int32) string {
	if n == 0 {
		return "0"
	}
	x := int(n)
	var b [32]byte
	i := len(b)
	for x > 0 {
		i--
		b[i] = byte('0' + x%10)
		x /= 10
	}
	return string(b[i:])
}

func sameUser(a, b string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	if a == b {
		return true
	}
	if i := strings.LastIndex(a, "\\"); i >= 0 {
		a = a[i+1:]
	}
	if i := strings.LastIndex(b, "\\"); i >= 0 {
		b = b[i+1:]
	}
	if i := strings.Index(a, "@"); i >= 0 {
		a = a[:i]
	}
	if i := strings.Index(b, "@"); i >= 0 {
		b = b[:i]
	}
	return a == b
}
