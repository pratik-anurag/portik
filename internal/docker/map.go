package docker

import (
	"bytes"
	"os/exec"
	"strings"

	"github.com/pratik-anurag/portik/internal/model"
)

func MapPort(port int, proto string) model.DockerMap {
	m := model.DockerMap{Checked: true}
	if _, err := exec.LookPath("docker"); err != nil {
		return m
	}

	out, err := exec.Command("docker", "ps", "--format", "{{.ID}} {{.Names}}").Output()
	if err != nil {
		return m
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) < 2 {
			continue
		}
		id := strings.TrimSpace(parts[0])
		name := strings.TrimSpace(parts[1])

		po, err := exec.Command("docker", "port", id).Output()
		if err != nil {
			continue
		}
		if mapped, cport := parseDockerPortOutput(po, port, proto); mapped {
			m.Mapped = true
			m.ContainerID = id
			m.ContainerName = name
			m.ContainerPort = cport
			m.ComposeService = composeServiceLabel(id)
			return m
		}
	}
	return m
}

func parseDockerPortOutput(b []byte, hostPort int, proto string) (bool, string) {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		parts := strings.Split(l, "->")
		if len(parts) != 2 {
			continue
		}
		left := strings.TrimSpace(parts[0])  // "5432/tcp"
		right := strings.TrimSpace(parts[1]) // "0.0.0.0:5432" or "[::]:5432"
		if !strings.HasSuffix(left, "/"+proto) {
			continue
		}
		if strings.HasSuffix(right, ":"+itoa(hostPort)) {
			return true, left
		}
	}
	return false, ""
}

func composeServiceLabel(containerID string) string {
	cmd := exec.Command("docker", "inspect", "-f", `{{ index .Config.Labels "com.docker.compose.service" }}`, containerID)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	_ = cmd.Run()
	return strings.TrimSpace(buf.String())
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [32]byte
	i := len(b)
	x := n
	for x > 0 {
		i--
		b[i] = byte('0' + x%10)
		x /= 10
	}
	return string(b[i:])
}
