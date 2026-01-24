package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type Report struct {
	Port        int          `json:"port"`
	Proto       string       `json:"proto"`
	Generated   time.Time    `json:"generated"`
	Host        HostSummary  `json:"host"`
	User        UserSummary  `json:"user"`
	Listeners   []Listener   `json:"listeners"`
	Connections []Conn       `json:"connections,omitempty"`
	Docker      DockerMap    `json:"docker"`
	Diagnostics []Diagnostic `json:"diagnostics"`
}

type HostSummary struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Hostname string `json:"hostname"`
	Kernel   string `json:"kernel,omitempty"`
}

type UserSummary struct {
	Username string `json:"username,omitempty"`
}

type Listener struct {
	LocalIP   string `json:"local_ip"`
	LocalPort int    `json:"local_port"`
	Family    string `json:"family"` // ipv4|ipv6|unknown
	State     string `json:"state"`  // LISTEN|BOUND
	PID       int32  `json:"pid,omitempty"`

	ProcName   string `json:"proc_name,omitempty"`
	Cmdline    string `json:"cmdline,omitempty"`
	WorkingDir string `json:"working_dir,omitempty"`
	User       string `json:"user,omitempty"`
	IsZombie   bool   `json:"is_zombie,omitempty"`
}

type Conn struct {
	LocalIP    string `json:"local_ip"`
	LocalPort  int    `json:"local_port"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort int    `json:"remote_port"`
	Family     string `json:"family"`
	State      string `json:"state"`

	PID      int32  `json:"pid,omitempty"`
	ProcName string `json:"proc_name,omitempty"`
}

type DockerMap struct {
	Checked        bool   `json:"checked"`
	Mapped         bool   `json:"mapped"`
	ContainerID    string `json:"container_id,omitempty"`
	ContainerName  string `json:"container_name,omitempty"`
	ComposeService string `json:"compose_service,omitempty"`
	ContainerPort  string `json:"container_port,omitempty"` // like 5432/tcp
}

type Diagnostic struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"` // info|warn|error
	Summary  string `json:"summary"`
	Details  string `json:"details,omitempty"`
	Action   string `json:"action,omitempty"`
}

func (r Report) PrimaryListener() (Listener, bool) {
	if len(r.Listeners) == 0 {
		return Listener{}, false
	}
	for _, l := range r.Listeners {
		if l.PID > 0 {
			return l, true
		}
	}
	return r.Listeners[0], true
}

func (r Report) Signature() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d/%s|", r.Port, r.Proto)
	for _, l := range r.Listeners {
		fmt.Fprintf(&b, "L:%s:%d:%s:%d|", l.LocalIP, l.LocalPort, l.ProcName, l.PID)
	}
	if r.Docker.Mapped {
		fmt.Fprintf(&b, "D:%s:%s:%s|", r.Docker.ContainerID, r.Docker.ContainerName, r.Docker.ComposeService)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func DedupeDiagnostics(in []Diagnostic) []Diagnostic {
	seen := map[string]bool{}
	var out []Diagnostic
	for _, d := range in {
		k := d.Kind + "|" + d.Summary
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, d)
	}
	return out
}

type LintFinding struct {
	Severity string `json:"severity"` // info|warn|error
	Code     string `json:"code"`
	Summary  string `json:"summary"`
	Details  string `json:"details,omitempty"`
	Action   string `json:"action,omitempty"`

	Proto   string `json:"proto"`
	Port    int    `json:"port"`
	LocalIP string `json:"local_ip,omitempty"`

	PID      int32  `json:"pid,omitempty"`
	ProcName string `json:"proc_name,omitempty"`
	User     string `json:"user,omitempty"`
}
