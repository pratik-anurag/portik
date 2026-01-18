package trace

import (
	"testing"

	"github.com/pratik-anurag/portik/internal/model"
	"github.com/pratik-anurag/portik/internal/proctree"
)

func TestStepsBasic(t *testing.T) {
	rep := model.Report{
		Port:  5432,
		Proto: "tcp",
		Listeners: []model.Listener{
			{LocalIP: "127.0.0.1", LocalPort: 5432, State: "LISTEN", PID: 10, ProcName: "postgres", User: "me"},
		},
	}
	chain := []proctree.Proc{{PID: 10, Name: "postgres"}, {PID: 1, Name: "launchd"}}
	started := proctree.StartedBy{Kind: "launchd", Details: "parent chain includes launchd"}
	steps := Steps(rep, chain, started)

	if len(steps) == 0 {
		t.Fatalf("expected steps")
	}
	foundLoopback := false
	for _, s := range steps {
		if s.Kind == "loopback" {
			foundLoopback = true
		}
	}
	if !foundLoopback {
		t.Fatalf("expected loopback step")
	}
}
