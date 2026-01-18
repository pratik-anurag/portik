package inspect

import (
	"testing"

	"github.com/pratik-anurag/portik/internal/model"
)

func TestDiagnoseIPv6Only(t *testing.T) {
	rep := model.Report{
		Port:  5432,
		Proto: "tcp",
		Listeners: []model.Listener{
			{Family: "ipv6", State: "LISTEN", PID: 10, ProcName: "x"},
		},
	}
	d := Diagnose(rep)
	found := false
	for _, x := range d {
		if x.Kind == "ipv6-only" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected ipv6-only diagnostic")
	}
}

func TestDiagnoseMissingPID(t *testing.T) {
	rep := model.Report{
		Port:  5432,
		Proto: "tcp",
		Listeners: []model.Listener{
			{Family: "ipv4", LocalIP: "127.0.0.1", State: "LISTEN"},
		},
	}
	d := Diagnose(rep)
	found := false
	for _, x := range d {
		if x.Kind == "pid-missing" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected pid-missing diagnostic")
	}
}

func TestDiagnoseLoopbackOnly(t *testing.T) {
	rep := model.Report{
		Port:  8080,
		Proto: "tcp",
		Listeners: []model.Listener{
			{Family: "ipv4", LocalIP: "127.0.0.1", State: "LISTEN", PID: 10, ProcName: "x"},
		},
	}
	d := Diagnose(rep)
	found := false
	for _, x := range d {
		if x.Kind == "loopback-only" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected loopback-only diagnostic")
	}
}

func TestDiagnoseMultiListener(t *testing.T) {
	rep := model.Report{
		Port:  9000,
		Proto: "tcp",
		Listeners: []model.Listener{
			{Family: "ipv4", LocalIP: "0.0.0.0", State: "LISTEN", PID: 10, ProcName: "a"},
			{Family: "ipv4", LocalIP: "0.0.0.0", State: "LISTEN", PID: 11, ProcName: "b"},
		},
	}
	d := Diagnose(rep)
	found := false
	for _, x := range d {
		if x.Kind == "multi-listener" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected multi-listener diagnostic")
	}
}
