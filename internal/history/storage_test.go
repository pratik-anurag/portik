package history

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pratik-anurag/portik/internal/model"
)

func TestRecordLoadAndRecentOwners(t *testing.T) {
	configureHistoryTestPaths(t)

	base := time.Date(2026, 4, 1, 10, 0, 0, 0, time.Local)

	rep1 := testReport(5432, "tcp", base, 100, "postgres")
	rep2 := testReport(5432, "tcp", base.Add(1*time.Minute), 100, "postgres")
	rep3 := testReport(5432, "tcp", base.Add(2*time.Minute), 200, "postgres-restarted")

	if err := Record(rep1); err != nil {
		t.Fatalf("record rep1: %v", err)
	}
	if err := Record(rep2); err != nil {
		t.Fatalf("record rep2: %v", err)
	}
	if err := Record(rep3); err != nil {
		t.Fatalf("record rep3: %v", err)
	}

	store, err := Load()
	if err != nil {
		t.Fatalf("load store: %v", err)
	}

	events := store.Ports["5432/tcp"]
	if len(events) != 2 {
		t.Fatalf("expected 2 events after dedupe, got %d", len(events))
	}
	if events[0].PID != 100 || events[1].PID != 200 {
		t.Fatalf("unexpected event pids: %+v", events)
	}

	recent := store.RecentOwners(5432, "tcp", 5)
	if len(recent) != 2 {
		t.Fatalf("expected 2 recent owners, got %d", len(recent))
	}
	if recent[1].ProcName != "postgres-restarted" {
		t.Fatalf("expected most recent owner to be postgres-restarted, got %+v", recent[1])
	}
}

func TestRecordPrunesPerPortHistory(t *testing.T) {
	configureHistoryTestPaths(t)

	base := time.Date(2026, 4, 1, 11, 0, 0, 0, time.Local)
	total := maxEntriesPerPort + 5
	for i := 0; i < total; i++ {
		rep := testReport(8080, "tcp", base.Add(time.Duration(i)*time.Second), int32(i+1), "svc")
		if err := Record(rep); err != nil {
			t.Fatalf("record event %d: %v", i, err)
		}
	}

	store, err := Load()
	if err != nil {
		t.Fatalf("load store: %v", err)
	}

	events := store.Ports["8080/tcp"]
	if len(events) != maxEntriesPerPort {
		t.Fatalf("expected %d events, got %d", maxEntriesPerPort, len(events))
	}
	if events[0].PID != 6 {
		t.Fatalf("expected oldest retained pid to be 6, got %d", events[0].PID)
	}
	if events[len(events)-1].PID != int32(total) {
		t.Fatalf("expected latest retained pid to be %d, got %d", total, events[len(events)-1].PID)
	}
}

func TestLoadMigratesLegacyJSON(t *testing.T) {
	dbPath, legacyPath := configureHistoryTestPaths(t)

	legacy := &Store{
		Version: 1,
		Ports: map[string][]OwnershipEvent{
			"3000/tcp": {
				{
					At:        time.Date(2026, 4, 1, 9, 30, 0, 0, time.Local),
					Port:      3000,
					Proto:     "tcp",
					PID:       321,
					ProcName:  "devserver",
					User:      "me",
					Signature: "sig-1",
				},
			},
		},
	}
	data, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatalf("marshal legacy store: %v", err)
	}
	if err := os.WriteFile(legacyPath, data, 0o644); err != nil {
		t.Fatalf("write legacy json: %v", err)
	}

	store, err := Load()
	if err != nil {
		t.Fatalf("load migrated store: %v", err)
	}
	events := store.Ports["3000/tcp"]
	if len(events) != 1 {
		t.Fatalf("expected 1 migrated event, got %d", len(events))
	}
	if events[0].ProcName != "devserver" {
		t.Fatalf("unexpected migrated event: %+v", events[0])
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("expected sqlite db to exist at %s: %v", dbPath, err)
	}

	store, err = Load()
	if err != nil {
		t.Fatalf("reload store after migration: %v", err)
	}
	if got := len(store.Ports["3000/tcp"]); got != 1 {
		t.Fatalf("expected migration to run once, got %d events after reload", got)
	}
}

func configureHistoryTestPaths(t *testing.T) (string, string) {
	t.Helper()

	dir := t.TempDir()
	dbPath := filepath.Join(dir, historyDBFilename)
	legacyPath := filepath.Join(dir, legacyHistoryFilename)
	t.Setenv(historyDBEnv, dbPath)
	t.Setenv(legacyHistoryJSONEnv, legacyPath)
	return dbPath, legacyPath
}

func testReport(port int, proto string, at time.Time, pid int32, procName string) model.Report {
	return model.Report{
		Port:      port,
		Proto:     proto,
		Generated: at,
		Listeners: []model.Listener{
			{
				LocalIP:   "127.0.0.1",
				LocalPort: port,
				Family:    "ipv4",
				State:     "LISTEN",
				PID:       pid,
				ProcName:  procName,
				User:      "me",
				Cmdline:   procName + " --port",
			},
		},
	}
}
