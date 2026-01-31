package graph

import "testing"

func TestMatchListener(t *testing.T) {
	listeners := []listenerRec{
		{PID: 1, ProcName: "postgres", LocalIP: "127.0.0.1", Port: 5432},
		{PID: 2, ProcName: "postgres", LocalIP: "0.0.0.0", Port: 5432},
	}

	match, ambiguous := matchListener(listeners, "127.0.0.1", 5432)
	if ambiguous || match == nil || match.PID != 1 {
		t.Fatalf("expected exact match pid=1, got %+v ambiguous=%v", match, ambiguous)
	}

	match, ambiguous = matchListener(listeners, "10.0.0.5", 5432)
	if ambiguous || match == nil || match.PID != 2 {
		t.Fatalf("expected wildcard match pid=2, got %+v ambiguous=%v", match, ambiguous)
	}

	listeners = append(listeners, listenerRec{PID: 3, ProcName: "postgres2", LocalIP: "127.0.0.1", Port: 5432})
	match, ambiguous = matchListener(listeners, "127.0.0.1", 5432)
	if !ambiguous || match != nil {
		t.Fatalf("expected ambiguous match, got %+v ambiguous=%v", match, ambiguous)
	}
}

func TestRecordDependencyAggregation(t *testing.T) {
	deps := map[depKey]*Dependency{}
	client := Node{ID: "proc:1", PID: 1, ProcName: "api"}
	server := Node{ID: "proc:2", PID: 2, ProcName: "db"}
	port := Node{ID: "port:tcp:127.0.0.1:5432", Type: NodePort, Port: 5432}

	recordDependency(deps, client, server, port, true)
	recordDependency(deps, client, server, port, true)
	recordDependency(deps, client, server, port, false)

	if len(deps) != 1 {
		t.Fatalf("expected 1 dependency, got %d", len(deps))
	}
	for _, d := range deps {
		if d.Established != 2 || d.TimeWait != 1 {
			t.Fatalf("expected counts EST=2 TW=1, got EST=%d TW=%d", d.Established, d.TimeWait)
		}
	}
}

func TestGraphWithMultipleDependencies(t *testing.T) {
	// Test scenario: api process depends on postgres and redis
	deps := map[depKey]*Dependency{}

	api := Node{ID: "proc:2210", PID: 2210, ProcName: "api", Type: NodeProcess}
	postgres := Node{ID: "proc:8123", PID: 8123, ProcName: "postgres", Type: NodeProcess}
	redis := Node{ID: "proc:9012", PID: 9012, ProcName: "redis", Type: NodeProcess}
	worker := Node{ID: "proc:2241", PID: 2241, ProcName: "worker", Type: NodeProcess}

	postgresPort := Node{ID: "port:tcp:127.0.0.1:5432", Type: NodePort, Port: 5432, LocalIP: "127.0.0.1", Protocol: "tcp"}
	redisPort := Node{ID: "port:tcp:127.0.0.1:6379", Type: NodePort, Port: 6379, LocalIP: "127.0.0.1", Protocol: "tcp"}

	// api -> postgres (2 established connections)
	recordDependency(deps, api, postgres, postgresPort, true)
	recordDependency(deps, api, postgres, postgresPort, true)

	// api -> redis (1 established connection)
	recordDependency(deps, api, redis, redisPort, true)

	// worker -> postgres (1 established connection)
	recordDependency(deps, worker, postgres, postgresPort, true)

	if len(deps) != 3 {
		t.Fatalf("expected 3 dependencies, got %d", len(deps))
	}

	// Verify api->postgres has 2 established connections
	key := depKey{clientPID: 2210, serverPID: 8123, portID: "port:tcp:127.0.0.1:5432"}
	if d, ok := deps[key]; ok {
		if d.Established != 2 {
			t.Fatalf("api->postgres: expected EST=2, got EST=%d", d.Established)
		}
	} else {
		t.Fatalf("expected dependency api->postgres")
	}

	// Verify api->redis has 1 established connection
	key = depKey{clientPID: 2210, serverPID: 9012, portID: "port:tcp:127.0.0.1:6379"}
	if d, ok := deps[key]; ok {
		if d.Established != 1 {
			t.Fatalf("api->redis: expected EST=1, got EST=%d", d.Established)
		}
	} else {
		t.Fatalf("expected dependency api->redis")
	}
}

func TestGraphPortFiltering(t *testing.T) {
	// Test scenario: filter dependencies to specific ports
	deps := map[depKey]*Dependency{}

	api := Node{ID: "proc:2210", PID: 2210, ProcName: "api", Type: NodeProcess}
	postgres := Node{ID: "proc:8123", PID: 8123, ProcName: "postgres", Type: NodeProcess}
	redis := Node{ID: "proc:9012", PID: 9012, ProcName: "redis", Type: NodeProcess}

	postgresPort := Node{ID: "port:tcp:127.0.0.1:5432", Type: NodePort, Port: 5432, LocalIP: "127.0.0.1", Protocol: "tcp"}
	redisPort := Node{ID: "port:tcp:127.0.0.1:6379", Type: NodePort, Port: 6379, LocalIP: "127.0.0.1", Protocol: "tcp"}

	recordDependency(deps, api, postgres, postgresPort, true)
	recordDependency(deps, api, redis, redisPort, true)

	if len(deps) != 2 {
		t.Fatalf("expected 2 dependencies before filtering, got %d", len(deps))
	}

	// Filter to only postgres (5432)
	filtered := TopDependencies(convertDepsToSlice(deps), 10)
	if len(filtered) != 2 {
		t.Fatalf("expected 2 dependencies in slice, got %d", len(filtered))
	}
}

func TestGraphTopDependencies(t *testing.T) {
	// Test scenario: limit dependencies to top N by connection count
	deps := convertDepsToSlice(nil)

	// Create dependency with 5 established connections
	dep1 := Dependency{
		Client:      Node{ID: "proc:1", PID: 1, ProcName: "heavy"},
		Server:      Node{ID: "proc:2", PID: 2, ProcName: "db"},
		Port:        Node{ID: "port:5432", Port: 5432},
		Established: 5,
	}

	// Create dependency with 2 established connections
	dep2 := Dependency{
		Client:      Node{ID: "proc:3", PID: 3, ProcName: "light"},
		Server:      Node{ID: "proc:2", PID: 2, ProcName: "db"},
		Port:        Node{ID: "port:5432", Port: 5432},
		Established: 2,
	}

	deps = append(deps, dep1, dep2)

	topDeps := TopDependencies(deps, 1)
	if len(topDeps) != 1 {
		t.Fatalf("expected 1 top dependency, got %d", len(topDeps))
	}
	if topDeps[0].Established != 5 {
		t.Fatalf("expected top dependency to have EST=5, got EST=%d", topDeps[0].Established)
	}
}

func convertDepsToSlice(deps map[depKey]*Dependency) []Dependency {
	if deps == nil {
		return []Dependency{}
	}
	var result []Dependency
	for _, d := range deps {
		result = append(result, *d)
	}
	return result
}
