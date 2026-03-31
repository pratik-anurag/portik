package history

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/pratik-anurag/portik/internal/model"
)

const (
	maxEntriesPerPort     = 200
	historyStoreVersion   = 2
	historyDBFilename     = "history.db"
	legacyHistoryFilename = "history.json"
	historyDBEnv          = "PORTIK_HISTORY_DB"
	legacyHistoryJSONEnv  = "PORTIK_HISTORY_JSON"
	sqliteBusyTimeoutMS   = 5000
)

type Store struct {
	Version int                         `json:"version"`
	Ports   map[string][]OwnershipEvent `json:"ports"` // key: "5432/tcp"
}

type OwnershipEvent struct {
	At             time.Time `json:"at"`
	Port           int       `json:"port"`
	Proto          string    `json:"proto"`
	PID            int32     `json:"pid,omitempty"`
	ProcName       string    `json:"proc_name,omitempty"`
	Cmdline        string    `json:"cmdline,omitempty"`
	User           string    `json:"user,omitempty"`
	DockerMapped   bool      `json:"docker_mapped,omitempty"`
	ContainerID    string    `json:"container_id,omitempty"`
	ContainerName  string    `json:"container_name,omitempty"`
	ComposeService string    `json:"compose_service,omitempty"`
	Signature      string    `json:"signature"`
}

type View struct {
	Key      string           `json:"key"`
	Events   []OwnershipEvent `json:"events"`
	Top      []TopOwner       `json:"top"`
	Patterns []Pattern        `json:"patterns,omitempty"`
}

type Pattern struct {
	Kind    string `json:"kind"`              // hour-of-day|day-of-week|owner-at-hour
	Summary string `json:"summary"`           // human readable
	Details string `json:"details,omitempty"` // extra info
}

type TopOwner struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}

func Load() (*Store, error) {
	db, err := openDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	return loadFromDB(context.Background(), db)
}

func Save(s *Store) error {
	db, err := openDB()
	if err != nil {
		return err
	}
	defer db.Close()

	if s == nil {
		s = &Store{Version: historyStoreVersion, Ports: map[string][]OwnershipEvent{}}
	}

	return withImmediateTx(context.Background(), db, func(conn *sql.Conn) error {
		if _, err := conn.ExecContext(context.Background(), `DELETE FROM ownership_events`); err != nil {
			return err
		}

		keys := make([]string, 0, len(s.Ports))
		for key := range s.Ports {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		for _, key := range keys {
			events := s.Ports[key]
			for _, ev := range events {
				if err := insertEvent(context.Background(), conn, ev); err != nil {
					return err
				}
			}
			if len(events) > 0 {
				if err := prunePortHistory(context.Background(), conn, events[0].Port, events[0].Proto); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func Record(rep model.Report) error {
	db, err := openDB()
	if err != nil {
		return err
	}
	defer db.Close()

	ev := eventFromReport(rep)
	ctx := context.Background()

	return withImmediateTx(ctx, db, func(conn *sql.Conn) error {
		var lastSig string
		err := conn.QueryRowContext(ctx, `
			SELECT signature
			FROM ownership_events
			WHERE port = ? AND proto = ?
			ORDER BY at_unix_ns DESC, id DESC
			LIMIT 1
		`, ev.Port, ev.Proto).Scan(&lastSig)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil && lastSig == ev.Signature {
			return nil
		}

		if err := insertEvent(ctx, conn, ev); err != nil {
			return err
		}
		return prunePortHistory(ctx, conn, ev.Port, ev.Proto)
	})
}

func (s *Store) ViewPortSince(port int, cutoff time.Time, detectPatterns bool) View {
	var all []OwnershipEvent
	var key string

	for _, proto := range []string{"tcp", "udp"} {
		k := fmt.Sprintf("%d/%s", port, proto)
		evs := s.Ports[k]
		var filtered []OwnershipEvent
		for _, e := range evs {
			if e.At.After(cutoff) {
				filtered = append(filtered, e)
			}
		}
		if len(filtered) > 0 && key == "" {
			key = k
		}
		all = append(all, filtered...)
	}

	sort.Slice(all, func(i, j int) bool { return all[i].At.Before(all[j].At) })

	view := View{Key: key, Events: all, Top: topOwners(all)}
	if detectPatterns {
		view.Patterns = DetectPatterns(all)
	}
	return view
}

func (s *Store) RecentOwners(port int, proto string, n int) []OwnershipEvent {
	if n <= 0 {
		return nil
	}
	key := fmt.Sprintf("%d/%s", port, proto)
	evs := s.Ports[key]
	if len(evs) == 0 {
		return nil
	}
	if len(evs) <= n {
		out := make([]OwnershipEvent, len(evs))
		copy(out, evs)
		return out
	}
	out := make([]OwnershipEvent, n)
	copy(out, evs[len(evs)-n:])
	return out
}

func DetectPatterns(events []OwnershipEvent) []Pattern {
	// Simple heuristics:
	// - if most events cluster around an hour-of-day -> "morning pattern around 09:00"
	// - if most events cluster on a weekday -> "often on Mondays"
	// - if a specific owner dominates that hour -> "postgres takes it around 09:00"
	if len(events) < 5 {
		return nil
	}

	hourCount := make([]int, 24)
	dowCount := make([]int, 7)
	ownerHour := map[int]map[string]int{}

	for _, e := range events {
		h := e.At.Local().Hour()
		d := int(e.At.Local().Weekday())
		hourCount[h]++
		dowCount[d]++

		lbl := OwnerLabel(e)
		if ownerHour[h] == nil {
			ownerHour[h] = map[string]int{}
		}
		ownerHour[h][lbl]++
	}

	topHour, topHourN := argmax(hourCount)
	total := len(events)
	ratio := float64(topHourN) / float64(total)

	var out []Pattern
	if topHourN >= 3 && ratio >= 0.45 {
		s := fmt.Sprintf("Events often occur around %02d:00 local time (%d/%d in window)", topHour, topHourN, total)
		if topHour >= 5 && topHour <= 11 {
			s = fmt.Sprintf("Looks like a morning pattern around %02d:00 local time (%d/%d)", topHour, topHourN, total)
		}
		out = append(out, Pattern{Kind: "hour-of-day", Summary: s})

		if bestOwner, bestN := bestOwnerAtHour(ownerHour[topHour]); bestN >= 2 && float64(bestN)/float64(topHourN) >= 0.6 {
			out = append(out, Pattern{
				Kind:    "owner-at-hour",
				Summary: fmt.Sprintf("%s is the most common owner around %02d:00 (%d/%d)", bestOwner, topHour, bestN, topHourN),
			})
		}
	}

	topDow, topDowN := argmax(dowCount)
	ratioDow := float64(topDowN) / float64(total)
	if topDowN >= 3 && ratioDow >= 0.45 {
		out = append(out, Pattern{
			Kind:    "day-of-week",
			Summary: fmt.Sprintf("Events often happen on %s (%d/%d in window)", weekdayName(topDow), topDowN, total),
		})
	}

	return out
}

func argmax(arr []int) (idx int, val int) {
	bestI := 0
	bestV := -1
	for i, v := range arr {
		if v > bestV {
			bestV = v
			bestI = i
		}
	}
	return bestI, bestV
}

func bestOwnerAtHour(m map[string]int) (string, int) {
	best := ""
	bestN := -1
	for k, v := range m {
		if v > bestN {
			bestN = v
			best = k
		}
	}
	return best, bestN
}

func weekdayName(d int) string {
	switch d {
	case 0:
		return "Sunday"
	case 1:
		return "Monday"
	case 2:
		return "Tuesday"
	case 3:
		return "Wednesday"
	case 4:
		return "Thursday"
	case 5:
		return "Friday"
	case 6:
		return "Saturday"
	default:
		return "Unknown"
	}
}

func topOwners(events []OwnershipEvent) []TopOwner {
	counts := map[string]int{}
	for _, e := range events {
		counts[OwnerLabel(e)]++
	}
	var tops []TopOwner
	for k, v := range counts {
		tops = append(tops, TopOwner{Label: k, Count: v})
	}
	sort.Slice(tops, func(i, j int) bool { return tops[i].Count > tops[j].Count })
	if len(tops) > 5 {
		tops = tops[:5]
	}
	return tops
}

func OwnerLabel(e OwnershipEvent) string {
	if e.DockerMapped {
		l := fmt.Sprintf("docker:%s", e.ContainerName)
		if e.ComposeService != "" {
			l += fmt.Sprintf(" (service=%s)", e.ComposeService)
		}
		return l
	}
	if e.ProcName != "" {
		if e.User != "" {
			return fmt.Sprintf("%s (%s)", e.ProcName, e.User)
		}
		return e.ProcName
	}
	if e.PID > 0 {
		return fmt.Sprintf("pid:%d", e.PID)
	}
	return "none"
}

func RenderView(v View) string {
	var b strings.Builder
	if v.Key == "" {
		b.WriteString("No history for this port in the selected window.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "History for %s\n\n", v.Key)

	if len(v.Top) > 0 {
		b.WriteString("Top owners\n")
		for _, t := range v.Top {
			fmt.Fprintf(&b, "- %s: %d\n", t.Label, t.Count)
		}
		b.WriteString("\n")
	}

	if len(v.Patterns) > 0 {
		b.WriteString("Detected patterns\n")
		for _, p := range v.Patterns {
			fmt.Fprintf(&b, "- %s\n", p.Summary)
			if p.Details != "" {
				fmt.Fprintf(&b, "  %s\n", p.Details)
			}
		}
		b.WriteString("\n")
	}

	b.WriteString("Events\n")
	for _, e := range v.Events {
		fmt.Fprintf(&b, "%s  %s\n", e.At.Format(time.RFC3339), OwnerLabel(e))
		if e.Cmdline != "" {
			fmt.Fprintf(&b, "  cmd: %s\n", e.Cmdline)
		}
	}
	return b.String()
}

func openDB() (*sql.DB, error) {
	p, err := dbPath()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", p)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(fmt.Sprintf(`PRAGMA busy_timeout = %d`, sqliteBusyTimeoutMS)); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.Exec(`PRAGMA journal_mode = WAL`); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS ownership_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			port INTEGER NOT NULL,
			proto TEXT NOT NULL,
			at_unix_ns INTEGER NOT NULL,
			pid INTEGER NOT NULL DEFAULT 0,
			proc_name TEXT NOT NULL DEFAULT '',
			cmdline TEXT NOT NULL DEFAULT '',
			user_name TEXT NOT NULL DEFAULT '',
			docker_mapped INTEGER NOT NULL DEFAULT 0,
			container_id TEXT NOT NULL DEFAULT '',
			container_name TEXT NOT NULL DEFAULT '',
			compose_service TEXT NOT NULL DEFAULT '',
			signature TEXT NOT NULL
		)
	`); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_ownership_events_port_proto_time
		ON ownership_events (port, proto, at_unix_ns DESC, id DESC)
	`); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := migrateLegacyJSON(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

func dbPath() (string, error) {
	if p := strings.TrimSpace(os.Getenv(historyDBEnv)); p != "" {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".portik", historyDBFilename), nil
}

func legacyJSONPath() (string, error) {
	if p := strings.TrimSpace(os.Getenv(legacyHistoryJSONEnv)); p != "" {
		return p, nil
	}
	p, err := dbPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(p), legacyHistoryFilename), nil
}

func loadFromDB(ctx context.Context, db *sql.DB) (*Store, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT port, proto, at_unix_ns, pid, proc_name, cmdline, user_name,
		       docker_mapped, container_id, container_name, compose_service, signature
		FROM ownership_events
		ORDER BY port ASC, proto ASC, at_unix_ns ASC, id ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	store := &Store{
		Version: historyStoreVersion,
		Ports:   map[string][]OwnershipEvent{},
	}

	for rows.Next() {
		ev, err := scanOwnershipEvent(rows)
		if err != nil {
			return nil, err
		}
		key := fmt.Sprintf("%d/%s", ev.Port, ev.Proto)
		store.Ports[key] = append(store.Ports[key], ev)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return store, nil
}

func scanOwnershipEvent(scanner interface {
	Scan(dest ...any) error
}) (OwnershipEvent, error) {
	var ev OwnershipEvent
	var atUnixNS int64
	var pid int64
	var dockerMapped int64
	if err := scanner.Scan(
		&ev.Port,
		&ev.Proto,
		&atUnixNS,
		&pid,
		&ev.ProcName,
		&ev.Cmdline,
		&ev.User,
		&dockerMapped,
		&ev.ContainerID,
		&ev.ContainerName,
		&ev.ComposeService,
		&ev.Signature,
	); err != nil {
		return OwnershipEvent{}, err
	}
	ev.At = timeFromUnixNS(atUnixNS)
	ev.PID = int32(pid)
	ev.DockerMapped = dockerMapped != 0
	return ev, nil
}

func timeFromUnixNS(ns int64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns).In(time.Local)
}

func eventFromReport(rep model.Report) OwnershipEvent {
	ev := OwnershipEvent{
		At:        rep.Generated,
		Port:      rep.Port,
		Proto:     rep.Proto,
		Signature: rep.Signature(),
	}

	if l, ok := rep.PrimaryListener(); ok {
		ev.PID = l.PID
		ev.ProcName = l.ProcName
		ev.Cmdline = l.Cmdline
		ev.User = l.User
	}

	if rep.Docker.Mapped {
		ev.DockerMapped = true
		ev.ContainerID = rep.Docker.ContainerID
		ev.ContainerName = rep.Docker.ContainerName
		ev.ComposeService = rep.Docker.ComposeService
	}

	return ev
}

func insertEvent(ctx context.Context, conn *sql.Conn, ev OwnershipEvent) error {
	_, err := conn.ExecContext(ctx, `
		INSERT INTO ownership_events (
			port, proto, at_unix_ns, pid, proc_name, cmdline, user_name,
			docker_mapped, container_id, container_name, compose_service, signature
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		ev.Port,
		ev.Proto,
		unixNS(ev.At),
		ev.PID,
		ev.ProcName,
		ev.Cmdline,
		ev.User,
		boolToInt(ev.DockerMapped),
		ev.ContainerID,
		ev.ContainerName,
		ev.ComposeService,
		ev.Signature,
	)
	return err
}

func unixNS(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func prunePortHistory(ctx context.Context, conn *sql.Conn, port int, proto string) error {
	_, err := conn.ExecContext(ctx, `
		DELETE FROM ownership_events
		WHERE id IN (
			SELECT id
			FROM ownership_events
			WHERE port = ? AND proto = ?
			ORDER BY at_unix_ns DESC, id DESC
			LIMIT -1 OFFSET ?
		)
	`, port, proto, maxEntriesPerPort)
	return err
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func withImmediateTx(ctx context.Context, db *sql.DB, fn func(conn *sql.Conn) error) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		return err
	}

	committed := false
	defer func() {
		if committed {
			return
		}
		_, _ = conn.ExecContext(ctx, `ROLLBACK`)
	}()

	if err := fn(conn); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return err
	}
	committed = true
	return nil
}

func migrateLegacyJSON(db *sql.DB) error {
	ctx := context.Background()
	return withImmediateTx(ctx, db, func(conn *sql.Conn) error {
		var existing int
		if err := conn.QueryRowContext(ctx, `SELECT COUNT(1) FROM ownership_events`).Scan(&existing); err != nil {
			return err
		}
		if existing > 0 {
			return nil
		}

		p, err := legacyJSONPath()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}

		var legacy Store
		if err := json.Unmarshal(data, &legacy); err != nil {
			return fmt.Errorf("load legacy history JSON %q: %w", p, err)
		}
		if len(legacy.Ports) == 0 {
			return nil
		}

		keys := make([]string, 0, len(legacy.Ports))
		for key := range legacy.Ports {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		for _, key := range keys {
			events := legacy.Ports[key]
			for _, ev := range events {
				if err := insertEvent(ctx, conn, ev); err != nil {
					return err
				}
			}
			if len(events) > 0 {
				if err := prunePortHistory(ctx, conn, events[0].Port, events[0].Proto); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
