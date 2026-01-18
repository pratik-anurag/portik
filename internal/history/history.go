package history

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pratik-anurag/portik/internal/model"
)

const maxEntriesPerPort = 200

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

func historyPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".portik", "history.json"), nil
}

func Load() (*Store, error) {
	p, err := historyPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return &Store{Version: 1, Ports: map[string][]OwnershipEvent{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var s Store
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if s.Ports == nil {
		s.Ports = map[string][]OwnershipEvent{}
	}
	return &s, nil
}

func Save(s *Store) error {
	p, err := historyPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o644)
}

func Record(rep model.Report) error {
	s, err := Load()
	if err != nil {
		return err
	}
	key := fmt.Sprintf("%d/%s", rep.Port, rep.Proto)

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

	events := append(s.Ports[key], ev)

	// Dedup consecutive identical signatures
	if len(events) >= 2 {
		last := events[len(events)-1]
		prev := events[len(events)-2]
		if last.Signature == prev.Signature {
			events = events[:len(events)-1]
		}
	}
	if len(events) > maxEntriesPerPort {
		events = events[len(events)-maxEntriesPerPort:]
	}

	s.Ports[key] = events
	return Save(s)
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
	// - if most events cluster around an hour-of-day → "morning pattern around 09:00"
	// - if most events cluster on a weekday → "often on Mondays"
	// - if a specific owner dominates that hour → "postgres takes it around 09:00"
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
