package tui

import (
	"fmt"
	"time"

	"github.com/pratik-anurag/portik/internal/history"
)

func sparkForPort(st *history.Store, port int, proto string, window time.Duration, buckets int) string {
	if st == nil || buckets <= 1 {
		return ""
	}
	key := fmt.Sprintf("%d/%s", port, proto)
	evs := st.Ports[key]
	if len(evs) == 0 {
		return ""
	}
	now := time.Now()
	start := now.Add(-window)

	counts := make([]int, buckets)
	for i := 1; i < len(evs); i++ {
		t := evs[i].At
		if t.Before(start) || t.After(now) {
			continue
		}
		frac := float64(t.Sub(start)) / float64(window)
		idx := int(frac * float64(buckets))
		if idx < 0 {
			idx = 0
		}
		if idx >= buckets {
			idx = buckets - 1
		}
		counts[idx]++
	}
	return spark(counts)
}

func spark(counts []int) string {
	blocks := []rune("▁▂▃▄▅▆▇█")
	max := 0
	for _, c := range counts {
		if c > max {
			max = c
		}
	}
	if max == 0 {
		return ""
	}
	out := make([]rune, 0, len(counts))
	for _, c := range counts {
		level := int(float64(c) / float64(max) * float64(len(blocks)-1))
		if level < 0 {
			level = 0
		}
		if level >= len(blocks) {
			level = len(blocks) - 1
		}
		out = append(out, blocks[level])
	}
	return string(out)
}
