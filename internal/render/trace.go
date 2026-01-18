package render

import (
	"fmt"
	"strings"

	"github.com/pratik-anurag/portik/internal/trace"
)

func Trace(port int, proto string, steps []trace.Step, opt Options) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %d/%s\n", label("TRACE", opt), port, proto)

	if len(steps) == 0 {
		b.WriteString("  (no trace data)\n")
		return b.String()
	}

	for _, s := range steps {
		b.WriteString(fmt.Sprintf("  - %s\n", s.Summary))
		if s.Details != "" {
			b.WriteString(fmt.Sprintf("    %s\n", s.Details))
		}
	}
	return b.String()
}
