package receipt

import (
	"fmt"
	"strings"
	"time"
)

// Summary returns a short human-readable text for r. It is for display only;
// the signed bytes are the source of truth.
func Summary(r Receipt) string {
	var b strings.Builder
	fmt.Fprintf(&b, "backend:  %s\n", r.Backend)
	fmt.Fprintf(&b, "image:    %s\n", r.Image.Digest)
	fmt.Fprintf(&b, "command:  %s\n", strings.Join(r.Argv, " "))
	if r.Killed != "" {
		fmt.Fprintf(&b, "result:   killed (%s), exit %d\n", r.Killed, r.ExitCode)
	} else {
		fmt.Fprintf(&b, "result:   exit %d\n", r.ExitCode)
	}
	fmt.Fprintf(&b, "duration: %s\n", (time.Duration(r.DurationMS) * time.Millisecond).String())

	counts := map[string]int{}
	for _, e := range r.Diff.Entries {
		counts[e.Op]++
	}
	fmt.Fprintf(&b, "diff:     %d add, %d modify, %d delete, %d opaque", counts["add"], counts["modify"], counts["delete"], counts["opaque"])
	if r.Diff.Truncated {
		b.WriteString(" (truncated)")
	}
	b.WriteByte('\n')

	allowed, denied := 0, 0
	for _, c := range r.Connections {
		if c.Allowed {
			allowed++
		} else {
			denied++
		}
	}
	fmt.Fprintf(&b, "network:  %d allowed, %d denied\n", allowed, denied)
	fmt.Fprintf(&b, "memory:   %.1f MiB peak\n", float64(r.Cgroup.MemoryPeakBytes)/(1<<20))
	fmt.Fprintf(&b, "pids:     %d peak\n", r.Cgroup.PIDsPeak)
	return b.String()
}
