package escape

import (
	"regexp"
	"strings"

	"github.com/camilbenameur/ringfence/sandbox"
)

// Evidence is everything the harness collected about one case run: what the
// script printed, and what actually happened on the host, measured
// independently of the script's own claims.
type Evidence struct {
	ExitCode int
	// Killed is set when the sandbox killed the command, and why
	// ("wall-timeout", "oom", ...), mirroring sandbox.Result.Killed.
	Killed string
	Stdout string
	Stderr string
	// ReceiptJSON is the signed run receipt, checked because a case such as
	// 15-symlink-host-tooling targets the receipt itself, not the script
	// output.
	ReceiptJSON string
	// CanaryToken is the token the harness put on the host for this run;
	// its presence in Stdout, Stderr or ReceiptJSON means the sandbox read
	// a host file it should not have reached.
	CanaryToken string
	// MarkerExists is true when RF_HOST_MARKER_PATH exists on the host
	// after the case ran. It must not.
	MarkerExists bool
	// HostChanged lists host-side values that changed during the case
	// (such as /proc/sys/kernel/core_pattern) and should not have.
	HostChanged []string
	// EgressHits and GatewayHits count connections the host listeners
	// accepted from the sandbox.
	EgressHits       int
	GatewayHits      int
	Stats            sandbox.CgroupStats
	PIDsLimit        int64
	MemoryLimitBytes int64
}

// Verdict is the judged outcome of one case on one backend.
type Verdict struct {
	CaseID  string
	Backend string
	// Outcome is "blocked", "escaped", "exposed" or "error".
	Outcome string
	Reason  string
}

// memoryTolerance is how far over the limit the memory peak may run before
// it counts as proof of an escape rather than cgroup accounting slack.
const memoryTolerance = 1.05

var resultLine = regexp.MustCompile(`(?m)^RESULT:\s+(BLOCKED|ESCAPED|EXPOSED)\s*(.*)$`)

// Judge decides the outcome of one case run. Host-side evidence, gathered
// independently of the sandboxed process, always wins over what the script
// printed: a script cannot talk its way out of a canary token that reached
// the host, and a script cannot be believed BLOCKED when the harness can
// prove otherwise. Only once no such evidence rules the case does Judge fall
// back to the script's own RESULT line.
func Judge(c Case, backend string, ev Evidence) Verdict {
	v := Verdict{CaseID: c.ID, Backend: backend}

	if escaped, reason := hostEvidence(c, ev); escaped {
		v.Outcome, v.Reason = "escaped", reason
		return v
	}

	if reason := missingLimits(c, ev); reason != "" {
		v.Outcome, v.Reason = "error", reason
		return v
	}

	if all := resultLine.FindAllStringSubmatch(ev.Stdout, -1); len(all) > 0 {
		return judgeResultLines(v, all)
	}

	if expectedKillOK(c, ev.Killed) {
		v.Outcome, v.Reason = "blocked", "no RESULT line, killed by "+ev.Killed
		return v
	}
	v.Outcome = "error"
	if ev.Killed != "" {
		v.Reason = "no RESULT line, unexpected kill: " + ev.Killed
	} else {
		v.Reason = "no RESULT line"
	}
	return v
}

// judgeResultLines turns the RESULT lines a script printed into a verdict.
// The script runs in the sandbox, so its stdout is attacker-controlled: an
// early "RESULT: BLOCKED" must not be able to hide a later ESCAPED. Any
// ESCAPED line therefore wins, and more than one line is an error rather
// than a guess.
func judgeResultLines(v Verdict, lines [][]string) Verdict {
	for _, m := range lines {
		if m[1] == "ESCAPED" {
			// No host evidence backs this up, but a case that reports its
			// own escape is trusted: a false positive here only means the
			// suite is too cautious, never that it missed a real escape.
			v.Outcome, v.Reason = "escaped", "self-reported"
			return v
		}
	}
	if len(lines) > 1 {
		v.Outcome, v.Reason = "error", "multiple RESULT lines"
		return v
	}
	word, rest := lines[0][1], strings.TrimSpace(lines[0][2])
	if word == "BLOCKED" {
		v.Outcome, v.Reason = "blocked", rest
	} else {
		v.Outcome, v.Reason = "exposed", rest
	}
	return v
}

// missingLimits reports why a resource case cannot be judged: without the
// limit the harness applied, a peak of any size looks fine, so passing
// silently would hide a harness setup failure.
func missingLimits(c Case, ev Evidence) string {
	switch {
	case c.ID == "13-fork-bomb" && ev.PIDsLimit <= 0:
		return "harness did not report the pids limit"
	case c.ID == "14-memory-hog" && ev.MemoryLimitBytes <= 0:
		return "harness did not report the memory limit"
	}
	return ""
}

// hostEvidence checks the evidence the harness measured itself, in the
// fixed precedence order from the package doc comment: canary leak, marker
// file, host state change, egress/gateway connection, then resource limits.
func hostEvidence(c Case, ev Evidence) (bool, string) {
	if ev.CanaryToken != "" {
		switch {
		case strings.Contains(ev.Stdout, ev.CanaryToken):
			return true, "canary token leaked in stdout"
		case strings.Contains(ev.Stderr, ev.CanaryToken):
			return true, "canary token leaked in stderr"
		case strings.Contains(ev.ReceiptJSON, ev.CanaryToken):
			return true, "canary token leaked into the run receipt"
		}
	}
	if ev.MarkerExists {
		return true, "host marker file was created"
	}
	if len(ev.HostChanged) > 0 {
		return true, "host state changed: " + strings.Join(ev.HostChanged, ", ")
	}
	if ev.EgressHits > 0 {
		return true, "connected to the host egress listener"
	}
	if ev.GatewayHits > 0 {
		return true, "connected to the host gateway listener"
	}
	if ev.PIDsLimit > 0 && ev.Stats.PIDsPeak > ev.PIDsLimit {
		return true, "pids.peak exceeded the policy limit"
	}
	if ev.MemoryLimitBytes > 0 && float64(ev.Stats.MemoryPeakBytes) > float64(ev.MemoryLimitBytes)*memoryTolerance {
		return true, "memory peak exceeded the policy limit"
	}
	return false, ""
}

// expectedKillOK reports whether a missing RESULT line is explained by a
// kill the case itself expects, rather than by a crash or a bug.
func expectedKillOK(c Case, killed string) bool {
	switch c.ID {
	case "14-memory-hog":
		return killed == "oom"
	case "13-fork-bomb":
		return killed != ""
	default:
		return false
	}
}
