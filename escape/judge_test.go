package escape

import (
	"strings"
	"testing"

	"github.com/camilbenameur/sandmeter/sandbox"
)

func TestJudge(t *testing.T) {
	base := Case{ID: "01-proc-root"}

	tests := []struct {
		name    string
		c       Case
		ev      Evidence
		outcome string
		reason  string // substring, checked only when non-empty
	}{
		{
			name:    "blocked from RESULT line",
			c:       base,
			ev:      Evidence{Stdout: "setting up\nRESULT: BLOCKED read refused\n"},
			outcome: "blocked",
			reason:  "read refused",
		},
		{
			name:    "exposed from RESULT line",
			c:       base,
			ev:      Evidence{Stdout: "RESULT: EXPOSED bpf reachable\n"},
			outcome: "exposed",
			reason:  "bpf reachable",
		},
		{
			name:    "self-reported escape trusted without host evidence",
			c:       base,
			ev:      Evidence{Stdout: "RESULT: ESCAPED thinks it got out\n"},
			outcome: "escaped",
			reason:  "self-reported",
		},
		{
			name: "canary in stdout wins over a BLOCKED claim",
			c:    base,
			ev: Evidence{
				CanaryToken: "deadbeef",
				Stdout:      "token is deadbeef\nRESULT: BLOCKED nothing to see\n",
			},
			outcome: "escaped",
			reason:  "stdout",
		},
		{
			name: "canary in stderr",
			c:    base,
			ev: Evidence{
				CanaryToken: "deadbeef",
				Stderr:      "leaked deadbeef here",
				Stdout:      "RESULT: BLOCKED\n",
			},
			outcome: "escaped",
			reason:  "stderr",
		},
		{
			name: "canary in receipt",
			c:    base,
			ev: Evidence{
				CanaryToken: "deadbeef",
				ReceiptJSON: `{"note":"deadbeef"}`,
				Stdout:      "RESULT: BLOCKED\n",
			},
			outcome: "escaped",
			reason:  "receipt",
		},
		{
			name:    "marker exists wins over BLOCKED claim",
			c:       base,
			ev:      Evidence{MarkerExists: true, Stdout: "RESULT: BLOCKED fine\n"},
			outcome: "escaped",
			reason:  "marker",
		},
		{
			name:    "host state changed wins over EXPOSED claim",
			c:       base,
			ev:      Evidence{HostChanged: []string{"core_pattern"}, Stdout: "RESULT: EXPOSED write allowed\n"},
			outcome: "escaped",
			reason:  "core_pattern",
		},
		{
			name:    "egress hit wins",
			c:       Case{ID: "10-egress-none"},
			ev:      Evidence{EgressHits: 1, Stdout: "RESULT: BLOCKED connect refused\n"},
			outcome: "escaped",
			reason:  "egress",
		},
		{
			name:    "gateway hit wins",
			c:       Case{ID: "12-host-gateway"},
			ev:      Evidence{GatewayHits: 2, Stdout: "RESULT: BLOCKED connect refused\n"},
			outcome: "escaped",
			reason:  "gateway",
		},
		{
			name: "pids peak over limit wins",
			c:    Case{ID: "13-fork-bomb"},
			ev: Evidence{
				PIDsLimit: 64,
				Stats:     sandbox.CgroupStats{PIDsPeak: 65},
				Stdout:    "RESULT: BLOCKED fork refused\n",
			},
			outcome: "escaped",
			reason:  "pids.peak",
		},
		{
			name: "pids peak at limit is fine",
			c:    Case{ID: "13-fork-bomb"},
			ev: Evidence{
				PIDsLimit: 64,
				Stats:     sandbox.CgroupStats{PIDsPeak: 64},
				Stdout:    "RESULT: BLOCKED fork refused\n",
			},
			outcome: "blocked",
		},
		{
			name: "memory peak over 105% of limit wins",
			c:    Case{ID: "14-memory-hog"},
			ev: Evidence{
				MemoryLimitBytes: 1000,
				Stats:            sandbox.CgroupStats{MemoryPeakBytes: 1060},
				Stdout:           "RESULT: BLOCKED oom\n",
			},
			outcome: "escaped",
			reason:  "memory peak",
		},
		{
			name: "memory peak within 105% tolerance is fine",
			c:    Case{ID: "14-memory-hog"},
			ev: Evidence{
				MemoryLimitBytes: 1000,
				Stats:            sandbox.CgroupStats{MemoryPeakBytes: 1040},
				Stdout:           "RESULT: BLOCKED oom\n",
			},
			outcome: "blocked",
		},
		{
			name:    "earlier BLOCKED line cannot hide a later ESCAPED",
			c:       base,
			ev:      Evidence{Stdout: "RESULT: BLOCKED x\nRESULT: ESCAPED y\n"},
			outcome: "escaped",
			reason:  "self-reported",
		},
		{
			name:    "two non-escape RESULT lines are an error",
			c:       base,
			ev:      Evidence{Stdout: "RESULT: BLOCKED x\nRESULT: EXPOSED y\n"},
			outcome: "error",
			reason:  "multiple",
		},
		{
			name:    "fork bomb without a pids limit cannot be judged",
			c:       Case{ID: "13-fork-bomb"},
			ev:      Evidence{Stdout: "RESULT: BLOCKED x\n"},
			outcome: "error",
			reason:  "pids limit",
		},
		{
			name:    "memory hog without a memory limit cannot be judged",
			c:       Case{ID: "14-memory-hog"},
			ev:      Evidence{Stdout: "RESULT: BLOCKED x\n"},
			outcome: "error",
			reason:  "memory limit",
		},
		{
			name:    "missing RESULT line, expected oom kill",
			c:       Case{ID: "14-memory-hog"},
			ev:      Evidence{Killed: "oom", MemoryLimitBytes: 1000, Stdout: "allocating...\n"},
			outcome: "blocked",
			reason:  "oom",
		},
		{
			name:    "missing RESULT line, unexpected kill reason for that case",
			c:       Case{ID: "14-memory-hog"},
			ev:      Evidence{Killed: "wall-timeout", MemoryLimitBytes: 1000, Stdout: "allocating...\n"},
			outcome: "error",
			reason:  "wall-timeout",
		},
		{
			name:    "missing RESULT line, fork bomb killed by timeout",
			c:       Case{ID: "13-fork-bomb"},
			ev:      Evidence{Killed: "wall-timeout", PIDsLimit: 64, Stdout: "forking...\n"},
			outcome: "blocked",
		},
		{
			name:    "missing RESULT line, no kill at all, not a case with an expected kill",
			c:       base,
			ev:      Evidence{Stdout: "set up and then nothing\n"},
			outcome: "error",
			reason:  "no RESULT line",
		},
		{
			name:    "missing RESULT line, killed but case has no expected kill",
			c:       base,
			ev:      Evidence{Killed: "oom", Stdout: "set up\n"},
			outcome: "error",
			reason:  "oom",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := Judge(tt.c, "native", tt.ev)
			if v.CaseID != tt.c.ID || v.Backend != "native" {
				t.Errorf("Verdict identity = %+v", v)
			}
			if v.Outcome != tt.outcome {
				t.Errorf("Outcome = %q, want %q (reason: %q)", v.Outcome, tt.outcome, v.Reason)
			}
			if tt.reason != "" && !strings.Contains(v.Reason, tt.reason) {
				t.Errorf("Reason = %q, want it to contain %q", v.Reason, tt.reason)
			}
		})
	}
}
