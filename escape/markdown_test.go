package escape

import "testing"

func TestMarkdownGolden(t *testing.T) {
	// Deliberately out of order and with one missing cell (gvisor has no
	// 02-host-pids verdict), to check that Markdown sorts rows/columns and
	// renders a missing cell as "-" rather than panicking or guessing.
	verdicts := []Verdict{
		{CaseID: "02-host-pids", Backend: "native", Outcome: "exposed", Reason: "systemd visible"},
		{CaseID: "01-proc-root", Backend: "gvisor", Outcome: "blocked", Reason: "read refused"},
		{CaseID: "01-proc-root", Backend: "native", Outcome: "blocked", Reason: "read refused"},
	}

	want := "" +
		"| Case | gvisor | native |\n" +
		"|---|---|---|\n" +
		"| 01-proc-root | blocked: read refused | blocked: read refused |\n" +
		"| 02-host-pids | - | exposed: systemd visible |\n" +
		"\n" +
		"gvisor: blocked 1 / 1\n" +
		"native: blocked 1 / 2\n"

	got := Markdown(verdicts)
	if got != want {
		t.Errorf("Markdown() mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestMarkdownEmpty(t *testing.T) {
	got := Markdown(nil)
	want := "| Case |\n|---|\n\n"
	if got != want {
		t.Errorf("Markdown(nil) = %q, want %q", got, want)
	}
}
