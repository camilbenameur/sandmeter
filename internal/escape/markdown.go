package escape

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// Markdown renders a result table: one row per case, one column per
// backend, each cell the outcome and its short reason. A totals line per
// backend follows. Case IDs and backends are sorted, so the table is the
// same regardless of the order verdicts were given in.
func Markdown(verdicts []Verdict) string {
	caseSet := map[string]bool{}
	backendSet := map[string]bool{}
	cell := map[[2]string]Verdict{}
	for _, v := range verdicts {
		caseSet[v.CaseID] = true
		backendSet[v.Backend] = true
		cell[[2]string{v.CaseID, v.Backend}] = v
	}
	cases := sortedKeys(caseSet)
	backends := sortedKeys(backendSet)

	var b strings.Builder
	b.WriteString("| Case |")
	for _, be := range backends {
		fmt.Fprintf(&b, " %s |", cellText(be))
	}
	b.WriteString("\n|---|")
	for range backends {
		b.WriteString("---|")
	}
	b.WriteString("\n")

	for _, c := range cases {
		fmt.Fprintf(&b, "| %s |", cellText(c))
		for _, be := range backends {
			v, ok := cell[[2]string{c, be}]
			if !ok {
				b.WriteString(" - |")
				continue
			}
			text := v.Outcome
			if v.Reason != "" {
				text += ": " + v.Reason
			}
			fmt.Fprintf(&b, " %s |", cellText(text))
		}
		b.WriteString("\n")
	}

	b.WriteString("\n")
	for _, be := range backends {
		total, blocked := 0, 0
		for _, c := range cases {
			v, ok := cell[[2]string{c, be}]
			if !ok {
				continue
			}
			total++
			if v.Outcome == "blocked" {
				blocked++
			}
		}
		fmt.Fprintf(&b, "%s: blocked %d / %d\n", cellText(be), blocked, total)
	}
	return b.String()
}

// maxCellRunes caps one cell so a verbose reason cannot swamp the table.
const maxCellRunes = 120

var cellEscaper = strings.NewReplacer(
	"\\", "\\\\", "|", "\\|", "<", "&lt;", ">", "&gt;", "&", "&amp;", "`", "\\`",
)

// cellText makes sandbox-controlled text safe to publish in a table cell:
// control characters (newlines included) become spaces, the text is
// truncated, and the characters that would open a column, an HTML tag or a
// code span are escaped.
func cellText(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	if r := []rune(s); len(r) > maxCellRunes {
		s = string(r[:maxCellRunes]) + "..."
	}
	return cellEscaper.Replace(s)
}

func sortedKeys(set map[string]bool) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
