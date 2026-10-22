// Package finding defines the result types shared by all analyzers.
package finding

import (
	"sort"
	"strings"
)

// Severity ranks how exploitable a finding is.
type Severity string

// Severities from most to least severe. Pass marks a trust relationship that
// was checked and found to be scoped correctly.
const (
	High   Severity = "HIGH"
	Medium Severity = "MEDIUM"
	Low    Severity = "LOW"
	Pass   Severity = "PASS"
)

// Rank orders severities; higher is worse.
func (s Severity) Rank() int {
	switch s {
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	default:
		return 0
	}
}

// ParseSeverity validates a user supplied severity name.
func ParseSeverity(s string) (Severity, bool) {
	for _, v := range []Severity{High, Medium, Low} {
		if string(v) == strings.ToUpper(s) {
			return v, true
		}
	}
	return "", false
}

// Finding is one observation about a trust relationship.
type Finding struct {
	RuleID      string   `json:"ruleId"`
	Severity    Severity `json:"severity"`
	Resource    string   `json:"resource"`
	Message     string   `json:"message"`
	Remediation string   `json:"remediation,omitempty"`
	// Source is the input file the resource came from.
	Source string `json:"source"`
}

// Rule documents a rule for --list and SARIF output.
type Rule struct {
	ID          string
	Severity    Severity
	Title       string
	Description string
}

// Report is the aggregated result of a run.
type Report struct {
	Findings []Finding        `json:"findings"`
	Summary  map[Severity]int `json:"summary"`
	Worst    Severity         `json:"worst"`
}

// NewReport sorts findings worst first and computes the summary.
func NewReport(fs []Finding) Report {
	r := Report{Findings: fs, Summary: map[Severity]int{High: 0, Medium: 0, Low: 0, Pass: 0}, Worst: Pass}
	for _, f := range fs {
		r.Summary[f.Severity]++
		if f.Severity.Rank() > r.Worst.Rank() {
			r.Worst = f.Severity
		}
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		return r.Findings[i].Severity.Rank() > r.Findings[j].Severity.Rank()
	})
	return r
}
