package finding

import "testing"

func TestParseSeverity(t *testing.T) {
	for in, want := range map[string]Severity{"high": High, "MEDIUM": Medium, "Low": Low} {
		if got, ok := ParseSeverity(in); !ok || got != want {
			t.Errorf("ParseSeverity(%q) = %q, %v", in, got, ok)
		}
	}
	if _, ok := ParseSeverity("pass"); ok {
		t.Error("PASS is not a valid threshold")
	}
}

func TestNewReport(t *testing.T) {
	r := NewReport([]Finding{
		{RuleID: "a", Severity: Pass},
		{RuleID: "b", Severity: Medium},
		{RuleID: "c", Severity: High},
		{RuleID: "d", Severity: Low},
	})
	if r.Worst != High || r.Summary[High] != 1 || r.Summary[Pass] != 1 {
		t.Fatalf("got %+v", r)
	}
	if r.Findings[0].RuleID != "c" || r.Findings[3].RuleID != "a" {
		t.Fatalf("findings not sorted worst first: %+v", r.Findings)
	}
	if NewReport(nil).Worst != Pass {
		t.Fatal("an empty report is PASS")
	}
}
