package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/OTA-EITA/oidc-trust-audit/internal/finding"
)

func sample() finding.Report {
	return finding.NewReport([]finding.Finding{
		{RuleID: "AWS-GHA-001", Severity: finding.High, Resource: "arn:aws:iam::1:role/ci", Message: "no sub | condition", Remediation: "pin it", Source: "roles.json"},
		{RuleID: "PASS", Severity: finding.Pass, Resource: "arn:aws:iam::1:role/ok", Message: "pinned", Source: "roles.json"},
	})
}

func TestParseFormat(t *testing.T) {
	for _, f := range Formats {
		if got, err := ParseFormat(string(f)); err != nil || got != f {
			t.Errorf("ParseFormat(%q) = %q, %v", f, got, err)
		}
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Error("unknown formats must be rejected")
	}
}

func TestTableAndQuiet(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, sample(), Table, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "role/ok") || !strings.Contains(b.String(), "worst=HIGH high=1 medium=0 low=0 pass=1") {
		t.Errorf("table:\n%s", b.String())
	}
	b.Reset()
	if err := Write(&b, sample(), Table, Options{Quiet: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "role/ok") {
		t.Errorf("quiet must hide PASS:\n%s", b.String())
	}
}

func TestMarkdownEscapesPipes(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, sample(), Markdown, Options{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `no sub \| condition`) {
		t.Errorf("markdown:\n%s", b.String())
	}
}

func TestJSONRoundTrip(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, sample(), JSON, Options{}); err != nil {
		t.Fatal(err)
	}
	var got finding.Report
	if err := json.Unmarshal(b.Bytes(), &got); err != nil || got.Worst != finding.High || len(got.Findings) != 2 {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestSARIF(t *testing.T) {
	var b bytes.Buffer
	opt := Options{
		Version: "v0.1.0",
		Rules:   []finding.Rule{{ID: "AWS-GHA-001", Severity: finding.High, Title: "t", Description: "d"}},
		LineOf:  func(source, resource string) int { return 7 },
	}
	if err := Write(&b, sample(), SARIF, opt); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(b.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	run := log.Runs[0]
	if log.Version != "2.1.0" || run.Tool.Driver.Version != "v0.1.0" || len(run.Tool.Driver.Rules) != 1 {
		t.Fatalf("driver: %+v", run.Tool.Driver)
	}
	if run.Tool.Driver.Rules[0].Properties.SecuritySeverity != "8.0" {
		t.Errorf("security-severity: %+v", run.Tool.Driver.Rules[0].Properties)
	}
	if len(run.Results) != 1 {
		t.Fatalf("PASS findings must not become SARIF results: %+v", run.Results)
	}
	res := run.Results[0]
	if res.Level != "error" || res.Locations[0].PhysicalLocation.ArtifactLocation.URI != "roles.json" || res.Locations[0].PhysicalLocation.Region.StartLine != 7 {
		t.Errorf("result: %+v", res)
	}
	if !strings.Contains(res.Message.Text, "Fix: pin it") {
		t.Errorf("message: %q", res.Message.Text)
	}
}
