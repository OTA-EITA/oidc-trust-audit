package gcpwif

import (
	"os"
	"strings"
	"testing"

	"github.com/OTA-EITA/oidc-trust-audit/internal/finding"
)

func TestAnalyzeFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/providers.json")
	if err != nil {
		t.Fatal(err)
	}
	ps, err := ParseProviders(data, "providers.json")
	if err != nil {
		t.Fatal(err)
	}
	fs := Analyze(ps)
	got := map[string]string{}
	for _, f := range fs {
		got[f.Resource[strings.LastIndex(f.Resource, "/")+1:]] += f.RuleID + " "
	}
	want := map[string]string{
		"open":   "GCP-GHA-001 ",
		"prefix": "GCP-GHA-003 ",
		"by-id":  "PASS ",
		"gitlab": "GCP-OIDC-001 ",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got["old"]; ok {
		t.Error("disabled providers must be skipped")
	}
}

func TestAnalyzeGitHubCondition(t *testing.T) {
	mk := func(id string, sev finding.Severity, msg, fix string) finding.Finding {
		return finding.Finding{RuleID: id, Severity: sev}
	}
	cases := []struct {
		cond string
		want string
	}{
		{"assertion.repository_owner_id == '1234'", "PASS"},
		{"'1234' == assertion.repository_owner_id", "PASS"},
		{"assertion.repository_owner_id in ['1', '2']", "PASS"},
		{"assertion.repository_owner == 'example-org'", "GCP-GHA-004"},
		{"assertion.repository_owner=='example-org'", "GCP-GHA-004"},
		{"assertion.repository_owner_id=='1234'", "PASS"},
		{"assertion.repository == 'example-org/api'", "GCP-GHA-004"},
		{"assertion.repository.startsWith('example-org/')", "PASS"},
		{"assertion.repository.startsWith('example-org')", "GCP-GHA-003"},
		{"assertion.repository_owner.startsWith('example')", "GCP-GHA-003"},
		{"assertion.sub.startsWith('repo:example-org/')", "PASS"},
		{"assertion.sub.startsWith('repo:example')", "GCP-GHA-003"},
		{"assertion.ref == 'refs/heads/main'", "GCP-GHA-002"},
		{"assertion.repository_owner_id == '1' || assertion.ref == 'refs/heads/main'", "GCP-GHA-005"},
	}
	for _, c := range cases {
		fs := analyzeGitHubCondition(c.cond, mk)
		var ids []string
		for _, f := range fs {
			ids = append(ids, f.RuleID)
		}
		if !contains(ids, c.want) {
			t.Errorf("%q: got %v, want %s", c.cond, ids, c.want)
		}
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func TestParseProvidersSingleObject(t *testing.T) {
	ps, err := ParseProviders([]byte(`{"name":"projects/1/locations/global/workloadIdentityPools/p/providers/x","oidc":{"issuerUri":"https://token.actions.githubusercontent.com"}}`), "one.json")
	if err != nil || len(ps) != 1 || ps[0].Source != "one.json" {
		t.Fatalf("got %+v, %v", ps, err)
	}
	if _, err := ParseProviders([]byte("[{"), "bad.json"); err == nil {
		t.Fatal("invalid JSON must fail")
	}
}
