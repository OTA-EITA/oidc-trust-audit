package awsiam

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/OTA-EITA/oidc-trust-audit/internal/finding"
)

func loadRoles(t *testing.T, file string) []Role {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", filepath.Base(file)))
	if err != nil {
		t.Fatal(err)
	}
	roles, err := ParseRoles(data, file)
	if err != nil {
		t.Fatal(err)
	}
	return roles
}

func rulesFor(fs []finding.Finding, resourceSuffix string) map[string]finding.Finding {
	out := map[string]finding.Finding{}
	for _, f := range fs {
		if strings.HasSuffix(f.Resource, resourceSuffix) {
			out[f.RuleID] = f
		}
	}
	return out
}

func TestAnalyzeFixtures(t *testing.T) {
	var roles []Role
	for _, f := range []string{"authorization-details.json", "list-roles.json", "get-role-urlencoded.json"} {
		roles = append(roles, loadRoles(t, f)...)
	}
	fs := Analyze(roles)

	cases := []struct {
		role, rule string
		sev        finding.Severity
	}{
		{"role/gha-no-sub", "AWS-GHA-001", finding.High},
		{"role/gha-prod-deploy", "PASS", finding.Pass},
		{"role/irsa-any-namespace", "AWS-IRSA-002", finding.High},
		{"role/irsa-any-namespace", "AWS-IRSA-004", finding.Low},
		{"role/open-to-world", "AWS-ROLE-001", finding.High},
		{"role/gha-prefix", "AWS-GHA-003", finding.High},
		{"role/gha-prefix", "AWS-GHA-007", finding.Low},
	}
	for _, c := range cases {
		f, ok := rulesFor(fs, c.role)[c.rule]
		if !ok || f.Severity != c.sev {
			t.Errorf("%s: want %s (%s), got %+v", c.role, c.rule, c.sev, rulesFor(fs, c.role))
		}
	}
	if got := rulesFor(fs, "role/ec2-instance"); len(got) != 0 {
		t.Errorf("service roles are out of scope, got %+v", got)
	}
	if got := rulesFor(fs, "role/gha-prod-deploy"); len(got) != 1 {
		t.Errorf("a pinned role with aud should only PASS, got %+v", got)
	}
}

func TestClassifyGitHubSub(t *testing.T) {
	cases := []struct {
		sub  string
		glob bool
		want string
	}{
		{"*", true, "AWS-GHA-002"},
		{"repo:*", true, "AWS-GHA-002"},
		{"repo:*/infra:*", true, "AWS-GHA-002"},
		{"repo:my-org*/infra:ref:refs/heads/main", true, "AWS-GHA-003"},
		{"repo:my-org/*", true, "AWS-GHA-004"},
		{"repo:my-org/infra-*:ref:refs/heads/main", true, "AWS-GHA-004"},
		{"repo:my-org/infra:*", true, "AWS-GHA-005"},
		{"repo:my-org/infra", false, "AWS-GHA-005"},
		{"repo:my-org/infra:ref:refs/heads/release-*", true, "AWS-GHA-006"},
		{"repo:my-org/infra:environment:production", false, "PASS"},
		// StringEquals does not expand wildcards, so "*" is a literal that matches nothing.
		{"repo:my-org/infra:environment:production*", false, "PASS"},
		{"repository_owner_id:1234:repository_id:5678", false, "PASS"},
		{"*:repository_id:5678", true, "AWS-GHA-002"},
	}
	mk := func(id string, sev finding.Severity, msg, fix string) finding.Finding {
		return finding.Finding{RuleID: id, Severity: sev}
	}
	for _, c := range cases {
		if got := classifyGitHubSub(conditionValue{value: c.sub, glob: c.glob}, mk); got.RuleID != c.want {
			t.Errorf("sub %q (glob=%v) = %s, want %s", c.sub, c.glob, got.RuleID, c.want)
		}
	}
}

func TestOperatorsOnTheSameKeyAreANDed(t *testing.T) {
	st := Statement{
		Effect:    "Allow",
		Principal: Principal{Federated: StringList{"arn:aws:iam::1:oidc-provider/" + githubIssuer}},
		Action:    StringList{webIdentity},
		Condition: map[string]map[string]StringList{
			"StringLike":   {githubIssuer + ":sub": {"repo:my-org/*"}},
			"StringEquals": {githubIssuer + ":sub": {"repo:my-org/api:ref:refs/heads/main"}, githubIssuer + ":aud": {stsAudience}},
		},
	}
	fs := Analyze([]Role{{Name: "r", Trust: Policy{Statement: []Statement{st}}}})
	if len(fs) != 1 || fs[0].RuleID != "PASS" {
		t.Fatalf("the StringEquals pin narrows the StringLike pattern, got %+v", fs)
	}
}

func TestValuesOfOneOperatorAreORed(t *testing.T) {
	st := Statement{
		Effect:    "Allow",
		Principal: Principal{Federated: StringList{"arn:aws:iam::1:oidc-provider/" + githubIssuer}},
		Action:    StringList{webIdentity},
		Condition: map[string]map[string]StringList{
			"StringLike": {
				githubIssuer + ":sub": {"repo:my-org/api:ref:refs/heads/main", "repo:*"},
				githubIssuer + ":aud": {stsAudience},
			},
		},
	}
	fs := Analyze([]Role{{Name: "r", Trust: Policy{Statement: []Statement{st}}}})
	if len(fs) != 1 || fs[0].RuleID != "AWS-GHA-002" {
		t.Fatalf("one broad value opens the role, got %+v", fs)
	}
}

func TestNegatedOperatorsDoNotRestrict(t *testing.T) {
	st := Statement{
		Effect:    "Allow",
		Principal: Principal{Federated: StringList{"arn:aws:iam::1:oidc-provider/" + githubIssuer}},
		Action:    StringList{webIdentity},
		Condition: map[string]map[string]StringList{
			"StringNotLike": {githubIssuer + ":sub": {"repo:evil/*"}},
		},
	}
	fs := Analyze([]Role{{Name: "r", Trust: Policy{Statement: []Statement{st}}}})
	if rulesFor(fs, "role/r")["AWS-GHA-001"].Severity != finding.High {
		t.Fatalf("a deny-list is not a restriction, got %+v", fs)
	}
}

func TestOtherOIDCProviders(t *testing.T) {
	mkSt := func(cond map[string]map[string]StringList) Statement {
		return Statement{
			Effect:    "Allow",
			Principal: Principal{Federated: StringList{"arn:aws:iam::1:oidc-provider/gitlab.com"}},
			Action:    StringList{webIdentity},
			Condition: cond,
		}
	}
	open := Analyze([]Role{{Name: "open", Trust: Policy{Statement: []Statement{mkSt(nil)}}}})
	if open[0].RuleID != "AWS-OIDC-001" {
		t.Fatalf("got %+v", open)
	}
	pinned := Analyze([]Role{{Name: "pinned", Trust: Policy{Statement: []Statement{mkSt(map[string]map[string]StringList{
		"StringEquals": {"gitlab.com:sub": {"project_path:group/app:ref_type:branch:ref:main"}},
	})}}}})
	if pinned[0].RuleID != "PASS" {
		t.Fatalf("got %+v", pinned)
	}
}

func TestClassifyIRSASub(t *testing.T) {
	mk := func(id string, sev finding.Severity, msg, fix string) finding.Finding {
		return finding.Finding{RuleID: id, Severity: sev}
	}
	cases := map[string]string{
		"*":                                    "AWS-IRSA-002",
		"system:serviceaccount:*:external-dns": "AWS-IRSA-002",
		"system:serviceaccount:kube-system:*":  "AWS-IRSA-003",
		"system:serviceaccount:kube-system:ebs-*":                 "AWS-IRSA-003",
		"system:serviceaccount:kube-system:ebs-csi-controller-sa": "PASS",
	}
	for sub, want := range cases {
		if got := classifyIRSASub(conditionValue{value: sub, glob: true}, mk); got.RuleID != want {
			t.Errorf("sub %q = %s, want %s", sub, got.RuleID, want)
		}
	}
}

func TestParseRolesErrors(t *testing.T) {
	if _, err := ParseRoles([]byte("{"), "x.json"); err == nil {
		t.Error("invalid JSON must fail")
	}
	if _, err := ParseRoles([]byte(`{"Roles":[{"RoleName":"r","AssumeRolePolicyDocument":"%zz"}]}`), "x.json"); err == nil {
		t.Error("an undecodable policy must fail")
	}
}
