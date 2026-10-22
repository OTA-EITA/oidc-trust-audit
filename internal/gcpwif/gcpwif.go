// Package gcpwif audits Google Cloud Workload Identity Federation providers,
// in particular those that trust GitHub Actions.
//
// Attribute conditions are CEL expressions. They are inspected with targeted
// pattern matching rather than a full CEL evaluator, so complex expressions
// are flagged for manual review instead of being judged.
package gcpwif

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/OTA-EITA/oidc-trust-audit/internal/finding"
)

const githubIssuer = "https://token.actions.githubusercontent.com"

// Provider is the part of a workload identity pool provider that is audited.
type Provider struct {
	Name               string            `json:"name"`
	DisplayName        string            `json:"displayName"`
	Disabled           bool              `json:"disabled"`
	State              string            `json:"state"`
	AttributeCondition string            `json:"attributeCondition"`
	AttributeMapping   map[string]string `json:"attributeMapping"`
	OIDC               *struct {
		IssuerURI string `json:"issuerUri"`
	} `json:"oidc"`
	Source string `json:"-"`
}

// LooksLikeGCP reports whether a JSON object is a workload identity provider.
func LooksLikeGCP(doc map[string]json.RawMessage) bool {
	name, ok := doc["name"]
	return ok && strings.Contains(string(name), "/workloadIdentityPools/")
}

// ParseProviders reads the JSON output of
//
//	gcloud iam workload-identity-pools providers list --format=json ...
//	gcloud iam workload-identity-pools providers describe --format=json ...
func ParseProviders(data []byte, source string) ([]Provider, error) {
	trimmed := strings.TrimSpace(string(data))
	var ps []Provider
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(data, &ps); err != nil {
			return nil, fmt.Errorf("%s: %w", source, err)
		}
	} else {
		var p Provider
		if err := json.Unmarshal(data, &p); err != nil {
			return nil, fmt.Errorf("%s: %w", source, err)
		}
		ps = []Provider{p}
	}
	for i := range ps {
		ps[i].Source = source
	}
	return ps, nil
}

// Rules lists every rule this package can report.
var Rules = []finding.Rule{
	{ID: "GCP-GHA-001", Severity: finding.High, Title: "GitHub provider without an attribute condition",
		Description: "Tokens from any GitHub repository are accepted by the pool."},
	{ID: "GCP-GHA-002", Severity: finding.High, Title: "GitHub provider condition does not restrict the owner or repository",
		Description: "The attribute condition never pins repository_owner, repository_owner_id or repository."},
	{ID: "GCP-GHA-003", Severity: finding.High, Title: "GitHub provider condition matches an owner prefix",
		Description: "startsWith on the owner or repository without a trailing '/' also matches attacker-registered owners."},
	{ID: "GCP-GHA-004", Severity: finding.Low, Title: "GitHub provider condition pins the owner by name",
		Description: "Owner names can be re-registered after a rename or deletion; repository_owner_id is immutable."},
	{ID: "GCP-GHA-005", Severity: finding.Low, Title: "Complex GitHub provider condition",
		Description: "The condition uses '||'; check that every alternative pins the owner."},
	{ID: "GCP-OIDC-001", Severity: finding.Medium, Title: "OIDC provider without an attribute condition",
		Description: "Every identity issued by the provider can use the pool."},
}

var (
	ownerIDEq   = regexp.MustCompile(`assertion\.repository_owner_id\s*(==|\bin\b)|==\s*assertion\.repository_owner_id\b`)
	ownerNameEq = regexp.MustCompile(`assertion\.repository_owner\s*(==|\bin\b)|==\s*assertion\.repository_owner\b`)
	repoEq      = regexp.MustCompile(`assertion\.repository\s*(==|\bin\b)|==\s*assertion\.repository\b`)
	prefixCall  = regexp.MustCompile(`assertion\.(repository_owner|repository|sub)\.startsWith\(\s*['"]([^'"]*)['"]\s*\)`)
)

// Analyze audits the providers. Disabled providers are skipped.
func Analyze(ps []Provider) []finding.Finding {
	var out []finding.Finding
	for _, p := range ps {
		if p.Disabled || p.State == "DELETED" || p.OIDC == nil {
			continue
		}
		mk := func(id string, sev finding.Severity, msg, fix string) finding.Finding {
			return finding.Finding{RuleID: id, Severity: sev, Resource: p.Name, Message: msg, Remediation: fix, Source: p.Source}
		}
		cond := strings.TrimSpace(p.AttributeCondition)
		issuer := strings.TrimSuffix(p.OIDC.IssuerURI, "/")
		if issuer != githubIssuer {
			if cond == "" {
				out = append(out, mk("GCP-OIDC-001", finding.Medium, "provider for "+issuer+" has no attribute condition",
					"Add an attribute condition that limits which identities can use the pool."))
			}
			continue
		}
		out = append(out, analyzeGitHubCondition(cond, mk)...)
	}
	return out
}

type mkFunc func(id string, sev finding.Severity, msg, fix string) finding.Finding

func analyzeGitHubCondition(cond string, mk mkFunc) []finding.Finding {
	if cond == "" {
		return []finding.Finding{mk("GCP-GHA-001", finding.High, "accepts tokens from every GitHub repository (no attribute condition)",
			"Set --attribute-condition=\"assertion.repository_owner_id == 'OWNER_ID'\".")}
	}
	var out []finding.Finding
	pinned := false
	for _, m := range prefixCall.FindAllStringSubmatch(cond, -1) {
		attr, prefix := m[1], m[2]
		safe := (attr == "repository" && strings.HasSuffix(prefix, "/")) ||
			(attr == "sub" && strings.HasPrefix(prefix, "repo:") && strings.Contains(prefix, "/"))
		if !safe {
			out = append(out, mk("GCP-GHA-003", finding.High, fmt.Sprintf("assertion.%s.startsWith(%q) also matches other owners", attr, prefix),
				"Compare the owner exactly, e.g. assertion.repository_owner_id == 'OWNER_ID'."))
			continue
		}
		pinned = true
	}
	switch {
	case ownerIDEq.MatchString(cond):
		pinned = true
	case ownerNameEq.MatchString(cond) || repoEq.MatchString(cond):
		pinned = true
		out = append(out, mk("GCP-GHA-004", finding.Low, "pins the owner or repository by name",
			"Prefer assertion.repository_owner_id, which cannot be re-registered."))
	}
	if !pinned && len(out) == 0 {
		out = append(out, mk("GCP-GHA-002", finding.High, fmt.Sprintf("condition %q does not restrict the repository owner", cond),
			"Add assertion.repository_owner_id == 'OWNER_ID' to the condition."))
	}
	if strings.Contains(cond, "||") {
		out = append(out, mk("GCP-GHA-005", finding.Low, "condition uses '||'; every alternative must pin the owner",
			"Split the alternatives into separate providers or review each branch."))
	}
	if len(out) == 0 {
		out = append(out, mk("PASS", finding.Pass, "condition pins the repository owner by ID", ""))
	}
	return out
}
