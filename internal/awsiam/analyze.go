package awsiam

import (
	"fmt"
	"strings"

	"github.com/OTA-EITA/oidc-trust-audit/internal/finding"
)

const (
	githubIssuer    = "token.actions.githubusercontent.com"
	webIdentity     = "sts:AssumeRoleWithWebIdentity"
	stsAudience     = "sts.amazonaws.com"
	saSubjectPrefix = "system:serviceaccount:"
)

// Rules lists every rule this package can report.
var Rules = []finding.Rule{
	{ID: "AWS-GHA-001", Severity: finding.High, Title: "GitHub OIDC trust without a sub condition",
		Description: "Any workflow in any GitHub repository can obtain credentials for the role."},
	{ID: "AWS-GHA-002", Severity: finding.High, Title: "GitHub OIDC trust allows any repository owner",
		Description: "The sub condition wildcards the owner, so workflows outside your organization match."},
	{ID: "AWS-GHA-003", Severity: finding.High, Title: "GitHub OIDC trust matches an owner prefix",
		Description: "A pattern such as repo:my-org*/... also matches an attacker-registered owner such as my-org-evil."},
	{ID: "AWS-GHA-004", Severity: finding.Medium, Title: "GitHub OIDC trust allows many repositories",
		Description: "Every repository of the owner (or every repository with a name prefix) can assume the role."},
	{ID: "AWS-GHA-005", Severity: finding.Medium, Title: "GitHub OIDC trust allows any branch, tag, pull request or environment",
		Description: "Anyone who can push a branch or run a workflow in the repository can assume the role."},
	{ID: "AWS-GHA-006", Severity: finding.Low, Title: "GitHub OIDC trust uses a wildcard ref or environment",
		Description: "The role is limited to a ref or environment pattern; make sure branch or environment protection covers it."},
	{ID: "AWS-GHA-007", Severity: finding.Low, Title: "GitHub OIDC trust without an aud condition",
		Description: "The audience should be pinned to sts.amazonaws.com so tokens minted for other audiences are rejected."},
	{ID: "AWS-IRSA-001", Severity: finding.High, Title: "EKS IRSA trust without a sub condition",
		Description: "Every service account in the cluster, in any namespace, can assume the role."},
	{ID: "AWS-IRSA-002", Severity: finding.High, Title: "EKS IRSA trust allows any namespace",
		Description: "Anyone who can create a namespace or service account can assume the role."},
	{ID: "AWS-IRSA-003", Severity: finding.Medium, Title: "EKS IRSA trust allows many service accounts",
		Description: "The service account name is a wildcard, so other workloads in the namespace can assume the role."},
	{ID: "AWS-IRSA-004", Severity: finding.Low, Title: "EKS IRSA trust without an aud condition",
		Description: "The audience should be pinned to sts.amazonaws.com."},
	{ID: "AWS-OIDC-001", Severity: finding.High, Title: "OIDC trust without a sub condition",
		Description: "Any identity issued by the provider can assume the role."},
	{ID: "AWS-ROLE-001", Severity: finding.High, Title: "Role trusts any principal",
		Description: `The trust policy allows Principal "*" without conditions, so any AWS account can assume the role.`},
}

// Analyze audits the trust policies of roles. Roles that do not federate with
// an OIDC provider and do not trust "*" produce no findings.
func Analyze(roles []Role) []finding.Finding {
	var out []finding.Finding
	for _, r := range roles {
		res := r.Arn
		if res == "" {
			res = "role/" + r.Name
		}
		for _, st := range r.Trust.Statement {
			if !strings.EqualFold(st.Effect, "Allow") {
				continue
			}
			mk := func(id string, sev finding.Severity, msg, fix string) finding.Finding {
				return finding.Finding{RuleID: id, Severity: sev, Resource: res, Message: msg, Remediation: fix, Source: r.Source}
			}
			if st.Principal.Any && len(st.Condition) == 0 {
				out = append(out, mk("AWS-ROLE-001", finding.High, `trusts Principal "*" with no conditions`,
					"Replace \"*\" with the specific account, role or federated provider that needs access."))
				continue
			}
			if !st.HasAction(webIdentity) {
				continue
			}
			for _, provider := range st.Principal.Federated {
				issuer := issuerOf(provider)
				switch {
				case issuer == githubIssuer:
					out = append(out, analyzeGitHub(st, issuer, mk)...)
				case strings.HasPrefix(issuer, "oidc.eks.") && strings.Contains(issuer, "/id/"):
					out = append(out, analyzeIRSA(st, issuer, mk)...)
				case issuer != "":
					if len(allowValues(st, issuer+":sub")) == 0 {
						out = append(out, mk("AWS-OIDC-001", finding.High, "trusts "+issuer+" without a sub condition",
							"Add a StringEquals condition on "+issuer+":sub that names the exact identity."))
					} else {
						out = append(out, mk("PASS", finding.Pass, "trusts "+issuer+" with a sub condition", ""))
					}
				}
			}
		}
	}
	return out
}

type mkFunc func(id string, sev finding.Severity, msg, fix string) finding.Finding

// issuerOf extracts the issuer host/path from an OIDC provider ARN.
func issuerOf(provider string) string {
	if _, after, ok := strings.Cut(provider, ":oidc-provider/"); ok {
		return after
	}
	return ""
}

// allowValues returns the values that restrict key, grouped by operator and
// keeping only operators that narrow access. Negated operators
// (StringNotLike, ...) never restrict who can assume the role on their own,
// so they are ignored.
func allowValues(st Statement, key string) map[string][]conditionValue {
	out := map[string][]conditionValue{}
	for op, vals := range st.ConditionValues(key) {
		base := op
		if _, after, ok := strings.Cut(op, ":"); ok { // ForAnyValue:StringLike
			base = after
		}
		base = strings.TrimSuffix(base, "IfExists")
		switch strings.ToLower(base) {
		case "stringequals", "stringequalsignorecase":
			for _, v := range vals {
				out[op] = append(out[op], conditionValue{value: v})
			}
		case "stringlike":
			for _, v := range vals {
				out[op] = append(out[op], conditionValue{value: v, glob: true})
			}
		}
	}
	return out
}

// effective classifies a condition key. Values under one operator are ORed,
// so the broadest value decides that operator's risk; different operators on
// the same key are ANDed, so the narrowest operator decides the result.
func effective(groups map[string][]conditionValue, classify func(conditionValue) finding.Finding) finding.Finding {
	var best *finding.Finding
	for _, vals := range groups {
		var worst *finding.Finding
		for _, v := range vals {
			f := classify(v)
			if worst == nil || f.Severity.Rank() > worst.Severity.Rank() {
				worst = &f
			}
		}
		if best == nil || worst.Severity.Rank() < best.Severity.Rank() {
			best = worst
		}
	}
	return *best
}

type conditionValue struct {
	value string
	glob  bool // wildcards * and ? are interpreted
}

func (c conditionValue) hasWildcard(s string) bool {
	return c.glob && strings.ContainsAny(s, "*?")
}

func (c conditionValue) isAny(s string) bool {
	return c.glob && strings.Trim(s, "*") == ""
}

func analyzeGitHub(st Statement, issuer string, mk mkFunc) []finding.Finding {
	var out []finding.Finding
	subs := allowValues(st, issuer+":sub")
	if len(subs) == 0 {
		out = append(out, mk("AWS-GHA-001", finding.High, "any GitHub repository can assume this role (no "+issuer+":sub condition)",
			`Add "StringEquals": {"`+issuer+`:sub": "repo:OWNER/REPO:environment:production"} or a specific ref.`))
	} else {
		out = append(out, effective(subs, func(v conditionValue) finding.Finding { return classifyGitHubSub(v, mk) }))
	}
	if !audPinned(st, issuer) {
		out = append(out, mk("AWS-GHA-007", finding.Low, "no "+issuer+":aud condition",
			`Add "StringEquals": {"`+issuer+`:aud": "sts.amazonaws.com"}.`))
	}
	return out
}

func classifyGitHubSub(v conditionValue, mk mkFunc) finding.Finding {
	sub := v.value
	quoted := fmt.Sprintf("sub %q", sub)
	if v.isAny(sub) {
		return mk("AWS-GHA-002", finding.High, quoted+" matches every repository on GitHub",
			"Pin the sub condition to repo:OWNER/REPO:<ref or environment>.")
	}
	rest, ok := strings.CutPrefix(sub, "repo:")
	if !ok {
		if v.hasWildcard(sub) && strings.HasPrefix(sub, "*") {
			return mk("AWS-GHA-002", finding.High, quoted+" starts with a wildcard",
				"Make the customized sub claim start with a fixed repository_owner_id or repository.")
		}
		return mk("PASS", finding.Pass, quoted+" (customized sub claim)", "")
	}
	ownerRepo, context, _ := strings.Cut(rest, ":")
	owner, repo, _ := strings.Cut(ownerRepo, "/")
	switch {
	case v.isAny(owner):
		return mk("AWS-GHA-002", finding.High, quoted+" allows any repository owner",
			"Replace the owner wildcard with your organization or user name.")
	case v.hasWildcard(owner):
		return mk("AWS-GHA-003", finding.High, quoted+" matches any owner starting with that prefix",
			"Use the exact owner name; consider a customized sub claim with repository_owner_id.")
	case v.hasWildcard(repo):
		return mk("AWS-GHA-004", finding.Medium, quoted+" allows multiple repositories",
			"Grant each repository its own role, or list the repositories explicitly.")
	case context == "" || v.isAny(context):
		return mk("AWS-GHA-005", finding.Medium, quoted+" allows any branch, tag, pull request or environment",
			"Restrict to a protected environment (repo:OWNER/REPO:environment:prod) or ref (repo:OWNER/REPO:ref:refs/heads/main).")
	case v.hasWildcard(context):
		return mk("AWS-GHA-006", finding.Low, quoted+" uses a wildcard ref or environment",
			"Make sure branch or environment protection rules cover every ref the pattern matches.")
	default:
		return mk("PASS", finding.Pass, quoted+" is pinned to one repository and ref/environment", "")
	}
}

func analyzeIRSA(st Statement, issuer string, mk mkFunc) []finding.Finding {
	var out []finding.Finding
	subs := allowValues(st, issuer+":sub")
	if len(subs) == 0 {
		out = append(out, mk("AWS-IRSA-001", finding.High, "any service account in the cluster can assume this role (no sub condition)",
			`Add "StringEquals": {"`+issuer+`:sub": "system:serviceaccount:NAMESPACE:NAME"}.`))
	} else {
		out = append(out, effective(subs, func(v conditionValue) finding.Finding { return classifyIRSASub(v, mk) }))
	}
	if !audPinned(st, issuer) {
		out = append(out, mk("AWS-IRSA-004", finding.Low, "no aud condition",
			`Add "StringEquals": {"`+issuer+`:aud": "sts.amazonaws.com"}.`))
	}
	return out
}

func classifyIRSASub(v conditionValue, mk mkFunc) finding.Finding {
	sub := v.value
	quoted := fmt.Sprintf("sub %q", sub)
	rest, ok := strings.CutPrefix(sub, saSubjectPrefix)
	if v.isAny(sub) || (!ok && v.hasWildcard(sub)) {
		return mk("AWS-IRSA-002", finding.High, quoted+" matches every service account",
			"Pin the sub condition to system:serviceaccount:NAMESPACE:NAME.")
	}
	ns, name, _ := strings.Cut(rest, ":")
	switch {
	case v.hasWildcard(ns):
		return mk("AWS-IRSA-002", finding.High, quoted+" allows any namespace",
			"Name the namespace explicitly.")
	case v.hasWildcard(name):
		return mk("AWS-IRSA-003", finding.Medium, quoted+" allows any service account in the namespace",
			"Name the service account explicitly.")
	default:
		return mk("PASS", finding.Pass, quoted+" is pinned to one service account", "")
	}
}

func audPinned(st Statement, issuer string) bool {
	for _, vals := range allowValues(st, issuer+":aud") {
		for _, v := range vals {
			if v.value == stsAudience {
				return true
			}
		}
	}
	return false
}
