// Package awsiam audits IAM role trust policies that federate with OIDC
// identity providers such as GitHub Actions and EKS (IRSA).
package awsiam

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// StringList accepts both a JSON string and an array of strings, as IAM
// policy grammar allows either almost everywhere.
type StringList []string

// UnmarshalJSON implements json.Unmarshaler.
func (s *StringList) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*s = StringList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("expected string or array of strings: %w", err)
	}
	*s = many
	return nil
}

// Principal is either "*" or a map such as {"Federated": "arn:..."}.
type Principal struct {
	Any       bool
	Federated StringList
	AWS       StringList
	Service   StringList
}

// UnmarshalJSON implements json.Unmarshaler.
func (p *Principal) UnmarshalJSON(b []byte) error {
	var star string
	if err := json.Unmarshal(b, &star); err == nil {
		p.Any = star == "*"
		return nil
	}
	var m struct {
		Federated StringList
		AWS       StringList
		Service   StringList
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	p.Federated, p.AWS, p.Service = m.Federated, m.AWS, m.Service
	return nil
}

// Statement is one statement of a policy document.
type Statement struct {
	Sid       string
	Effect    string
	Principal Principal
	Action    StringList
	// Condition maps an operator (e.g. StringLike) to condition keys and values.
	Condition map[string]map[string]StringList
}

// Policy is an IAM policy document.
type Policy struct {
	Version   string
	Statement []Statement
}

// UnmarshalJSON accepts a single statement object as well as an array.
func (p *Policy) UnmarshalJSON(b []byte) error {
	var raw struct {
		Version   string
		Statement json.RawMessage
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	p.Version = raw.Version
	if len(raw.Statement) == 0 {
		return nil
	}
	if raw.Statement[0] == '{' {
		var st Statement
		if err := json.Unmarshal(raw.Statement, &st); err != nil {
			return err
		}
		p.Statement = []Statement{st}
		return nil
	}
	return json.Unmarshal(raw.Statement, &p.Statement)
}

// ParsePolicyDocument decodes a policy given either as a JSON object or as the
// URL-encoded string returned by the raw IAM API.
func ParsePolicyDocument(raw json.RawMessage) (Policy, error) {
	var p Policy
	if len(raw) == 0 {
		return p, fmt.Errorf("empty policy document")
	}
	if raw[0] == '"' {
		var enc string
		if err := json.Unmarshal(raw, &enc); err != nil {
			return p, err
		}
		dec, err := url.QueryUnescape(enc)
		if err != nil {
			return p, fmt.Errorf("url-decode policy: %w", err)
		}
		raw = json.RawMessage(dec)
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, fmt.Errorf("parse policy: %w", err)
	}
	return p, nil
}

// HasAction reports whether the statement grants action, honouring "*" and
// service wildcards such as "sts:*". IAM action names are case-insensitive.
func (s Statement) HasAction(action string) bool {
	for _, a := range s.Action {
		if a == "*" || strings.EqualFold(a, action) {
			return true
		}
		if prefix, ok := strings.CutSuffix(a, "*"); ok && strings.HasPrefix(strings.ToLower(action), strings.ToLower(prefix)) {
			return true
		}
	}
	return false
}

// ConditionValues returns every value constrained for key, grouped by the
// operator that applies them. Condition keys are case-insensitive in IAM.
func (s Statement) ConditionValues(key string) map[string][]string {
	out := map[string][]string{}
	for op, kv := range s.Condition {
		for k, vals := range kv {
			if strings.EqualFold(k, key) {
				out[op] = append(out[op], vals...)
			}
		}
	}
	return out
}
