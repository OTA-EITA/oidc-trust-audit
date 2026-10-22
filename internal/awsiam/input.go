package awsiam

import (
	"encoding/json"
	"fmt"
)

// Role is the part of an IAM role needed to audit its trust policy.
type Role struct {
	Name   string
	Arn    string
	Trust  Policy
	Source string
}

type rawRole struct {
	RoleName                 string
	Arn                      string
	AssumeRolePolicyDocument json.RawMessage
}

// LooksLikeAWS reports whether a JSON document is one of the supported AWS CLI outputs.
func LooksLikeAWS(doc map[string]json.RawMessage) bool {
	_, details := doc["RoleDetailList"]
	_, roles := doc["Roles"]
	_, role := doc["Role"]
	return details || roles || role
}

// ParseRoles reads the output of any of:
//
//	aws iam get-account-authorization-details --filter Role
//	aws iam list-roles
//	aws iam get-role --role-name NAME
func ParseRoles(data []byte, source string) ([]Role, error) {
	var doc struct {
		RoleDetailList []rawRole
		Roles          []rawRole
		Role           *rawRole
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	raws := append(append([]rawRole{}, doc.RoleDetailList...), doc.Roles...)
	if doc.Role != nil {
		raws = append(raws, *doc.Role)
	}
	roles := make([]Role, 0, len(raws))
	for _, r := range raws {
		p, err := ParsePolicyDocument(r.AssumeRolePolicyDocument)
		if err != nil {
			return nil, fmt.Errorf("%s: role %s: %w", source, r.RoleName, err)
		}
		roles = append(roles, Role{Name: r.RoleName, Arn: r.Arn, Trust: p, Source: source})
	}
	return roles, nil
}
