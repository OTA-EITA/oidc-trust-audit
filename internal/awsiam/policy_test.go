package awsiam

import (
	"encoding/json"
	"testing"
)

func TestStringListAcceptsStringOrArray(t *testing.T) {
	var s struct{ A, B StringList }
	if err := json.Unmarshal([]byte(`{"A":"x","B":["y","z"]}`), &s); err != nil {
		t.Fatal(err)
	}
	if len(s.A) != 1 || s.A[0] != "x" || len(s.B) != 2 {
		t.Fatalf("got %+v", s)
	}
	if err := json.Unmarshal([]byte(`{"A":1}`), &s); err == nil {
		t.Fatal("numbers are not valid")
	}
}

func TestParsePolicyDocumentURLEncoded(t *testing.T) {
	p, err := ParsePolicyDocument(json.RawMessage(`"%7B%22Statement%22%3A%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%22%2A%22%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%7D"`))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Statement) != 1 || !p.Statement[0].Principal.Any {
		t.Fatalf("got %+v", p)
	}
	if _, err := ParsePolicyDocument(nil); err == nil {
		t.Fatal("empty documents must be rejected")
	}
}

func TestHasAction(t *testing.T) {
	st := Statement{Action: StringList{"sts:*"}}
	if !st.HasAction("sts:AssumeRoleWithWebIdentity") {
		t.Error("sts:* covers every STS action")
	}
	st.Action = StringList{"STS:assumerolewithwebidentity"}
	if !st.HasAction("sts:AssumeRoleWithWebIdentity") {
		t.Error("action names are case-insensitive")
	}
	st.Action = StringList{"sts:AssumeRole"}
	if st.HasAction("sts:AssumeRoleWithWebIdentity") {
		t.Error("AssumeRole does not grant AssumeRoleWithWebIdentity")
	}
}

func TestConditionValuesIsCaseInsensitive(t *testing.T) {
	st := Statement{Condition: map[string]map[string]StringList{
		"StringEquals": {"Token.Actions.GitHubUserContent.com:SUB": {"repo:a/b:ref:refs/heads/main"}},
	}}
	if got := st.ConditionValues("token.actions.githubusercontent.com:sub"); len(got["StringEquals"]) != 1 {
		t.Fatalf("got %v", got)
	}
}
