package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

const (
	awsFixture = "../../internal/awsiam/testdata/authorization-details.json"
	gcpFixture = "../../internal/gcpwif/testdata/providers.json"
)

func TestRunAgainstFixtures(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"--quiet", awsFixture, gcpFixture}, nil, &out, &errOut)
	if code != exitFail {
		t.Fatalf("HIGH findings must exit 1, got %d (stderr: %s)", code, errOut.String())
	}
	for _, want := range []string{"AWS-GHA-001", "AWS-IRSA-002", "GCP-GHA-001", "GCP-GHA-003"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output is missing %s:\n%s", want, out.String())
		}
	}
}

func TestRunReadsStdin(t *testing.T) {
	in := strings.NewReader(`{"Role":{"RoleName":"ok","Arn":"arn:aws:iam::1:role/ok","AssumeRolePolicyDocument":{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}}}`)
	var out bytes.Buffer
	if code := run([]string{"-"}, in, &out, io.Discard); code != exitOK {
		t.Fatalf("exit %d:\n%s", code, out.String())
	}
}

func TestFailOnThreshold(t *testing.T) {
	// The GitLab provider without a condition is MEDIUM; the others are filtered by --fail-on.
	in := strings.NewReader(`{"name":"projects/1/locations/global/workloadIdentityPools/p/providers/gitlab","oidc":{"issuerUri":"https://gitlab.com"}}`)
	if code := run([]string{"--fail-on", "high", "-"}, in, io.Discard, io.Discard); code != exitOK {
		t.Errorf("MEDIUM must not fail with --fail-on high, got %d", code)
	}
	in = strings.NewReader(`{"name":"projects/1/locations/global/workloadIdentityPools/p/providers/gitlab","oidc":{"issuerUri":"https://gitlab.com"}}`)
	if code := run([]string{"--fail-on", "medium", "-"}, in, io.Discard, io.Discard); code != exitFail {
		t.Errorf("MEDIUM must fail with --fail-on medium, got %d", code)
	}
}

func TestSARIFHasLineNumbers(t *testing.T) {
	var out bytes.Buffer
	run([]string{"--output", "sarif", awsFixture}, nil, &out, io.Discard)
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID    string
				Locations []struct {
					PhysicalLocation struct {
						Region *struct{ StartLine int }
					}
				}
			}
		}
	}
	if err := json.Unmarshal(out.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	for _, r := range log.Runs[0].Results {
		if reg := r.Locations[0].PhysicalLocation.Region; reg == nil || reg.StartLine == 0 {
			t.Errorf("%s has no line number", r.RuleID)
		}
	}
}

func TestRunRejectsBadInput(t *testing.T) {
	cases := [][]string{
		{},
		{"--output", "xml", awsFixture},
		{"--fail-on", "critical", awsFixture},
		{"does-not-exist.json"},
	}
	for _, args := range cases {
		if code := run(args, nil, io.Discard, io.Discard); code != exitUsage {
			t.Errorf("run(%v) = %d, want %d", args, code, exitUsage)
		}
	}
	if code := run([]string{"-"}, strings.NewReader(`{"Something":"else"}`), io.Discard, io.Discard); code != exitUsage {
		t.Errorf("unrecognised JSON must be a usage error, got %d", code)
	}
}

func TestList(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"--list"}, nil, &out, io.Discard); code != exitOK || !strings.Contains(out.String(), "GCP-GHA-005") {
		t.Fatalf("exit %d:\n%s", code, out.String())
	}
}
