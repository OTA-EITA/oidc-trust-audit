// Command oidc-trust-audit finds over-permissive trust between cloud IAM and
// OIDC identity providers: AWS IAM roles trusted by GitHub Actions or EKS
// service accounts, and Google Cloud Workload Identity Federation providers.
//
// It reads the JSON that the AWS CLI and gcloud already produce, so it needs
// no cloud credentials of its own and can run on exported data in CI.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/OTA-EITA/oidc-trust-audit/internal/awsiam"
	"github.com/OTA-EITA/oidc-trust-audit/internal/finding"
	"github.com/OTA-EITA/oidc-trust-audit/internal/gcpwif"
	"github.com/OTA-EITA/oidc-trust-audit/internal/report"
)

const (
	exitOK    = 0
	exitFail  = 1
	exitUsage = 2
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func allRules() []finding.Rule {
	return append(append([]finding.Rule{}, awsiam.Rules...), gcpwif.Rules...)
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("oidc-trust-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: oidc-trust-audit [flags] FILE... (use - for stdin)")
		fs.PrintDefaults()
	}
	output := fs.String("output", "table", "output format: table, json, markdown or sarif")
	failOn := fs.String("fail-on", "high", "exit 1 when a finding is at least this severe: high, medium or low")
	quiet := fs.Bool("quiet", false, "hide PASS findings")
	list := fs.Bool("list", false, "list rules and exit")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if *showVersion {
		fmt.Fprintln(stdout, "oidc-trust-audit", version)
		return exitOK
	}
	if *list {
		return listRules(stdout)
	}
	format, err := report.ParseFormat(*output)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitUsage
	}
	threshold, ok := finding.ParseSeverity(*failOn)
	if !ok {
		fmt.Fprintf(stderr, "error: --fail-on must be high, medium or low, got %q\n", *failOn)
		return exitUsage
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return exitUsage
	}

	sources := map[string][]byte{}
	var all []finding.Finding
	for _, path := range fs.Args() {
		data, err := readInput(path, stdin)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return exitUsage
		}
		sources[path] = data
		found, err := analyze(data, path)
		if err != nil {
			fmt.Fprintln(stderr, "error:", err)
			return exitUsage
		}
		all = append(all, found...)
	}

	r := finding.NewReport(all)
	opt := report.Options{Quiet: *quiet, Rules: allRules(), Version: version, LineOf: lineFinder(sources)}
	if err := report.Write(stdout, r, format, opt); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitUsage
	}
	if r.Worst != finding.Pass && r.Worst.Rank() >= threshold.Rank() {
		return exitFail
	}
	return exitOK
}

func readInput(path string, stdin io.Reader) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(path) // #nosec G304 -- reading user-specified input files is the purpose of the tool
}

// analyze detects which CLI produced the JSON and runs the matching analyzer.
func analyze(data []byte, source string) ([]finding.Finding, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		ps, err := gcpwif.ParseProviders(data, source)
		if err != nil {
			return nil, err
		}
		return gcpwif.Analyze(ps), nil
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: not a JSON object or array: %w", source, err)
	}
	switch {
	case awsiam.LooksLikeAWS(doc):
		roles, err := awsiam.ParseRoles(data, source)
		if err != nil {
			return nil, err
		}
		return awsiam.Analyze(roles), nil
	case gcpwif.LooksLikeGCP(doc):
		ps, err := gcpwif.ParseProviders(data, source)
		if err != nil {
			return nil, err
		}
		return gcpwif.Analyze(ps), nil
	default:
		return nil, fmt.Errorf("%s: unrecognised input; expected AWS CLI IAM role output or gcloud workload identity provider output", source)
	}
}

// lineFinder locates the first line mentioning a resource, so SARIF results
// point at the role or provider inside the input file.
func lineFinder(sources map[string][]byte) func(source, resource string) int {
	return func(source, resource string) int {
		needle := resource
		if name, ok := strings.CutPrefix(resource, "role/"); ok {
			needle = `"` + name + `"`
		}
		for i, line := range strings.Split(string(sources[source]), "\n") {
			if strings.Contains(line, needle) {
				return i + 1
			}
		}
		return 0
	}
}

func listRules(w io.Writer) int {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "RULE\tSEVERITY\tTITLE")
	for _, r := range allRules() {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", r.ID, r.Severity, r.Title)
	}
	if err := tw.Flush(); err != nil {
		return exitUsage
	}
	return exitOK
}
