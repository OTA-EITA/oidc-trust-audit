// Package report renders findings as a table, JSON, Markdown or SARIF.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/OTA-EITA/oidc-trust-audit/internal/finding"
)

// Format is an output format name.
type Format string

// Supported output formats.
const (
	Table    Format = "table"
	JSON     Format = "json"
	Markdown Format = "markdown"
	SARIF    Format = "sarif"
)

// Formats lists the accepted values for --output.
var Formats = []Format{Table, JSON, Markdown, SARIF}

// ParseFormat validates a user supplied format name.
func ParseFormat(s string) (Format, error) {
	for _, f := range Formats {
		if string(f) == s {
			return f, nil
		}
	}
	return "", fmt.Errorf("unknown output format %q (want one of %v)", s, Formats)
}

// Options control rendering.
type Options struct {
	// Quiet hides PASS findings.
	Quiet bool
	// Rules documents every rule, for SARIF.
	Rules []finding.Rule
	// Version is the tool version written to SARIF.
	Version string
	// LineOf returns the 1-based line of resource in source, or 0 if unknown.
	LineOf func(source, resource string) int
}

// Write renders r to w.
func Write(w io.Writer, r finding.Report, f Format, opt Options) error {
	if opt.Quiet || f == SARIF {
		r.Findings = withoutPass(r.Findings)
	}
	switch f {
	case JSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case Markdown:
		return writeMarkdown(w, r)
	case SARIF:
		return writeSARIF(w, r, opt)
	default:
		return writeTable(w, r)
	}
}

func withoutPass(fs []finding.Finding) []finding.Finding {
	out := make([]finding.Finding, 0, len(fs))
	for _, f := range fs {
		if f.Severity != finding.Pass {
			out = append(out, f)
		}
	}
	return out
}

func writeTable(w io.Writer, r finding.Report) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tRULE\tRESOURCE\tMESSAGE")
	for _, f := range r.Findings {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Severity, f.RuleID, f.Resource, f.Message)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := fmt.Fprintf(w, "\n%s\n", summaryLine(r))
	return err
}

func writeMarkdown(w io.Writer, r finding.Report) error {
	var b strings.Builder
	fmt.Fprintf(&b, "## oidc-trust-audit: %s\n\n%s\n\n", r.Worst, summaryLine(r))
	b.WriteString("| Severity | Rule | Resource | Finding | Fix |\n|---|---|---|---|---|\n")
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "| %s | %s | `%s` | %s | %s |\n", f.Severity, f.RuleID, f.Resource, esc(f.Message), esc(f.Remediation))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func esc(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

func summaryLine(r finding.Report) string {
	return fmt.Sprintf("worst=%s high=%d medium=%d low=%d pass=%d",
		r.Worst, r.Summary[finding.High], r.Summary[finding.Medium], r.Summary[finding.Low], r.Summary[finding.Pass])
}
