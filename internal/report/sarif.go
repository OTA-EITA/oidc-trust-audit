package report

import (
	"encoding/json"
	"io"

	"github.com/OTA-EITA/oidc-trust-audit/internal/finding"
)

// Minimal SARIF 2.1.0 model, enough for GitHub code scanning.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string         `json:"id"`
	Name                 string         `json:"name"`
	ShortDescription     sarifText      `json:"shortDescription"`
	FullDescription      sarifText      `json:"fullDescription"`
	DefaultConfiguration sarifConfig    `json:"defaultConfiguration"`
	Properties           sarifRuleProps `json:"properties"`
}

type sarifRuleProps struct {
	Tags             []string `json:"tags"`
	SecuritySeverity string   `json:"security-severity"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func level(s finding.Severity) string {
	switch s {
	case finding.High:
		return "error"
	case finding.Medium:
		return "warning"
	default:
		return "note"
	}
}

// securitySeverity maps to the CVSS-like score GitHub uses to label alerts.
func securitySeverity(s finding.Severity) string {
	switch s {
	case finding.High:
		return "8.0"
	case finding.Medium:
		return "5.0"
	default:
		return "2.0"
	}
}

func writeSARIF(w io.Writer, r finding.Report, opt Options) error {
	driver := sarifDriver{
		Name:           "oidc-trust-audit",
		InformationURI: "https://github.com/OTA-EITA/oidc-trust-audit",
		Version:        opt.Version,
		Rules:          []sarifRule{},
	}
	for _, rule := range opt.Rules {
		driver.Rules = append(driver.Rules, sarifRule{
			ID:                   rule.ID,
			Name:                 rule.ID,
			ShortDescription:     sarifText{rule.Title},
			FullDescription:      sarifText{rule.Description},
			DefaultConfiguration: sarifConfig{level(rule.Severity)},
			Properties:           sarifRuleProps{Tags: []string{"security", "iam", "oidc"}, SecuritySeverity: securitySeverity(rule.Severity)},
		})
	}
	results := []sarifResult{}
	for _, f := range r.Findings {
		loc := sarifLocation{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: f.Source}}}
		if opt.LineOf != nil {
			if line := opt.LineOf(f.Source, f.Resource); line > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: line}
			}
		}
		msg := f.Resource + ": " + f.Message
		if f.Remediation != "" {
			msg += " Fix: " + f.Remediation
		}
		results = append(results, sarifResult{RuleID: f.RuleID, Level: level(f.Severity), Message: sarifText{msg}, Locations: []sarifLocation{loc}})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{{Tool: sarifTool{Driver: driver}, Results: results}},
	})
}
