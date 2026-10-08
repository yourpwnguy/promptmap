// SARIF reporting for promptmap.
//
// Basically the same findings as JSON, shaped as SARIF 2.1.0 so CI
// dashboards (GitHub code scanning and friends) can ingest them.
// Blocked probes are not findings, so they are skipped. Levels map
// our honesty policy: likely-vulnerable is an error, unclear is a
// warning, transport errors are notes (the scan failed, not the app).
package report

import (
	"encoding/json"
	"fmt"
	"os"
)

const sarifVersion = "2.1.0"

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
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
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string   `json:"id"`
	ShortDescription sarifMsg `json:"shortDescription"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMsg        `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMsg struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhys `json:"physicalLocation"`
}

type sarifPhys struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// sarifLevel maps verdicts to SARIF levels.
func sarifLevel(verdict string) (string, bool) {
	switch verdict {
	case "likely-vulnerable":
		return "error", true
	case "unclear":
		return "warning", true
	case "error":
		return "note", true
	default:
		return "", false
	}
}

// WriteSARIF writes findings as a SARIF log. The artifact URI is the
// target hash, since the real URL may carry secrets and never lands
// in report files.
func WriteSARIF(path string, r Report) error {
	log := sarifLog{
		Version: sarifVersion,
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:    "promptmap",
				Version: r.CorpusVersion,
			}},
			Results: []sarifResult{},
		}},
	}
	run := &log.Runs[0]
	seenRule := map[string]bool{}
	for _, f := range r.Findings {
		level, ok := sarifLevel(f.Verdict)
		if !ok {
			continue
		}
		if !seenRule[f.PayloadID] {
			seenRule[f.PayloadID] = true
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
				ID:               f.PayloadID,
				ShortDescription: sarifMsg{Text: f.Category},
			})
		}
		run.Results = append(run.Results, sarifResult{
			RuleID:  f.PayloadID,
			Level:   level,
			Message: sarifMsg{Text: f.Reason + ": " + f.Response},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhys{
					ArtifactLocation: sarifArtifact{URI: "target:" + r.TargetHash},
				},
			}},
		})
	}
	raw, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("encode sarif: %w", err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
