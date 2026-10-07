// Package report turns raw Results into files and terminal output.
//
// Basically two sinks: a JSON file for CI and pentest reports, and a
// lipgloss styled table for humans watching the terminal. We save full
// evidence only for Unclear and LikelyVuln plus errors, otherwise files
// would balloon on big scans.
//
// SchemaVersion stays at 1 until we change the JSON shape. When we do,
// we bump it and keep a tiny migrator, so old tooling can detect the
// mismatch instead of silently misreading.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/promptmap/promptmap/internal/detect"
	"github.com/promptmap/promptmap/internal/runner"
)

// SchemaVersion is written into every report.
const SchemaVersion = 1

// Report is the JSON file shape.
type Report struct {
	SchemaVersion int       `json:"schema_version"`
	CorpusVersion string    `json:"corpus_version"`
	TargetHash    string    `json:"target_hash"`
	StartedAt     time.Time `json:"started_at"`
	Interrupted   bool      `json:"interrupted"`
	Summary       Summary   `json:"summary"`
	Findings      []Finding `json:"findings"`
}

// Summary counts by verdict.
type Summary struct {
	Total      int `json:"total"`
	Blocked    int `json:"blocked"`
	Unclear    int `json:"unclear"`
	LikelyVuln int `json:"likely_vulnerable"`
	Errors     int `json:"errors"`
}

// Finding is one probe result trimmed for the file.
type Finding struct {
	PayloadID  string   `json:"payload_id"`
	Category   string   `json:"category"`
	Severity   string   `json:"severity"`
	Mutations  []string `json:"mutations"`
	SentPrompt string   `json:"sent_prompt"`
	Response   string   `json:"response_excerpt"`
	Verdict    string   `json:"verdict"`
	Reason     string   `json:"reason"`
	LatencyMs  int64    `json:"latency_ms"`
}

// Build assembles a Report from results. targetHash should already be
// a sha256 of the URL, not the raw URL, so secrets never land in files.
// saveAll keeps prompts and excerpts for blocked probes too, at the
// cost of a much bigger file. Default off: blocked noise is rarely
// worth the disk.
func Build(results []runner.Result, targetHash, corpusVersion string, started time.Time, interrupted, saveAll bool) Report {
	r := Report{
		SchemaVersion: SchemaVersion,
		CorpusVersion: corpusVersion,
		TargetHash:    targetHash,
		StartedAt:     started,
		Interrupted:   interrupted,
		Findings:      make([]Finding, 0, len(results)),
	}
	for _, res := range results {
		r.Summary.Total++
		switch res.Verdict {
		case detect.Blocked:
			r.Summary.Blocked++
		case detect.Unclear:
			r.Summary.Unclear++
		case detect.LikelyVuln:
			r.Summary.LikelyVuln++
		default:
			r.Summary.Errors++
		}
		f := Finding{
			PayloadID: res.Probe.PayloadID,
			Category:  res.Probe.Category,
			Severity:  res.Probe.Severity,
			Mutations: res.Probe.Mutations,
			Verdict:   string(res.Verdict),
			Reason:    res.Reason,
			LatencyMs: res.LatencyMs,
		}
		// Save prompts and excerpts only for interesting results.
		// Blocked probes would just bloat the file with noise, unless
		// the user asked for everything with saveAll.
		if res.Verdict != detect.Blocked || saveAll {
			f.SentPrompt = res.Probe.Prompt
			if res.Err != "" {
				f.Response = res.Err
			} else {
				f.Response = res.Response
			}
		}
		r.Findings = append(r.Findings, f)
	}
	return r
}

// WriteJSON writes an indented report file.
func WriteJSON(path string, r Report) error {
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// PrintSummary renders a small colored table to stdout.
//
// We use lipgloss because hand rolled ANSI is fragile and ugly.
// Keep it minimal: counts plus a nudge to check the JSON for hits.
func PrintSummary(r Report) {
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	yellow := lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	red := lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	dim := lipgloss.NewStyle().Faint(true)

	fmt.Printf("\n%s %s\n", dim.Render("Corpus:"), r.CorpusVersion)
	fmt.Printf("%s blocked=%s unclear=%s likely-vuln=%s errors=%d total=%d\n",
		dim.Render("Summary:"),
		green.Render(fmt.Sprint(r.Summary.Blocked)),
		yellow.Render(fmt.Sprint(r.Summary.Unclear)),
		red.Render(fmt.Sprint(r.Summary.LikelyVuln)),
		r.Summary.Errors,
		r.Summary.Total,
	)
	if r.Summary.LikelyVuln > 0 || r.Summary.Unclear > 0 {
		fmt.Println(yellow.Render("Check the JSON report for evidence, then run `verify` on each hit."))
	}
	if r.Interrupted {
		fmt.Println(yellow.Render("Scan was interrupted, report is partial."))
	}
}
