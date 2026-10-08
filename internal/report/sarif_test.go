package report_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/promptmap/promptmap/internal/detect"
	"github.com/promptmap/promptmap/internal/payloads"
	"github.com/promptmap/promptmap/internal/report"
	"github.com/promptmap/promptmap/internal/runner"
)

func TestWriteSARIF(t *testing.T) {
	results := []runner.Result{
		{Probe: payloads.Probe{PayloadID: "a", Category: "c"}, Verdict: detect.LikelyVuln, Reason: "canary_found", Response: "PWNED"},
		{Probe: payloads.Probe{PayloadID: "b", Category: "c"}, Verdict: detect.Unclear, Reason: "canary_echo", Response: "hmm"},
		{Probe: payloads.Probe{PayloadID: "c"}, Verdict: detect.Blocked},
		{Probe: payloads.Probe{PayloadID: "d"}, Verdict: detect.VerdictError, Reason: "send_failed", Response: "timeout"},
	}
	rep := report.Build(results, "sha256:abc", "v0.1.0", time.Now(), false, true)
	path := filepath.Join(t.TempDir(), "r.sarif")
	if err := report.WriteSARIF(path, rep); err != nil {
		t.Fatalf("write sarif: %v", err)
	}
	raw, _ := os.ReadFile(path)
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatalf("parse sarif: %v", err)
	}
	if log.Version != "2.1.0" || log.Runs[0].Tool.Driver.Name != "promptmap" {
		t.Fatalf("bad envelope: %+v", log.Version)
	}
	got := map[string]string{}
	for _, r := range log.Runs[0].Results {
		got[r.RuleID] = r.Level
	}
	want := map[string]string{"a": "error", "b": "warning", "d": "note"}
	for id, level := range want {
		if got[id] != level {
			t.Errorf("result %s: got %q want %q (all: %v)", id, got[id], level, got)
		}
	}
	if _, ok := got["c"]; ok {
		t.Error("blocked finding should not appear in sarif")
	}
}
