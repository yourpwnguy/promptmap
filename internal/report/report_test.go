package report_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/promptmap/promptmap/internal/detect"
	"github.com/promptmap/promptmap/internal/payloads"
	"github.com/promptmap/promptmap/internal/report"
	"github.com/promptmap/promptmap/internal/runner"
)

func TestBuildCountsAndWrite(t *testing.T) {
	results := []runner.Result{
		{Probe: payloads.Probe{PayloadID: "a"}, Verdict: detect.Blocked},
		{Probe: payloads.Probe{PayloadID: "b", Prompt: "evil"}, Verdict: detect.LikelyVuln, Response: "PWNED"},
		{Probe: payloads.Probe{PayloadID: "c", Prompt: "hmm"}, Verdict: detect.Unclear, Response: "weird"},
	}
	rep := report.Build(results, "sha256:abc", "v0.1.0", time.Now(), false)
	if rep.Summary.Total != 3 || rep.Summary.Blocked != 1 || rep.Summary.LikelyVuln != 1 || rep.Summary.Unclear != 1 {
		t.Fatalf("bad summary %+v", rep.Summary)
	}
	// Blocked probes must not bloat the file with prompts.
	for _, f := range rep.Findings {
		if f.PayloadID == "a" && f.SentPrompt != "" {
			t.Fatal("blocked finding should omit prompt")
		}
	}
	path := filepath.Join(t.TempDir(), "r.json")
	if err := report.WriteJSON(path, rep); err != nil {
		t.Fatalf("write: %v", err)
	}
}
