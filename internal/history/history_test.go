package history_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/promptmap/promptmap/internal/detect"
	"github.com/promptmap/promptmap/internal/history"
	"github.com/promptmap/promptmap/internal/payloads"
	"github.com/promptmap/promptmap/internal/report"
	"github.com/promptmap/promptmap/internal/runner"
)

func TestSaveGetRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.db")
	st, err := history.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	results := []runner.Result{
		{Probe: payloads.Probe{PayloadID: "a", Category: "c"}, Verdict: detect.LikelyVuln, Reason: "canary_found"},
		{Probe: payloads.Probe{PayloadID: "b", Category: "c"}, Verdict: detect.Blocked, Reason: "no_signal"},
	}
	rep := report.Build(results, "sha256:abc", "v0.1.0", time.Now(), false, false)
	id, err := st.Save(rep)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if id <= 0 {
		t.Fatalf("bad scan id %d", id)
	}

	got, err := st.Get(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Summary.Total != 2 || got.Summary.LikelyVuln != 1 || got.Summary.Blocked != 1 {
		t.Fatalf("bad summary: %+v", got.Summary)
	}
	if len(got.Findings) != 2 || got.Findings[0].PayloadID != "a" || got.Findings[0].Verdict != "likely-vulnerable" {
		t.Fatalf("bad findings: %+v", got.Findings)
	}
	if got.TargetHash != "sha256:abc" {
		t.Fatalf("bad target hash %q", got.TargetHash)
	}
}

func TestGetUnknown(t *testing.T) {
	st, err := history.Open(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	if _, err := st.Get(999); err == nil {
		t.Fatal("expected error for unknown scan id")
	}
}
