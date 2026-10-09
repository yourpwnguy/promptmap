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

func TestListNewestFirst(t *testing.T) {
	st, err := history.Open(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	for i := 0; i < 3; i++ {
		rep := report.Build(nil, "sha256:x", "v0.1.0", time.Now().Add(time.Duration(i)*time.Minute), false, false)
		if _, err := st.Save(rep); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	rows, err := st.List(10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(rows))
	}
	if rows[0].ID <= rows[1].ID || rows[1].ID <= rows[2].ID {
		t.Fatalf("expected newest first, got ids %d %d %d", rows[0].ID, rows[1].ID, rows[2].ID)
	}
	if rows[0].Total != 0 {
		t.Fatalf("empty scan should have total 0, got %d", rows[0].Total)
	}
}

func TestListLimit(t *testing.T) {
	st, err := history.Open(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	for i := 0; i < 3; i++ {
		rep := report.Build(nil, "sha256:x", "v0.1.0", time.Now(), false, false)
		if _, err := st.Save(rep); err != nil {
			t.Fatalf("save: %v", err)
		}
	}
	rows, err := st.List(2)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("limit ignored, got %d", len(rows))
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

func TestCompareBuckets(t *testing.T) {
	st, err := history.Open(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	// older run: a is vulnerable, b is unclear, c is clean
	older := report.Build([]runner.Result{
		{Probe: payloads.Probe{PayloadID: "a"}, Verdict: detect.LikelyVuln, Reason: "canary_found"},
		{Probe: payloads.Probe{PayloadID: "b"}, Verdict: detect.Unclear, Reason: "canary_echo"},
		{Probe: payloads.Probe{PayloadID: "c"}, Verdict: detect.Blocked, Reason: "no_signal"},
	}, "sha256:same", "v0.1.0", time.Now(), false, false)
	fromID, err := st.Save(older)
	if err != nil {
		t.Fatalf("save older: %v", err)
	}
	// newer run: a got fixed, b still bad, c broke
	newer := report.Build([]runner.Result{
		{Probe: payloads.Probe{PayloadID: "a"}, Verdict: detect.Blocked, Reason: "refusal_phrase"},
		{Probe: payloads.Probe{PayloadID: "b"}, Verdict: detect.LikelyVuln, Reason: "canary_found"},
		{Probe: payloads.Probe{PayloadID: "c"}, Verdict: detect.Unclear, Reason: "suspicious_pattern"},
	}, "sha256:same", "v0.1.0", time.Now().Add(time.Minute), false, false)
	toID, err := st.Save(newer)
	if err != nil {
		t.Fatalf("save newer: %v", err)
	}

	got, err := st.Compare(fromID, toID)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if len(got.Fixed) != 1 || got.Fixed[0].PayloadID != "a" {
		t.Errorf("a should be fixed: %+v", got.Fixed)
	}
	// c broke and b got worse, both count as new problems
	if len(got.New) != 2 {
		t.Errorf("b and c should both be new problems: %+v", got.New)
	}
	if len(got.Changed) != 0 {
		t.Errorf("nothing should land in the plain change bucket: %+v", got.Changed)
	}
	if len(got.Warnings) != 0 {
		t.Errorf("same target and corpus should warn about nothing: %+v", got.Warnings)
	}
}

func TestCompareWarnsOnMismatch(t *testing.T) {
	st, err := history.Open(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	a, _ := st.Save(report.Build(nil, "sha256:aaa", "v0.1.0", time.Now(), false, false))
	b, _ := st.Save(report.Build(nil, "sha256:bbb", "v0.2.0", time.Now(), false, false))
	got, err := st.Compare(a, b)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if len(got.Warnings) != 2 {
		t.Fatalf("expected target and corpus warnings, got %v", got.Warnings)
	}
}

func TestCompareUnknownID(t *testing.T) {
	st, err := history.Open(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	id, _ := st.Save(report.Build(nil, "sha256:x", "v0.1.0", time.Now(), false, false))
	if _, err := st.Compare(id, 999); err == nil {
		t.Fatal("expected error when comparing against unknown id")
	}
}
