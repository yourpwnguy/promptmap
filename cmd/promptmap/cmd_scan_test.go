package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/promptmap/promptmap/internal/config"
	"github.com/promptmap/promptmap/internal/payloads"
)

func TestQuickConfigOK(t *testing.T) {
	cfg, err := quickConfig("http://localhost:8080/api/chat", "POST", `{"message": "{{PROMPT}}"}`, "$.reply")
	if err != nil {
		t.Fatalf("expected valid quick config, got %v", err)
	}
	if cfg.Target.URL == "" || cfg.Scan.Concurrency != 5 {
		t.Fatalf("defaults not applied: %+v", cfg.Scan)
	}
}

func TestQuickConfigNeedsURL(t *testing.T) {
	if _, err := quickConfig("", "POST", `{"m": "{{PROMPT}}"}`, "$.reply"); err == nil {
		t.Fatal("expected error without --url")
	}
}

func TestQuickConfigBadBody(t *testing.T) {
	if _, err := quickConfig("https://app.example.com/chat", "POST", `{"m": "hi"}`, "$.reply"); err == nil {
		t.Fatal("expected error for body without {{PROMPT}}")
	}
}

func TestParseHeadersOK(t *testing.T) {
	got, err := parseHeaders([]string{"Authorization: Bearer abc", "X-Trace: a: b"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got["Authorization"] != "Bearer abc" || got["X-Trace"] != "a: b" {
		t.Fatalf("bad map: %v", got)
	}
}

func TestParseHeadersBad(t *testing.T) {
	for _, h := range []string{"no-colon", ": novalue", "Key:", "  "} {
		if _, err := parseHeaders([]string{h}); err == nil {
			t.Errorf("expected error for %q", h)
		}
	}
}

func TestMergeHeaders(t *testing.T) {
	cfg := config.Defaults()
	cfg.Target.Headers = map[string]string{"Auth": "old", "Keep": "yes"}
	if err := mergeHeaders(&cfg, []string{"Auth: new", "Extra: 1"}); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if cfg.Target.Headers["Auth"] != "new" || cfg.Target.Headers["Keep"] != "yes" || cfg.Target.Headers["Extra"] != "1" {
		t.Fatalf("bad merge: %v", cfg.Target.Headers)
	}
	if err := mergeHeaders(&cfg, []string{"broken"}); err == nil {
		t.Fatal("expected error for bad header")
	}
}

func TestSelectPayloads(t *testing.T) {
	all := []payloads.Payload{
		{ID: "a", Category: "ignore-instructions"},
		{ID: "b", Category: "indirect-basic"},
	}
	if got := selectPayloads(all, "direct", nil); len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("direct should skip indirect, got %v", got)
	}
	if got := selectPayloads(all, "indirect", nil); len(got) != 1 || got[0].ID != "b" {
		t.Fatalf("indirect defaults to indirect-basic, got %v", got)
	}
	if got := selectPayloads(all, "direct", []string{"ignore-instructions"}); len(got) != 1 {
		t.Fatalf("category filter broke direct, got %v", got)
	}
	if got := selectPayloads(all, "indirect", []string{"nope"}); len(got) != 0 {
		t.Fatalf("unknown category should select nothing, got %v", got)
	}
}

// TestRunScanTimeout proves an overall deadline produces a partial
// report instead of hanging: slow server, tiny timeout, interrupted
// must come back true.
func TestRunScanTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(500 * time.Millisecond):
			_, _ = w.Write([]byte(`{"reply": "slow"}`))
		}
	}))
	defer srv.Close()

	cfg := config.Defaults()
	cfg.Target.URL = srv.URL
	cfg.Target.BodyTemplate = `{"message": "{{PROMPT}}"}`
	cfg.Target.ResponsePath = "$.reply"
	cfg.Target.TimeoutMs = 5000
	cfg.Scan.AllowPrivate = true
	cfg.Scan.Categories = []string{"role-play"}
	cfg.Scan.Mutations = nil
	cfg.Scan.MaxProbes = 1
	cfg.Scan.Concurrency = 1
	cfg.Scan.RatePerSec = 100

	out := filepath.Join(t.TempDir(), "r.json")
	o := scanOpts{output: out, format: "json", timeout: 50 * time.Millisecond}
	if err := runScan(cfg, o); err != nil {
		t.Fatalf("runScan: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var rep struct {
		Interrupted bool `json:"interrupted"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("parse report: %v", err)
	}
	if !rep.Interrupted {
		t.Fatal("expected interrupted report after deadline")
	}
}

// TestRunScanDryRun proves dry run never touches the network: the URL
// points at a closed port, so any real send would fail loudly. Success
// plus no report file means nothing was sent and nothing was written.
func TestRunScanDryRun(t *testing.T) {
	cfg := config.Defaults()
	cfg.Target.URL = "http://127.0.0.1:9/api/chat"
	cfg.Target.BodyTemplate = `{"message": "{{PROMPT}}"}`
	cfg.Scan.AllowPrivate = true
	cfg.Scan.Categories = []string{"jailbreak"}
	cfg.Scan.Mutations = nil
	cfg.Scan.MaxProbes = 5

	out := filepath.Join(t.TempDir(), "r.json")
	if err := runScan(cfg, scanOpts{output: out, format: "json", dryRun: true}); err != nil {
		t.Fatalf("runScan dry run: %v", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("dry run must not write a report file")
	}
}
