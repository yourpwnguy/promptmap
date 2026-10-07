package main

import (
	"testing"
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
