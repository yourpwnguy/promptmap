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
