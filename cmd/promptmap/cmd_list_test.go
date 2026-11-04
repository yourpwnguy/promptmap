package main

import (
	"bytes"
	"strings"
	"testing"
)

// runList executes list-payloads with args and returns captured stdout.
// We go through cobra rather than calling internals so flag wiring and
// output redirection are both covered.
func runList(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newListCmd()
	cmd.SetArgs(args)
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := cmd.Execute()
	return buf.String(), err
}

func TestListPayloadsAll(t *testing.T) {
	out, err := runList(t)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out, "direct-ignore-001") || !strings.Contains(out, "indirect-doc-001") {
		t.Fatalf("expected direct and indirect payloads, got %q", out)
	}
}

func TestListPayloadsCategory(t *testing.T) {
	out, err := runList(t, "--categories", "jailbreak")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out, "[jailbreak]") {
		t.Fatalf("expected jailbreak rows, got %q", out)
	}
	if strings.Contains(out, "[ignore-instructions]") {
		t.Fatalf("category filter leaked other categories: %q", out)
	}
}

func TestListPayloadsUnknownCategory(t *testing.T) {
	if _, err := runList(t, "--categories", "nope"); err == nil {
		t.Fatal("expected an error for an unknown category")
	}
}
