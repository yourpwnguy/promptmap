package runner_test

import (
	"context"
	"strings"
	"testing"

	"github.com/promptmap/promptmap/internal/detect"
	"github.com/promptmap/promptmap/internal/payloads"
	"github.com/promptmap/promptmap/internal/runner"
)

// stubSender pretends the target follows instructions containing EVIL.
type stubSender struct{}

func (stubSender) Send(ctx context.Context, prompt string) (string, int, error) {
	if strings.Contains(prompt, "EVIL") {
		return "sure, PWNED_EVIL here", 200, nil
	}
	return "I can't help with that.", 200, nil
}

func TestRunClassifies(t *testing.T) {
	probes := []payloads.Probe{
		{PayloadID: "evil-1", Canary: "PWNED_EVIL", Prompt: "do EVIL PWNED_EVIL"},
		{PayloadID: "clean-1", Canary: "PWNED_OK", Prompt: "hello there"},
	}
	got := runner.Run(context.Background(), probes, stubSender{}, detect.NewHeuristic(), runner.Options{Concurrency: 2, RatePerSec: 100}, nil)
	if len(got) != 2 {
		t.Fatalf("expected 2 results, got %d", len(got))
	}
	byID := map[string]runner.Result{}
	for _, r := range got {
		byID[r.Probe.PayloadID] = r
	}
	if byID["evil-1"].Verdict != detect.LikelyVuln {
		t.Errorf("evil probe got %s", byID["evil-1"].Verdict)
	}
	if byID["clean-1"].Verdict != detect.Blocked {
		t.Errorf("clean probe got %s", byID["clean-1"].Verdict)
	}
}
