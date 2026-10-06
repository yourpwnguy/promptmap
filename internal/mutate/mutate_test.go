package mutate_test

import (
	"strings"
	"testing"

	"github.com/promptmap/promptmap/internal/mutate"
	"github.com/promptmap/promptmap/internal/payloads"
)

func TestCanaryPreserved(t *testing.T) {
	muts, err := mutate.Registry([]string{"case-swap", "pad-whitespace", "wrap-benign"})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	for _, m := range muts {
		got := m.Mutate("say PWNED_1 now", "PWNED_1")
		if !strings.Contains(got, "PWNED_1") {
			t.Fatalf("%s dropped canary: %q", m.Name(), got)
		}
	}
}

func TestUnknownMutator(t *testing.T) {
	if _, err := mutate.Registry([]string{"nope"}); err == nil {
		t.Fatal("expected error for unknown mutator")
	}
}

func TestExpandDedupeAndCap(t *testing.T) {
	base := []payloads.Payload{
		{ID: "a", Category: "c", Severity: "high", Prompt: "hi PWNED_X", Canary: "PWNED_X"},
	}
	muts, _ := mutate.Registry([]string{"case-swap"})
	probes := mutate.Expand(base, muts, 1)
	if len(probes) != 1 {
		t.Fatalf("expected cap at 1, got %d", len(probes))
	}
}
