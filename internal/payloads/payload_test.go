package payloads_test

import (
	"testing"

	"github.com/promptmap/promptmap/internal/payloads"
)

func TestLoadEmbedded(t *testing.T) {
	all, err := payloads.LoadEmbedded()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(all) < 3 {
		t.Fatalf("expected at least 3 seed payloads, got %d", len(all))
	}
}

func TestFilter(t *testing.T) {
	all, _ := payloads.LoadEmbedded()
	got := payloads.Filter(all, []string{"indirect-basic"})
	if len(got) == 0 {
		t.Fatal("expected indirect payloads")
	}
	for _, p := range got {
		if p.Category != "indirect-basic" {
			t.Fatalf("unexpected category %s", p.Category)
		}
	}
}
