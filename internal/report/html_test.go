package report_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/promptmap/promptmap/internal/detect"
	"github.com/promptmap/promptmap/internal/payloads"
	"github.com/promptmap/promptmap/internal/report"
	"github.com/promptmap/promptmap/internal/runner"
)

func TestWriteHTML(t *testing.T) {
	results := []runner.Result{
		{
			Probe:    payloads.Probe{PayloadID: "xss-1", Category: "c", Prompt: `<script>alert("PWNED_1")</script>`},
			Verdict:  detect.LikelyVuln,
			Reason:   "canary_found",
			Response: `<b>PWNED_1</b>`,
		},
	}
	rep := report.Build(results, "sha256:abc", "v0.1.0", time.Now(), false, true)
	path := filepath.Join(t.TempDir(), "r.html")
	if err := report.WriteHTML(path, rep); err != nil {
		t.Fatalf("write html: %v", err)
	}
	raw, _ := os.ReadFile(path)
	html := string(raw)
	if !strings.Contains(html, "xss-1") || !strings.Contains(html, "likely-vulnerable") {
		t.Fatalf("missing content in html: %s", html[:200])
	}
	if strings.Contains(html, "<script>alert") || strings.Contains(html, "<b>PWNED_1</b>") {
		t.Fatal("evidence was not escaped, page contains live markup")
	}
}
