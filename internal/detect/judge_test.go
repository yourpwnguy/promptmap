package detect

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeJudgeServer returns a canned assistant reply for any request.
func fakeJudgeServer(t *testing.T, status int, reply string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Error("judge request missing auth header")
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":{"message":"boom"}}`))
			return
		}
		out, _ := json.Marshal(judgeResponse{})
		_ = out
		body := `{"choices":[{"message":{"content":` + jsonString(reply) + `}}]}`
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
}

func jsonString(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

func TestJudgeClassifyFollowed(t *testing.T) {
	srv := fakeJudgeServer(t, http.StatusOK, `{"verdict":"followed","reason":"printed canary"}`)
	defer srv.Close()

	j := NewJudge(JudgeOptions{
		APIKey:  "test-key",
		BaseURL: srv.URL,
		Timeout: 5 * time.Second,
	})
	got := j.Classify("PWNED_1", "sure, PWNED_1 here")
	if got.Verdict != LikelyVuln {
		t.Fatalf("expected likely-vulnerable, got %s (%s)", got.Verdict, got.Reason)
	}
	if got.Reason != "judge_followed" {
		t.Fatalf("bad reason %q", got.Reason)
	}
}

func TestJudgeClassifyRefused(t *testing.T) {
	srv := fakeJudgeServer(t, http.StatusOK, `{"verdict":"refused","reason":"said no"}`)
	defer srv.Close()
	j := NewJudge(JudgeOptions{APIKey: "k", BaseURL: srv.URL})
	got := j.Classify("PWNED_1", "I can't help with that.")
	if got.Verdict != Blocked {
		t.Fatalf("expected blocked, got %s (%s)", got.Verdict, got.Reason)
	}
}

// A judge outage must not become a false positive, it degrades to unclear.
func TestJudgeUnavailableDegrades(t *testing.T) {
	srv := fakeJudgeServer(t, http.StatusInternalServerError, ``)
	defer srv.Close()
	j := NewJudge(JudgeOptions{APIKey: "k", BaseURL: srv.URL})
	got := j.Classify("PWNED_1", "anything")
	if got.Verdict != Unclear {
		t.Fatalf("expected unclear on failure, got %s (%s)", got.Verdict, got.Reason)
	}
	if got.Reason != "judge_failed" {
		t.Fatalf("expected judge_failed, got %q", got.Reason)
	}
}

func TestJudgeUnparseableAnswer(t *testing.T) {
	srv := fakeJudgeServer(t, http.StatusOK, "um, i dunno maybe")
	defer srv.Close()
	j := NewJudge(JudgeOptions{APIKey: "k", BaseURL: srv.URL})
	got := j.Classify("PWNED_1", "text")
	if got.Verdict != Unclear || got.Reason != "judge_unparsed" {
		t.Fatalf("expected unclear/unparsed, got %s/%s", got.Verdict, got.Reason)
	}
}

// Fenced JSON is common from chatty models, make sure we still parse it.
func TestParseJudgeVerdictFenced(t *testing.T) {
	v, r := parseJudgeVerdict("```json\n{\"verdict\":\"followed\",\"reason\":\"x\"}\n```")
	if v != LikelyVuln || r != "followed" {
		t.Fatalf("fenced json not parsed, got %s/%s", v, r)
	}
}

// The escalation wrapper must only call the judge when the heuristic is unsure.
func TestFallbackEscalatesOnlyUnclear(t *testing.T) {
	stub := stubDetector{verdict: LikelyVuln}
	escalated := false
	spy := spyDetector{fn: func(canary, response string) (Verdict, string) {
		escalated = true
		return Blocked, "spied"
	}}
	f := NewFallback(stub, spy)
	out := f.Classify("PWNED_1", "resp")
	if out.Verdict != LikelyVuln {
		t.Fatalf("primary verdict should stand, got %s", out.Verdict)
	}
	if escalated {
		t.Fatal("judge was called even though primary was decisive")
	}

	unsure := stubDetector{verdict: Unclear}
	f2 := NewFallback(unsure, spy)
	out2 := f2.Classify("PWNED_1", "resp")
	if out2.Verdict != Blocked {
		t.Fatalf("judge should have taken over, got %s", out2.Verdict)
	}
	if !escalated {
		t.Fatal("judge was not called for an unclear primary result")
	}
}

type stubDetector struct{ verdict Verdict }

func (s stubDetector) Classify(canary, response string) Outcome {
	return Outcome{Verdict: s.verdict, Reason: "stub"}
}

type spyDetector struct {
	verdict Verdict
	fn      func(canary, response string) (Verdict, string)
}

func (s spyDetector) Classify(canary, response string) Outcome {
	if s.fn != nil {
		v, r := s.fn(canary, response)
		return Outcome{Verdict: v, Reason: r}
	}
	return Outcome{Verdict: s.verdict, Reason: "spy"}
}
