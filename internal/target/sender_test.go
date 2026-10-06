package target_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/promptmap/promptmap/internal/target"
)

func fakeServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
}

func TestSendAndExtract(t *testing.T) {
	srv := fakeServer(t, `{"reply": "hello PWNED_1"}`)
	defer srv.Close()

	s := target.NewHTTPSender(target.Options{
		URL:          srv.URL,
		Method:       "POST",
		BodyTemplate: `{"message": "{{PROMPT}}"}`,
		ResponsePath: "$.reply",
		Timeout:      5 * time.Second,
	})
	text, status, err := s.Send(context.Background(), "try PWNED_1")
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if status != 200 || text != "hello PWNED_1" {
		t.Fatalf("unexpected %d %q", status, text)
	}
}

func TestExtractNested(t *testing.T) {
	got, err := target.Extract(`{"choices": [{"message": {"content": "hi" }}]}`, "$.choices.0.message.content")
	if err != nil || got != "hi" {
		t.Fatalf("nested extract got %q err %v", got, err)
	}
}

func TestExtractMissingPath(t *testing.T) {
	if _, err := target.Extract(`{"a": 1}`, "$.reply"); err == nil {
		t.Fatal("expected extractor error")
	}
}

func TestRedaction(t *testing.T) {
	got := target.RedactedHeaders(map[string]string{"Authorization": "Bearer x", "Content-Type": "application/json"})
	if got["Authorization"] != "[REDACTED]" {
		t.Fatalf("auth not redacted: %v", got)
	}
	if got["Content-Type"] != "application/json" {
		t.Fatalf("content type clobbered: %v", got)
	}
}

func TestSendEscapesTrickyPrompt(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"reply": "ok"}`))
	}))
	defer srv.Close()

	s := target.NewHTTPSender(target.Options{
		URL:          srv.URL,
		Method:       "POST",
		BodyTemplate: `{"message": "{{PROMPT}}"}`,
		ResponsePath: "$.reply",
		Timeout:      5 * time.Second,
	})
	tricky := "quote \" newline \n tab \t backslash \\ control \x01 done"
	if _, _, err := s.Send(context.Background(), tricky); err != nil {
		t.Fatalf("send: %v", err)
	}
	var decoded struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal([]byte(gotBody), &decoded); err != nil {
		t.Fatalf("sent body is not valid JSON %q: %v", gotBody, err)
	}
	if decoded.Message != tricky {
		t.Fatalf("prompt did not roundtrip: got %q want %q", decoded.Message, tricky)
	}
}
