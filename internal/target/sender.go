// Package target knows how to talk to the scanned app.
//
// Basically it takes a prompt, stuffs it into the user's body template
// where {{PROMPT}} lives, POSTs it, then pulls the model text back out
// using the response_path. Everything else (runner, detector) only sees
// the Sender interface, so later we can add GraphQL or SSE senders
// without touching the scan loop.
//
// Retries use hashicorp/go-retryablehttp because backoff plus jitter
// plus "only retry 429 and 5xx" is boilerplate everyone gets subtly
// wrong. This lib is mature and tiny, and stdlib types still flow through.
package target

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	retryablehttp "github.com/hashicorp/go-retryablehttp"
	"github.com/tidwall/gjson"
)

// Sender sends one prompt and returns the extracted model text.
type Sender interface {
	Send(ctx context.Context, prompt string) (string, int, error)
}

// HTTPSender is the v0.1 implementation for JSON HTTP chat endpoints.
type HTTPSender struct {
	url          string
	method       string
	headers      map[string]string
	bodyTemplate string
	responsePath string
	client       *retryablehttp.Client
	timeout      time.Duration
}

// Options keeps the constructor readable without a giant arg list.
type Options struct {
	URL          string
	Method       string
	Headers      map[string]string
	BodyTemplate string
	ResponsePath string
	Timeout      time.Duration
}

// NewHTTPSender builds a sender with polite retry defaults: 2 retries,
// only on network errors plus 429 and 5xx. We never retry 4xx (except
// 429) because that means our request itself is wrong and resending
// just spams the target.
func NewHTTPSender(o Options) *HTTPSender {
	rc := retryablehttp.NewClient()
	rc.RetryMax = 2
	rc.Logger = nil
	rc.HTTPClient.Timeout = o.Timeout
	if rc.HTTPClient.Timeout == 0 {
		rc.HTTPClient.Timeout = 15 * time.Second
	}
	rc.CheckRetry = func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		if err != nil {
			return true, nil
		}
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			return true, nil
		}
		return false, nil
	}
	method := o.Method
	if method == "" {
		method = "POST"
	}
	return &HTTPSender{
		url:          o.URL,
		method:       method,
		headers:      o.Headers,
		bodyTemplate: o.BodyTemplate,
		responsePath: o.ResponsePath,
		client:       rc,
		timeout:      rc.HTTPClient.Timeout,
	}
}

// Send renders the template, does one HTTP call, and extracts text.
func (s *HTTPSender) Send(ctx context.Context, prompt string) (string, int, error) {
	body := strings.ReplaceAll(s.bodyTemplate, "{{PROMPT}}", jsonEscape(prompt))

	req, err := retryablehttp.NewRequestWithContext(ctx, s.method, s.url, strings.NewReader(body))
	if err != nil {
		return "", 0, fmt.Errorf("build request: %w", err)
	}
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("post %s: %w", s.url, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", resp.StatusCode, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", resp.StatusCode, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, truncate(string(raw), 300))
	}

	text, err := Extract(string(raw), s.responsePath)
	if err != nil {
		return "", resp.StatusCode, err
	}
	return text, resp.StatusCode, nil
}

// Extract pulls model text out of a raw body using a gjson path.
//
// We use gjson because JSON paths like $.reply or
// $.choices.0.message.content are a solved problem and hand rolled
// parsing would be slow and buggy. If the path misses we fall back to
// raw trimmed text when it looks like plain text, otherwise we return
// an extractor error so the runner can mark the probe Unclear with a
// hint to fix response_path.
func Extract(raw, path string) (string, error) {
	if path == "" || path == "$" {
		return strings.TrimSpace(raw), nil
	}
	clean := strings.TrimPrefix(path, "$.")
	clean = strings.TrimPrefix(clean, "$")
	res := gjson.Get(raw, clean)
	if !res.Exists() {
		trimmed := strings.TrimSpace(raw)
		if len(trimmed) > 0 && !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
			return trimmed, nil
		}
		return "", fmt.Errorf("extractor_failed: path %q not found, fix response_path (raw starts: %q)", path, truncate(trimmed, 120))
	}
	return strings.TrimSpace(res.String()), nil
}

// RedactedHeaders returns headers safe to write into reports.
func RedactedHeaders(h map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range h {
		lk := strings.ToLower(k)
		if lk == "authorization" || lk == "cookie" || lk == "api-key" || lk == "x-api-key" {
			out[k] = "[REDACTED]"
			continue
		}
		out[k] = v
	}
	return out
}

// jsonEscape renders a prompt safe to splice into a JSON string field.
//
// We use encoding/json.Marshal and strip the surrounding quotes instead
// of hand rolling escapes. Hand rolled replacers always forget something
// (form feeds, control chars, weird unicode), Marshal gets it right and
// it is still stdlib, so no new dep.
func jsonEscape(s string) string {
	raw, err := json.Marshal(s)
	if err != nil {
		// Marshal on a string basically never fails. If it somehow does,
		// fall back to a minimal safe replacement rather than injecting raw.
		r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
		return r.Replace(s)
	}
	quoted := string(raw)
	if len(quoted) >= 2 {
		return quoted[1 : len(quoted)-1]
	}
	return quoted
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "...[truncated]"
	}
	return s
}
