// Package runner orchestrates a scan: probes in, results out.
//
// Basically it is a polite worker pool. Probes go into a channel,
// N workers pull them, each worker waits for the rate limiter, sends
// one request, classifies the answer, and pushes a Result. The caller
// gets a streaming callback plus a final slice.
//
// We use errgroup.SetLimit (official x/sync) for the pool and
// x/time/rate for pacing. That combo is the standard Go way to say
// "fast but not rude". No Kafka, no job server, just goroutines that
// exit when the scan does.
package runner

import (
	"context"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

	"github.com/promptmap/promptmap/internal/detect"
	"github.com/promptmap/promptmap/internal/payloads"
	"github.com/promptmap/promptmap/internal/target"
)

// Result is one finished probe with its verdict and timing.
type Result struct {
	Probe      payloads.Probe
	Response   string
	StatusCode int
	Verdict    detect.Verdict
	Reason     string
	LatencyMs  int64
	Err        string
}

// Options tunes concurrency and pacing.
type Options struct {
	Concurrency int
	RatePerSec  float64
}

// Progress is called per finished probe for live terminal output.
type Progress func(done, total int, r Result)

// Run executes all probes with bounded concurrency.
//
// Context cancellation (Ctrl-C) stops new work; in flight requests
// finish or time out, and we return what we have plus the ctx error.
// Partial results are still useful, so callers should still write a
// report marked interrupted.
func Run(ctx context.Context, probes []payloads.Probe, s target.Sender, d detect.Detector, o Options, onProgress Progress) []Result {
	if o.Concurrency < 1 {
		o.Concurrency = 1
	}
	if o.RatePerSec <= 0 {
		o.RatePerSec = 5
	}
	limiter := rate.NewLimiter(rate.Limit(o.RatePerSec), 1)

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(o.Concurrency)

	var mu sync.Mutex
	out := make([]Result, 0, len(probes))
	done := 0

	for _, pr := range probes {
		pr := pr
		g.Go(func() error {
			if err := limiter.Wait(ctx); err != nil {
				push(&mu, &out, &done, len(probes), Result{Probe: pr, Verdict: detect.VerdictError, Err: err.Error()}, onProgress)
				return nil
			}
			start := time.Now()
			text, status, err := s.Send(ctx, pr.Prompt)
			lat := time.Since(start).Milliseconds()
			var r Result
			if err != nil {
				r = Result{Probe: pr, StatusCode: status, Verdict: detect.VerdictError, Reason: "send_failed", LatencyMs: lat, Err: err.Error()}
			} else {
				oc := d.Classify(pr.Canary, text)
				r = Result{Probe: pr, Response: oc.Evidence, StatusCode: status, Verdict: oc.Verdict, Reason: oc.Reason, LatencyMs: lat}
			}
			push(&mu, &out, &done, len(probes), r, onProgress)
			return nil
		})
	}
	_ = g.Wait()
	return out
}

func push(mu *sync.Mutex, out *[]Result, done *int, total int, r Result, cb Progress) {
	mu.Lock()
	*out = append(*out, r)
	*done++
	n := *done
	mu.Unlock()
	if cb != nil {
		cb(n, total, r)
	}
}
