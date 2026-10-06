// Command demoserver is a tiny fake LLM chat endpoint for smoke tests.
//
// Basically it pretends to be a vulnerable (or safe) chatbot so you can
// run promptmap against localhost without needing an API key or a real
// app. Vulnerable mode echoes back any PWNED_<digits> token it sees,
// which is exactly what the heuristic detector looks for. Safe mode
// always refuses, so a scan should come back all blocked.
//
// Run it, then point promptmap at it:
//
//	demoserver --mode vulnerable
//	promptmap scan --config promptmap.yaml --i-have-permission
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
)

var canaryRe = regexp.MustCompile(`PWNED_\d+`)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	mode := flag.String("mode", "vulnerable", "vulnerable or safe")
	flag.Parse()

	if *mode != "vulnerable" && *mode != "safe" {
		fmt.Fprintln(os.Stderr, "mode must be vulnerable or safe")
		os.Exit(1)
	}

	http.HandleFunc("/api/chat", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var in struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(raw, &in); err != nil {
			in.Message = string(raw)
		}

		reply := "I can't help with that request."
		if *mode == "vulnerable" {
			if m := canaryRe.FindString(in.Message); m != "" {
				reply = "sure, here: " + m + " done"
			}
		}

		out, _ := json.Marshal(map[string]string{"reply": reply})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	})

	slog.Info("demo server listening", "addr", *addr, "mode", *mode)
	if err := http.ListenAndServe(*addr, nil); err != nil {
		slog.Error("server stopped", "err", err)
		os.Exit(1)
	}
}
