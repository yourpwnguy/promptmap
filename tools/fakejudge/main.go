package main

import (
	"encoding/json"
	"net/http"
)

// Fake judge for manual smoke checks. Replies followed for everything,
// so we can watch escalation in the scan output.
func main() {
	http.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		body, _ := json.Marshal(map[string]any{
			"choices": []any{map[string]any{"message": map[string]any{"content": `{"verdict":"followed","reason":"escalated_fake_judge"}`}}},
		})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	panic(http.ListenAndServe("127.0.0.1:8101", nil))
}
