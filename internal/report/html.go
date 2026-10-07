// HTML reporting for promptmap.
//
// Basically the same Report struct as JSON, rendered as one standalone
// page with no external assets so it can be attached to a pentest
// ticket as-is. We use html/template (stdlib) because it escapes by
// default, and finding evidence is attacker influenced text that must
// never become live markup in the page.
package report

import (
	"fmt"
	"html/template"
	"os"
	"strings"
)

const pageTmpl = `<!doctype html>
<html><head><meta charset="utf-8"><title>promptmap report</title>
<style>body{font-family:sans-serif;max-width:900px;margin:2em auto;padding:0 1em}
table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccc;padding:6px;text-align:left;vertical-align:top}
.vuln{color:#b00;font-weight:bold}.unclear{color:#a60}.blocked{color:#080}
pre{white-space:pre-wrap;background:#f6f6f6;padding:6px}</style>
</head><body>
<h1>promptmap report</h1>
<p>Corpus {{.CorpusVersion}} scanned at {{.StartedAt}}{{if .Interrupted}} (interrupted, partial){{end}}</p>
<p>Blocked {{.Summary.Blocked}}, unclear {{.Summary.Unclear}},
likely vulnerable {{.Summary.LikelyVuln}}, errors {{.Summary.Errors}},
total {{.Summary.Total}}</p>
<table><tr><th>Payload</th><th>Category</th><th>Verdict</th><th>Reason</th><th>Evidence</th></tr>
{{range .Findings}}<tr><td>{{.PayloadID}}</td><td>{{.Category}}</td>
<td class="{{.VerdictClass}}">{{.Verdict}}</td><td>{{.Reason}}</td>
<td>{{if .SentPrompt}}<pre>sent: {{.SentPrompt}}</pre>{{end}}<pre>{{.Response}}</pre></td></tr>
{{end}}</table></body></html>`

// VerdictClass maps a verdict to a CSS class for coloring.
func (f Finding) VerdictClass() string {
	switch f.Verdict {
	case "likely-vulnerable":
		return "vuln"
	case "unclear":
		return "unclear"
	default:
		return "blocked"
	}
}

// HTMLPath derives the companion html name for --format both.
// report.json becomes report.html, anything else just gains .html.
func HTMLPath(jsonPath string) string {
	if strings.HasSuffix(jsonPath, ".json") {
		return strings.TrimSuffix(jsonPath, ".json") + ".html"
	}
	return jsonPath + ".html"
}

// WriteHTML renders the report as a standalone page.
func WriteHTML(path string, r Report) error {
	t, err := template.New("page").Parse(pageTmpl)
	if err != nil {
		return fmt.Errorf("parse html template: %w", err)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	if err := t.Execute(f, r); err != nil {
		return fmt.Errorf("render html: %w", err)
	}
	return nil
}
