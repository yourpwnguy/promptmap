# promptmap

A small CLI that probes an LLM chat endpoint with known prompt injection
payloads and reports which ones look successful.

Point it at an app, it fires payloads plus small mutations, checks
responses for instruction following, and writes a JSON report with
evidence. Built for quick security smoke tests, not proofs of safety.

> Only scan apps you own or have permission to test. `scan` requires
> `--i-have-permission` for exactly this reason.

## Install

```bash
go install github.com/promptmap/promptmap/cmd/promptmap@latest
```

Or grab a release binary from GitHub Releases.

## Quickstart (2 minutes, no API key)

```bash
# terminal 1: fake vulnerable chatbot
make run-demo

# terminal 2: scan it (no config file needed for simple targets)
promptmap scan --url http://localhost:8080/api/chat --i-have-permission
```

Or with a config file for headers and auth:

```bash
promptmap init
promptmap scan --config promptmap.yaml --i-have-permission
```

You should see `likely-vulnerable` hits with evidence. Rerun one
manually to confirm:

```bash
promptmap verify --config promptmap.yaml --payload-id direct-ignore-001 --repeat 3
promptmap list-payloads
```

`--repeat` resends N times because one LLM answer can be luck. If
verdicts differ across runs, the result is flaky, treat it as unclear.

Want to see the judge work? Run the demo in `vague` mode, which leaks
that it has instructions without printing a canary, so heuristics call
it unclear and the judge has to settle it.

```bash
go run ./tools/demoserver --mode vague
promptmap scan --url http://localhost:8080/api/chat --judge-key $OPENAI_API_KEY --i-have-permission
```

## Useful flags

```bash
# auth and custom headers (repeatable, beats the config file on match)
promptmap scan --url https://app.com/chat --header "Authorization: Bearer $TOKEN" --i-have-permission

# only some payload families, or only some mutations (empty means none)
promptmap scan --config p.yaml --categories jailbreak,role-play --i-have-permission
promptmap scan --config p.yaml --mutations wrap-benign --max-probes 10 --i-have-permission

# reports: json (default), html, sarif, or json plus html
promptmap scan --config p.yaml --format sarif -o results.sarif --i-have-permission

# keep evidence for blocked probes too (big files), or cap a slow target
promptmap scan --config p.yaml --save-all --timeout 2m --i-have-permission

# see what would fire without sending anything
promptmap scan --config p.yaml --dry-run --categories jailbreak

# llm judge as second opinion, key from env or --judge-key
promptmap scan --config p.yaml --judge-url https://api.openai.com/v1 --judge-model gpt-4o-mini --i-have-permission
promptmap scan --config p.yaml --judge-all --i-have-permission   # judge every reply, pricier

# skip history for one off scans, or point the file elsewhere
promptmap scan --config p.yaml --no-history --i-have-permission
promptmap scan --config p.yaml --history-db /tmp/h.db --i-have-permission
```

## Remembering past scans

Every scan lands in a local SQLite history file, so you can answer
"did last week's fix work?".

```bash
promptmap history                      # list saved scans with ids
promptmap diff 1 2                     # compare scan 1 (older) against 2 (newer)
```

`diff` prints three buckets: new problems (bad news), fixed (good
news), and other moves. It warns when the targets or corpus versions
differ, because comparing a direct run to an indirect run is apples to
oranges and should not read as a security win. It exits `2` when
nothing got fixed and something new broke, so CI can gate a regression.

History stores summaries and verdicts only, never prompts or
responses. Full evidence stays in the report files, which keeps the
database small and boring to reason about.

## Scanning a real target

Edit the generated `promptmap.yaml`: set `target.url`, `target.body`
(keep the `{{PROMPT}}` placeholder), `target.response_path` (a JSON
path like `$.reply` pointing at the model text), and headers. Secrets
go in env vars, e.g. `Authorization: ${PROMPTMAP_TOKEN}`.

Modes:

- `direct`: you type evil input straight into the chat box.
- `indirect`: evil input hides inside pasted content (docs, notes,
  emails) that the app treats as data. v0.1 simulates the retrieved
  document inline.

Verdicts are three valued on purpose: `blocked`, `unclear`, and
`likely-vulnerable`. Heuristics cannot prove safety, they can only flag
what a human should review. Every flag ships with an evidence excerpt.

Exit codes are CI friendly: `0` clean, `2` hits found, `1` error.

## Development

```bash
make build   # compile everything
make test    # full suite with race detector
make vet     # static checks
make fmt     # format
```

Layout: `cmd/promptmap` is thin cobra wiring, real logic lives in
`internal/` (`config`, `payloads`, `mutate`, `detect`, `target`,
`runner`, `report`, `history`). The shipped corpus is 20 embedded
payloads under `internal/payloads/corpus`. Add your own payloads with
`--payload-dir`.

## Roadmap

The heuristic detector is the default and the LLM judge is the opt in
second opinion. Real callback based indirect tests are next on the
list. No server, no queue, no dashboard until someone actually needs
them.
