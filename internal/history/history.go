// Package history remembers past scans in a local SQLite file.
//
// Basically a memory for the CLI: every scan drops its summary plus
// per payload verdicts into a history.db file, so later commands can
// list runs and diff them ("are we more secure than last week?").
//
// We use modernc.org/sqlite (pure Go, no cgo) instead of the classic
// mattn driver so goreleaser cross builds work without a C toolchain.
// Tradeoff is a bigger binary, which is worth it for painless releases.
// Talk to it through database/sql only, so the driver stays swappable.
package history

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/promptmap/promptmap/internal/report"
)

const schema = `
CREATE TABLE IF NOT EXISTS scans(
	id INTEGER PRIMARY KEY,
	started_at TEXT NOT NULL,
	target_hash TEXT NOT NULL,
	corpus_version TEXT NOT NULL,
	total INTEGER NOT NULL,
	blocked INTEGER NOT NULL,
	unclear INTEGER NOT NULL,
	likely_vuln INTEGER NOT NULL,
	errors INTEGER NOT NULL,
	interrupted INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS findings(
	id INTEGER PRIMARY KEY,
	scan_id INTEGER NOT NULL REFERENCES scans(id),
	payload_id TEXT NOT NULL,
	category TEXT NOT NULL,
	verdict TEXT NOT NULL,
	reason TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_scan ON findings(scan_id);
`

// Store is one open history database.
type Store struct {
	db *sql.DB
}

// DefaultPath is where history lives when nobody configures a path.
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate config dir: %w", err)
	}
	return filepath.Join(dir, "promptmap", "history.db"), nil
}

// Open creates parent dirs as needed, opens the file, and migrates the
// schema. Schema changes are additive (CREATE TABLE IF NOT EXISTS), so
// old databases keep working when we add tables later.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create history dir: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open history db: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate history db: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the database handle.
func (s *Store) Close() error {
	return s.db.Close()
}

// SavedScan is one stored run with its per payload verdicts.
type SavedScan struct {
	ID            int64
	StartedAt     time.Time
	TargetHash    string
	CorpusVersion string
	Summary       report.Summary
	Interrupted   bool
	Findings      []SavedFinding
}

// SavedFinding is one stored probe verdict.
type SavedFinding struct {
	PayloadID string
	Category  string
	Verdict   string
	Reason    string
}

// Save stores a report and returns its scan id. Findings carry verdicts
// but not raw prompts or responses: history is for trending, full
// evidence stays in the JSON report files.
func (s *Store) Save(r report.Report) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin history tx: %w", err)
	}
	defer tx.Rollback()
	res, err := tx.Exec(
		`INSERT INTO scans(started_at, target_hash, corpus_version, total, blocked, unclear, likely_vuln, errors, interrupted)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.StartedAt.UTC().Format(time.RFC3339), r.TargetHash, r.CorpusVersion,
		r.Summary.Total, r.Summary.Blocked, r.Summary.Unclear,
		r.Summary.LikelyVuln, r.Summary.Errors, boolToInt(r.Interrupted),
	)
	if err != nil {
		return 0, fmt.Errorf("insert scan: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("scan id: %w", err)
	}
	for _, f := range r.Findings {
		if _, err := tx.Exec(
			`INSERT INTO findings(scan_id, payload_id, category, verdict, reason) VALUES(?, ?, ?, ?, ?)`,
			id, f.PayloadID, f.Category, f.Verdict, f.Reason,
		); err != nil {
			return 0, fmt.Errorf("insert finding: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit history: %w", err)
	}
	return id, nil
}

// Get loads one scan with its findings. Unknown ids error out so
// callers (history, diff) fail loudly instead of showing empty tables.
func (s *Store) Get(id int64) (SavedScan, error) {
	var out SavedScan
	var started string
	var interrupted int
	err := s.db.QueryRow(
		`SELECT id, started_at, target_hash, corpus_version, total, blocked, unclear, likely_vuln, errors, interrupted
		 FROM scans WHERE id = ?`, id,
	).Scan(&out.ID, &started, &out.TargetHash, &out.CorpusVersion,
		&out.Summary.Total, &out.Summary.Blocked, &out.Summary.Unclear,
		&out.Summary.LikelyVuln, &out.Summary.Errors, &interrupted)
	if err != nil {
		return SavedScan{}, fmt.Errorf("load scan %d: %w", id, err)
	}
	out.Interrupted = interrupted == 1
	out.StartedAt, _ = time.Parse(time.RFC3339, started)

	rows, err := s.db.Query(
		`SELECT payload_id, category, verdict, reason FROM findings WHERE scan_id = ? ORDER BY id`, id,
	)
	if err != nil {
		return SavedScan{}, fmt.Errorf("load findings: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var f SavedFinding
		if err := rows.Scan(&f.PayloadID, &f.Category, &f.Verdict, &f.Reason); err != nil {
			return SavedScan{}, fmt.Errorf("scan finding: %w", err)
		}
		out.Findings = append(out.Findings, f)
	}
	return out, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
