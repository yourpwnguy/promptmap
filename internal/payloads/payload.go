// Package payloads loads the attack corpus from YAML files.
//
// Basically a Payload is one evil thing we want to try, plus the
// canary string we expect to see if the app falls for it. Think of
// it like a Nuclei template but way simpler: prompt in, canary out.
//
// We embed the shipped corpus into the binary with go:embed so the
// tool works offline, and we also load user custom payloads from a
// directory so hackers can add their own without forking us.
package payloads

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed all:corpus
var embedded embed.FS

// Payload is one injection test.
type Payload struct {
	ID          string   `yaml:"id"`
	Category    string   `yaml:"category"`
	Severity    string   `yaml:"severity"`
	Description string   `yaml:"description"`
	Prompt      string   `yaml:"prompt"`
	Canary      string   `yaml:"canary"`
	BlockedHint []string `yaml:"blocked_hint"`
}

// Probe is a Payload with a concrete mutated prompt ready to send.
//
// We keep Payload (the template) separate from Probe (what we send)
// so mutators can expand one payload into several probes without
// losing track of which payload they came from.
type Probe struct {
	PayloadID string
	Category  string
	Severity  string
	Canary    string
	Prompt    string
	Mutations []string
}

// LoadEmbedded returns the shipped corpus (direct plus indirect).
func LoadEmbedded() ([]Payload, error) {
	return loadFromFS(embedded, "corpus")
}

// LoadDir loads extra user payloads from a directory tree of *.yaml.
func LoadDir(dir string) ([]Payload, error) {
	if dir == "" {
		return nil, nil
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, nil
	}
	var out []Payload
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || (!strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml")) {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		var p Payload
		if err := yaml.Unmarshal(raw, &p); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		if err := check(p); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Filter keeps only the requested categories. Empty means keep all.
func Filter(all []Payload, categories []string) []Payload {
	if len(categories) == 0 {
		return all
	}
	want := map[string]bool{}
	for _, c := range categories {
		want[strings.ToLower(c)] = true
	}
	var out []Payload
	for _, p := range all {
		if want[strings.ToLower(p.Category)] {
			out = append(out, p)
		}
	}
	return out
}

func loadFromFS(fsys embed.FS, root string) ([]Payload, error) {
	var out []Payload
	err := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || (!strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml")) {
			return nil
		}
		raw, err := fsys.ReadFile(path)
		if err != nil {
			return err
		}
		var p Payload
		if err := yaml.Unmarshal(raw, &p); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		if err := check(p); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func check(p Payload) error {
	if p.ID == "" || p.Prompt == "" || p.Canary == "" {
		return fmt.Errorf("payload needs id, prompt and canary")
	}
	return nil
}
