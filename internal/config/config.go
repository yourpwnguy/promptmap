// Package config loads and validates promptmap run configuration.
//
// Basically this is the boring but important glue: read a YAML file,
// overlay env vars and CLI flags via viper, expand ${SECRETS} so people
// do not commit tokens, then fail fast with a helpful message if
// something is missing.
//
// We use viper here because merging file plus flags plus env by hand
// is exactly the kind of reinvented shit we want to avoid. Viper is
// mature, it does that one job well, and cobra hands it flags directly.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// Target describes where and how to send a prompt.
//
// The BodyTemplate must contain {{PROMPT}} which we replace per probe.
// ResponsePath is a gjson path like $.reply or $.choices.0.message.content
// that tells us where the model text lives in the JSON reply.
type Target struct {
	URL          string            `mapstructure:"url"`
	Method       string            `mapstructure:"method"`
	Headers      map[string]string `mapstructure:"headers"`
	BodyTemplate string            `mapstructure:"body"`
	ResponsePath string            `mapstructure:"response_path"`
	TimeoutMs    int               `mapstructure:"timeout_ms"`
}

// Scan describes how aggressive the run is.
type Scan struct {
	Mode         string   `mapstructure:"mode"`
	Concurrency  int      `mapstructure:"concurrency"`
	RatePerSec   float64  `mapstructure:"rate_per_sec"`
	Categories   []string `mapstructure:"include_categories"`
	Mutations    []string `mapstructure:"mutations"`
	MaxProbes    int      `mapstructure:"max_probes"`
	AllowPrivate bool     `mapstructure:"allow_private"`
	HistoryDB    string   `mapstructure:"history_db"`
}

// Config is the full run configuration.
type Config struct {
	Version int    `mapstructure:"version"`
	Target  Target `mapstructure:"target"`
	Scan    Scan   `mapstructure:"scan"`
}

// Defaults fills in sane values so a minimal YAML still works.
func Defaults() Config {
	return Config{
		Version: 1,
		Target: Target{
			Method:       "POST",
			ResponsePath: "$.reply",
			TimeoutMs:    15000,
		},
		Scan: Scan{
			Mode:        "direct",
			Concurrency: 5,
			RatePerSec:  5,
			MaxProbes:   200,
		},
	}
}

// Load reads path with viper, overlays CLI overrides already bound to
// the viper instance, expands env vars, and validates.
func Load(v *viper.Viper, path string) (Config, error) {
	cfg := Defaults()

	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return Config{}, fmt.Errorf("read config %s: %w", path, err)
		}
	}

	if err := v.Unmarshal(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	cfg.Target.BodyTemplate = os.ExpandEnv(cfg.Target.BodyTemplate)
	for k, val := range cfg.Target.Headers {
		cfg.Target.Headers[k] = os.ExpandEnv(val)
	}

	if err := Validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate fails fast with actionable messages.
//
// We do manual checks instead of pulling in a validator lib because
// there are only a handful of rules and explicit ifs read better
// for a junior than struct tags with magic.
func Validate(c Config) error {
	if c.Target.URL == "" {
		return fmt.Errorf("target.url is required (run `promptmap init` for an example)")
	}
	u, err := url.Parse(c.Target.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("target.url must be http(s), got %q", c.Target.URL)
	}
	if !c.Scan.AllowPrivate {
		host := strings.ToLower(u.Hostname())
		if host == "localhost" || host == "127.0.0.1" || host == "::1" || strings.HasPrefix(host, "169.254.") {
			return fmt.Errorf("target %q looks private, refusing without allow_private (prevents accidental metadata scans)", host)
		}
	}
	if !strings.Contains(c.Target.BodyTemplate, "{{PROMPT}}") {
		return fmt.Errorf("target.body must contain {{PROMPT}} placeholder so we know where to inject")
	}
	if c.Scan.Mode != "direct" && c.Scan.Mode != "indirect" {
		return fmt.Errorf("scan.mode must be direct or indirect, got %q", c.Scan.Mode)
	}
	if c.Scan.Concurrency < 1 || c.Scan.Concurrency > 50 {
		return fmt.Errorf("scan.concurrency must be 1..50, got %d", c.Scan.Concurrency)
	}
	if c.Scan.RatePerSec <= 0 || c.Scan.RatePerSec > 100 {
		return fmt.Errorf("scan.rate_per_sec must be 0..100, got %v", c.Scan.RatePerSec)
	}
	if c.Scan.MaxProbes < 1 {
		return fmt.Errorf("scan.max_probes must be >= 1")
	}
	return nil
}

// SampleYAML returns a starter config for `promptmap init`.
func SampleYAML() string {
	return `version: 1
target:
  url: http://localhost:8080/api/chat
  method: POST
  headers:
    Content-Type: application/json
    Authorization: ${PROMPTMAP_TOKEN}
  body: '{"message": "{{PROMPT}}"}'
  response_path: $.reply
  timeout_ms: 15000
scan:
  mode: direct
  concurrency: 5
  rate_per_sec: 5
  include_categories: []
  mutations: [case-swap, pad-whitespace]
  max_probes: 200
  allow_private: true
  # empty history_db saves to the default history file, --no-history disables it
  history_db: ""
`
}
