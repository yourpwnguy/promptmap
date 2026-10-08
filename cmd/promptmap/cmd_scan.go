package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/promptmap/promptmap/internal/config"
	"github.com/promptmap/promptmap/internal/detect"
	"github.com/promptmap/promptmap/internal/mutate"
	"github.com/promptmap/promptmap/internal/payloads"
	"github.com/promptmap/promptmap/internal/report"
	"github.com/promptmap/promptmap/internal/runner"
	"github.com/promptmap/promptmap/internal/target"
)

func newScanCmd() *cobra.Command {
	var (
		mode        string
		output      string
		customDir   string
		permission  bool
		maxProbes   int
		concurrency int
		ratePerSec  float64
		quickURL    string
		quickMethod string
		quickBody   string
		quickResp   string
		headers     []string
		categories  []string
		saveAll     bool
		format      string
		timeout     time.Duration
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run payloads against a target",
		Long: "Scan from a config file (--config) or ad hoc with --url.\n" +
			"Quick mode example: promptmap scan --url http://localhost:8080/api/chat --i-have-permission",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !permission {
				return fmt.Errorf("refusing without --i-have-permission (only scan apps you own or are allowed to test)")
			}
			switch format {
			case "json", "html", "both":
			default:
				return fmt.Errorf("bad --format %q (want json, html or both)", format)
			}
			var cfg config.Config
			if cfgFile == "" {
				// No config file: build one from flags. Quick mode trusts
				// the explicit --url (including localhost), the permission
				// flag above is the real consent gate.
				var err error
				cfg, err = quickConfig(quickURL, quickMethod, quickBody, quickResp)
				if err != nil {
					return err
				}
			} else {
				var err error
				cfg, err = config.Load(v, cfgFile)
				if err != nil {
					return fmt.Errorf("load config: %w (run `promptmap init` first or use --url)", err)
				}
			}
			if cmd.Flags().Changed("mode") {
				cfg.Scan.Mode = mode
			}
			if cmd.Flags().Changed("max-probes") {
				cfg.Scan.MaxProbes = maxProbes
			}
			if cmd.Flags().Changed("concurrency") {
				cfg.Scan.Concurrency = concurrency
			}
			if cmd.Flags().Changed("rate") {
				cfg.Scan.RatePerSec = ratePerSec
			}
			if cmd.Flags().Changed("categories") {
				cfg.Scan.Categories = categories
			}
			extra, err := parseHeaders(headers)
			if err != nil {
				return err
			}
			if cfg.Target.Headers == nil {
				cfg.Target.Headers = map[string]string{}
			}
			for k, val := range extra {
				cfg.Target.Headers[k] = val
			}
			return runScan(cfg, scanOpts{output: output, customDir: customDir, saveAll: saveAll, format: format, timeout: timeout})
		},
	}
	cmd.Flags().StringVar(&mode, "mode", "direct", "direct or indirect")
	cmd.Flags().StringVarP(&output, "output", "o", "promptmap-report.json", "report path")
	cmd.Flags().StringVar(&customDir, "payload-dir", "", "extra custom payloads dir")
	cmd.Flags().BoolVar(&permission, "i-have-permission", false, "confirm you are allowed to test this target")
	cmd.Flags().IntVar(&maxProbes, "max-probes", 200, "cap total probes")
	cmd.Flags().IntVar(&concurrency, "concurrency", 5, "parallel requests")
	cmd.Flags().Float64Var(&ratePerSec, "rate", 5, "requests per second")
	cmd.Flags().StringVar(&quickURL, "url", "", "target chat URL (quick mode, no config file needed)")
	cmd.Flags().StringVar(&quickMethod, "method", "POST", "HTTP method for quick mode")
	cmd.Flags().StringVar(&quickBody, "body", `{"message": "{{PROMPT}}"}`, "body template for quick mode")
	cmd.Flags().StringVar(&quickResp, "response-path", "$.reply", "gjson path to model text for quick mode")
	cmd.Flags().StringArrayVar(&headers, "header", nil, `"Key: Value" header to send (repeatable)`)
	cmd.Flags().StringSliceVar(&categories, "categories", nil, "only run these payload categories (comma separated or repeatable)")
	cmd.Flags().BoolVar(&saveAll, "save-all", false, "save prompts and responses for blocked probes too (big files)")
	cmd.Flags().StringVar(&format, "format", "json", "report format: json, html or both")
	cmd.Flags().DurationVar(&timeout, "timeout", 0, "overall scan deadline, e.g. 2m (0 means none)")
	return cmd
}

// scanOpts groups the run time knobs so runScan does not grow a new
// parameter every time we add a flag. Plain struct, no magic.
type scanOpts struct {
	output    string
	customDir string
	saveAll   bool
	format    string
	timeout   time.Duration
}

// parseHeaders turns repeatable --header "Key: Value" flags into a map.
// Flags win over config file entries on exact key match. Values may
// contain colons (we split on the first one only).
func parseHeaders(flags []string) (map[string]string, error) {
	out := map[string]string{}
	for _, h := range flags {
		k, val, ok := strings.Cut(h, ":")
		k, val = strings.TrimSpace(k), strings.TrimSpace(val)
		if !ok || k == "" || val == "" {
			return nil, fmt.Errorf("bad --header %q (want \"Key: Value\")", h)
		}
		out[k] = val
	}
	return out, nil
}

// quickConfig builds a Config from --url flags so trivial targets do
// not need a YAML file. Anything exotic (custom auth, GraphQL) still
// wants a real config file.
func quickConfig(rawURL, method, body, respPath string) (config.Config, error) {
	if rawURL == "" {
		return config.Config{}, fmt.Errorf("need --url or --config (run `promptmap init` for a file example)")
	}
	cfg := config.Defaults()
	cfg.Target.URL = rawURL
	cfg.Target.Method = method
	cfg.Target.BodyTemplate = body
	cfg.Target.ResponsePath = respPath
	cfg.Scan.AllowPrivate = true
	if err := config.Validate(cfg); err != nil {
		return config.Config{}, err
	}
	return cfg, nil
}

// selectPayloads picks which corpus entries run for this scan.
//
// Direct mode runs everything except indirect-basic (those carry their
// own doc wrapper and belong to indirect mode). Indirect mode runs only
// indirect-basic unless the user explicitly filtered categories, in
// which case we honor the filter and let an empty result fail loudly
// downstream instead of silently scanning the wrong thing.
func selectPayloads(all []payloads.Payload, mode string, categories []string) []payloads.Payload {
	if mode == "indirect" {
		if len(categories) == 0 {
			return payloads.Filter(all, []string{"indirect-basic"})
		}
		return payloads.Filter(all, categories)
	}
	var base []payloads.Payload
	for _, p := range payloads.Filter(all, categories) {
		if p.Category == "indirect-basic" {
			continue
		}
		base = append(base, p)
	}
	return base
}

func runScan(cfg config.Config, o scanOpts) error {
	started := time.Now()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	// An overall deadline turns a hung target into a partial report
	// instead of a hung CLI. Expiry marks the report interrupted, same
	// as Ctrl-C, so downstream tooling treats it as incomplete.
	if o.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.timeout)
		defer cancel()
	}

	all, err := payloads.LoadEmbedded()
	if err != nil {
		return err
	}
	extra, err := payloads.LoadDir(o.customDir)
	if err != nil {
		return err
	}
	all = append(all, extra...)

	base := selectPayloads(all, cfg.Scan.Mode, cfg.Scan.Categories)
	if len(base) == 0 {
		return fmt.Errorf("no payloads selected for mode %q (check corpus and filters)", cfg.Scan.Mode)
	}

	muts, err := mutate.Registry(cfg.Scan.Mutations)
	if err != nil {
		return err
	}
	probes := mutate.Expand(base, muts, cfg.Scan.MaxProbes)
	slog.Info("scan starting", "mode", cfg.Scan.Mode, "probes", len(probes), "target", cfg.Target.URL)

	sender := target.NewHTTPSender(target.Options{
		URL:          cfg.Target.URL,
		Method:       cfg.Target.Method,
		Headers:      cfg.Target.Headers,
		BodyTemplate: cfg.Target.BodyTemplate,
		ResponsePath: cfg.Target.ResponsePath,
		Timeout:      time.Duration(cfg.Target.TimeoutMs) * time.Millisecond,
	})
	det := detect.NewHeuristic()

	results := runner.Run(ctx, probes, sender, det, runner.Options{
		Concurrency: cfg.Scan.Concurrency,
		RatePerSec:  cfg.Scan.RatePerSec,
	}, func(done, total int, r runner.Result) {
		if r.Verdict == detect.LikelyVuln || r.Verdict == detect.Unclear {
			fmt.Printf("[%d/%d] %s %s (%s)\n", done, total, r.Verdict, r.Probe.PayloadID, r.Reason)
		} else if verbose {
			fmt.Printf("[%d/%d] %s %s\n", done, total, r.Verdict, r.Probe.PayloadID)
		}
	})

	interrupted := ctx.Err() != nil
	sum := sha256.Sum256([]byte(cfg.Target.URL))
	rep := report.Build(results, fmt.Sprintf("sha256:%x", sum[:8]), "v0.1.0", started, interrupted, o.saveAll)
	switch o.format {
	case "json":
		if err := report.WriteJSON(o.output, rep); err != nil {
			return err
		}
		fmt.Println("wrote", o.output)
	case "html":
		if err := report.WriteHTML(o.output, rep); err != nil {
			return err
		}
		fmt.Println("wrote", o.output)
	case "both":
		if err := report.WriteJSON(o.output, rep); err != nil {
			return err
		}
		htmlPath := report.HTMLPath(o.output)
		if err := report.WriteHTML(htmlPath, rep); err != nil {
			return err
		}
		fmt.Println("wrote", o.output, "and", htmlPath)
	default:
		return fmt.Errorf("unreachable: bad format %q slipped past flag validation", o.format)
	}
	report.PrintSummary(rep)

	if rep.Summary.LikelyVuln > 0 || rep.Summary.Unclear > 0 {
		code := 2
		scanExitCode = &code
	}
	return nil
}
