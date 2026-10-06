package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
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
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run payloads against a target",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !permission {
				return fmt.Errorf("refusing without --i-have-permission (only scan apps you own or are allowed to test)")
			}
			// cfgFile is bound to the root persistent --config flag, so it
			// already holds the user's value no matter where they placed it
			// on the command line. No Changed check needed.
			cfg, err := config.Load(v, cfgFile)
			if err != nil {
				// Allow pure flag mode when no config file exists: require --url.
				return fmt.Errorf("load config: %w (run `promptmap init` first or pass --config)", err)
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
			return runScan(cfg, output, customDir)
		},
	}
	cmd.Flags().StringVar(&mode, "mode", "direct", "direct or indirect")
	cmd.Flags().StringVarP(&output, "output", "o", "promptmap-report.json", "report path")
	cmd.Flags().StringVar(&customDir, "payload-dir", "", "extra custom payloads dir")
	cmd.Flags().BoolVar(&permission, "i-have-permission", false, "confirm you are allowed to test this target")
	cmd.Flags().IntVar(&maxProbes, "max-probes", 200, "cap total probes")
	cmd.Flags().IntVar(&concurrency, "concurrency", 5, "parallel requests")
	cmd.Flags().Float64Var(&ratePerSec, "rate", 5, "requests per second")
	return cmd
}

func runScan(cfg config.Config, output, customDir string) error {
	started := time.Now()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	all, err := payloads.LoadEmbedded()
	if err != nil {
		return err
	}
	extra, err := payloads.LoadDir(customDir)
	if err != nil {
		return err
	}
	all = append(all, extra...)

	// Mode selects which slice of the corpus runs. Direct skips
	// indirect-basic (those need the doc wrapper which they already
	// carry), indirect runs only those. Simple and explainable.
	var base []payloads.Payload
	if cfg.Scan.Mode == "indirect" {
		base = payloads.Filter(all, []string{"indirect-basic"})
	} else {
		for _, p := range payloads.Filter(all, cfg.Scan.Categories) {
			if p.Category == "indirect-basic" {
				continue
			}
			base = append(base, p)
		}
	}
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
	rep := report.Build(results, fmt.Sprintf("sha256:%x", sum[:8]), "v0.1.0", started, interrupted)
	if err := report.WriteJSON(output, rep); err != nil {
		return err
	}
	report.PrintSummary(rep)
	fmt.Println("wrote", output)

	if rep.Summary.LikelyVuln > 0 || rep.Summary.Unclear > 0 {
		code := 2
		scanExitCode = &code
	}
	return nil
}
