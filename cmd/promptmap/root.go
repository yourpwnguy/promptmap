// Package main wires the cobra CLI tree.
//
// We use cobra because it is the de facto Go CLI standard: subcommands,
// flags, help text, and shell completion for free. Hand rolled flag
// parsing would be reinventing shit and would drift over time.
//
// Viper binds flags plus YAML plus env so `scan --config p.yaml`
// just works and secrets can come from ${ENV} instead of files.
package main

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	verbose bool
	quiet   bool
	v       = viper.New()
)

// Version is set at release time via ldflags (-X main.Version=...).
// Local builds report dev, which is honest about what they are.
var Version = "dev"

// Execute builds the tree and runs it. Returns a process exit code.
func Execute() (int, error) {
	root := &cobra.Command{
		Use:     "promptmap",
		Short:   "Prompt injection scanner for LLM apps",
		Long:    "Probe an LLM chat endpoint with known injection payloads and report which ones look successful.",
		Version: Version,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			setupLogging()
		},
		SilenceUsage: true,
	}

	root.PersistentFlags().StringVar(&cfgFile, "config", "", "path to promptmap.yaml")
	root.PersistentFlags().BoolVar(&verbose, "verbose", false, "debug logging")
	root.PersistentFlags().BoolVar(&quiet, "quiet", false, "only warnings and errors")
	_ = v.BindPFlag("verbose", root.PersistentFlags().Lookup("verbose"))

	root.AddCommand(newInitCmd(), newScanCmd(), newListCmd(), newVerifyCmd(), newHistoryCmd())

	if err := root.Execute(); err != nil {
		return 1, err
	}
	if scanExitCode != nil {
		return *scanExitCode, nil
	}
	return 0, nil
}

func setupLogging() {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	if quiet {
		level = slog.LevelWarn
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(h))
}

// scanExitCode lets the scan command request exit 2 for hits without
// calling os.Exit deep inside testable code. Nil means 0.
var scanExitCode *int
