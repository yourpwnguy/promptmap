package main

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/promptmap/promptmap/internal/config"
	"github.com/promptmap/promptmap/internal/detect"
	"github.com/promptmap/promptmap/internal/payloads"
	"github.com/promptmap/promptmap/internal/target"
)

func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list-payloads",
		Short: "List embedded payloads",
		RunE: func(cmd *cobra.Command, args []string) error {
			all, err := payloads.LoadEmbedded()
			if err != nil {
				return err
			}
			for _, p := range all {
				fmt.Printf("%s [%s] %s\n", p.ID, p.Category, p.Severity)
			}
			return nil
		},
	}
}

func newVerifyCmd() *cobra.Command {
	var (
		payloadID string
		repeat    int
	)
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Resend one payload and show the raw response",
		Long: "Resend one payload N times. LLMs are non deterministic, so a\n" +
			"single hit can be luck. If verdicts differ across repeats, the\n" +
			"result is flaky and needs a human, not a victory lap.",
		RunE: func(cmd *cobra.Command, args []string) error {
			if repeat < 1 {
				return fmt.Errorf("--repeat must be >= 1, got %d", repeat)
			}
			// Same as scan: cfgFile global already has the --config value.
			cfg, err := config.Load(v, cfgFile)
			if err != nil {
				return err
			}
			all, err := payloads.LoadEmbedded()
			if err != nil {
				return err
			}
			var found *payloads.Payload
			for _, p := range all {
				if p.ID == payloadID {
					p := p
					found = &p
					break
				}
			}
			if found == nil {
				return fmt.Errorf("payload %q not found (see list-payloads)", payloadID)
			}
			sender := target.NewHTTPSender(target.Options{
				URL:          cfg.Target.URL,
				Method:       cfg.Target.Method,
				Headers:      cfg.Target.Headers,
				BodyTemplate: cfg.Target.BodyTemplate,
				ResponsePath: cfg.Target.ResponsePath,
				Timeout:      time.Duration(cfg.Target.TimeoutMs) * time.Millisecond,
			})
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			seen := map[detect.Verdict]int{}
			for i := 1; i <= repeat; i++ {
				text, status, err := sender.Send(ctx, found.Prompt)
				if err != nil {
					return err
				}
				out := detect.NewHeuristic().Classify(found.Canary, text)
				seen[out.Verdict]++
				fmt.Printf("--- attempt %d/%d: status %d, verdict %s (%s)\n%s\n", i, repeat, status, out.Verdict, out.Reason, text)
			}
			if len(seen) > 1 {
				fmt.Printf("flaky: verdicts differed across %d runs %v, treat as unclear\n", repeat, seen)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&payloadID, "payload-id", "", "payload to resend")
	cmd.Flags().IntVar(&repeat, "repeat", 1, "how many times to resend")
	_ = cmd.MarkFlagRequired("payload-id")
	return cmd
}
