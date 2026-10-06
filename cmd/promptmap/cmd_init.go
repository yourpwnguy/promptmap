package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/promptmap/promptmap/internal/config"
)

func newInitCmd() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write a starter promptmap.yaml",
		RunE: func(cmd *cobra.Command, args []string) error {
			if out == "" {
				out = "promptmap.yaml"
			}
			if _, err := os.Stat(out); err == nil {
				return fmt.Errorf("%s already exists, refusing to overwrite", out)
			}
			if err := os.WriteFile(out, []byte(config.SampleYAML()), 0o644); err != nil {
				return fmt.Errorf("write %s: %w", out, err)
			}
			fmt.Println("wrote", out, "(edit target.url, then run scan with --i-have-permission)")
			return nil
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "promptmap.yaml", "where to write the sample config")
	return cmd
}
