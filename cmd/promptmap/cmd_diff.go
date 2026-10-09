package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/promptmap/promptmap/internal/history"
)

// newDiffCmd compares two saved scans.
//
// Basically "did last week's fix work?". Give it the older id and the
// newer id and it prints three buckets: newly broken stuff (bad news),
// stuff that got fixed (good news), and anything else that moved. It
// exits 2 when nothing got fixed or something new broke, so CI can
// gate on it.
func newDiffCmd() *cobra.Command {
	var (
		fromID int64
		toID   int64
		dbFile string
	)
	cmd := &cobra.Command{
		Use:   "diff FROM_ID TO_ID",
		Short: "Compare two saved scans",
		Long:  "Compare an older scan against a newer one by their ids from `promptmap history`.",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Ids come from flags first, then positional args, since
			// `diff 1 2` is the natural thing to type.
			if !cmd.Flags().Changed("from") {
				if len(args) < 1 {
					return fmt.Errorf("need FROM_ID (from `promptmap history`)")
				}
				var err error
				fromID, err = parseID(args[0])
				if err != nil {
					return err
				}
			}
			if !cmd.Flags().Changed("to") {
				if len(args) < 2 {
					return fmt.Errorf("need TO_ID (from `promptmap history`)")
				}
				var err error
				toID, err = parseID(args[1])
				if err != nil {
					return err
				}
			}
			if fromID < 1 || toID < 1 {
				return fmt.Errorf("scan ids must be positive, got %d and %d", fromID, toID)
			}

			path := dbFile
			if path == "" {
				path = historyDBFromConfig(cfgFile)
			}
			if path == "" {
				var err error
				path, err = history.DefaultPath()
				if err != nil {
					return err
				}
			}
			st, err := history.Open(path)
			if err != nil {
				return err
			}
			defer st.Close()

			res, err := st.Compare(fromID, toID)
			if err != nil {
				return err
			}
			for _, w := range res.Warnings {
				fmt.Println("warning:", w)
			}
			fmt.Printf("scan %d -> %d\n", res.FromID, res.ToID)
			if len(res.Fixed) > 0 {
				fmt.Println("fixed:")
				for _, ch := range res.Fixed {
					fmt.Printf("  %s [%s] %s -> %s\n", ch.PayloadID, ch.Category, ch.Before, ch.After)
				}
			}
			if len(res.New) > 0 {
				fmt.Println("new problems:")
				for _, ch := range res.New {
					fmt.Printf("  %s [%s] %s -> %s\n", ch.PayloadID, ch.Category, ch.Before, ch.After)
				}
			}
			if len(res.Changed) > 0 {
				fmt.Println("other changes:")
				for _, ch := range res.Changed {
					fmt.Printf("  %s [%s] %s -> %s\n", ch.PayloadID, ch.Category, ch.Before, ch.After)
				}
			}
			if len(res.Fixed) == 0 && len(res.New) == 0 && len(res.Changed) == 0 {
				fmt.Println("no changes between these scans")
			}

			// Exit 2 when nothing improved and something got worse, so
			// CI can fail a regression without parsing our output.
			if len(res.Fixed) == 0 && len(res.New) > 0 {
				code := 2
				scanExitCode = &code
			}
			return nil
		},
	}
	cmd.Flags().Int64Var(&fromID, "from", 0, "older scan id")
	cmd.Flags().Int64Var(&toID, "to", 0, "newer scan id")
	cmd.Flags().StringVar(&dbFile, "history-db", "", "history file path")
	return cmd
}

func parseID(s string) (int64, error) {
	var v int64
	if _, err := fmt.Sscanf(s, "%d", &v); err != nil {
		return 0, fmt.Errorf("bad scan id %q (see `promptmap history`)", s)
	}
	return v, nil
}
