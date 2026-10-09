package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/promptmap/promptmap/internal/history"
)

// historyDBFromConfig reads scan.history_db from a config file, if one
// was given and parses. Failure falls back to the default file rather
// than erroring, since listing history should never be hostage to a
// broken config.
func historyDBFromConfig(path string) string {
	if path == "" {
		return ""
	}
	v2 := viper.New()
	v2.SetConfigFile(path)
	if err := v2.ReadInConfig(); err != nil {
		return ""
	}
	return v2.GetString("scan.history_db")
}

// newHistoryCmd lists past scans from the SQLite history file.
//
// Basically a lookup table for "what did I run before and what did it
// find". The ids it prints are the ones you feed to `history show`,
// `diff` and friends.
func newHistoryCmd() *cobra.Command {
	var limit int
	var dbFile string
	cmd := &cobra.Command{
		Use:   "history",
		Short: "List saved scans",
		RunE: func(cmd *cobra.Command, args []string) error {
			if limit < 1 {
				return fmt.Errorf("--limit must be >= 1, got %d", limit)
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

			rows, err := st.List(limit)
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				// Fresh installs and "--no-history" users both land here,
				// so tell them where scans get recorded.
				fmt.Printf("no scans in %s yet, run a scan first\n", path)
				return nil
			}
			for _, r := range rows {
				flag := ""
				if r.Interrupted {
					flag = " (interrupted)"
				}
				fmt.Printf("#%-3d %s  total=%d likely=%d unclear=%d%s\n",
					r.ID, r.StartedAt.Format("2006-01-02 15:04"), r.Total, r.LikelyVuln, r.Unclear, flag)
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 20, "most recent N scans")
	cmd.Flags().StringVar(&dbFile, "history-db", "", "history file path")
	return cmd
}
