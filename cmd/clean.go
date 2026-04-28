package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"wifi-astra/internal/config"
	"wifi-astra/internal/logging"
	"wifi-astra/internal/ui"

	"github.com/spf13/cobra"
)

var (
	olderThan int
	dryRun    bool
	force     bool
)

type staleSession struct {
	name    string
	path    string
	ageDays int
	sizeB   int64
}

var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Remove stale session directories older than a threshold",
	Long: `Scan the sessions directory and permanently delete session folders whose last
modification time exceeds the --older-than threshold.

A formatted table of matching sessions is always shown before any deletion.
Use --dry-run to preview without deleting. Use --force / -f to skip the
interactive confirmation prompt (useful for scripts and cron jobs).

Example:
  astra clean --older-than 7 --dry-run     # preview sessions older than 7 days
  astra clean --older-than 7               # delete with confirmation prompt
  astra clean --older-than 7 --force       # delete without prompt (scriptable)`,
	Run: func(cmd *cobra.Command, args []string) {
		baseDir := "./sessions"
		if config.GlobalConfig != nil && config.GlobalConfig.SessionDir != "" {
			baseDir = config.GlobalConfig.SessionDir
		}

		fmt.Printf("[*] Scanning sessions older than %d days in %s...\n", olderThan, baseDir)

		entries, err := os.ReadDir(baseDir)
		if err != nil {
			logging.Error("Failed to read sessions directory: %v", err)
			return
		}

		now := time.Now()
		threshold := time.Duration(olderThan) * 24 * time.Hour

		var candidates []staleSession
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			age := now.Sub(info.ModTime())
			if age > threshold {
				p := filepath.Join(baseDir, entry.Name())
				candidates = append(candidates, staleSession{
					name:    entry.Name(),
					path:    p,
					ageDays: int(age.Hours() / 24),
					sizeB:   getDirSize(p),
				})
			}
		}

		if len(candidates) == 0 {
			fmt.Printf("[*] No sessions older than %d days found.\n", olderThan)
			return
		}

		var totalSize int64
		for _, c := range candidates {
			totalSize += c.sizeB
		}
		totalMB := totalSize / (1024 * 1024)
		n := len(candidates)

		w := tabwriter.NewWriter(os.Stdout, 2, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  SESSION\tAGE\tSIZE")
		fmt.Fprintln(w, "  ──────────────────────────────────\t─────────\t──────")
		for _, c := range candidates {
			fmt.Fprintf(w, "  %s\t%d days\t%d MB\n", c.name, c.ageDays, c.sizeB/(1024*1024))
		}
		w.Flush()
		fmt.Println()

		if dryRun {
			fmt.Printf("[*] %d session(s) would be deleted (%d MB). Run without --dry-run to remove.\n", n, totalMB)
			return
		}

		if !force {
			prompt := fmt.Sprintf("Delete %d session(s) (%d MB)?", n, totalMB)
			if !ui.PromptConfirm(prompt, false) {
				fmt.Println("[*] Aborted. No sessions deleted.")
				return
			}
		}

		deleted := 0
		for _, c := range candidates {
			fmt.Printf("[*] Deleting: %s\n", c.name)
			if err := os.RemoveAll(c.path); err != nil {
				logging.Error("Failed to delete %s: %v", c.name, err)
			} else {
				deleted++
			}
		}
		fmt.Printf("[✓] Removed %d session(s), freed %d MB.\n", deleted, totalMB)
	},
}

func getDirSize(path string) int64 {
	var size int64
	filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable entries, keep walking
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size
}

func init() {
	cleanCmd.Flags().IntVarP(&olderThan, "older-than", "t", 30, "Delete sessions whose last modification time exceeds N days")
	cleanCmd.Flags().BoolVar(&dryRun, "dry-run", false, "List sessions that would be removed without deleting them")
	cleanCmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation prompt and delete immediately")
	RootCmd.AddCommand(cleanCmd)
}
