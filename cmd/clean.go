package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
	"wifi-astra/internal/config"
	"wifi-astra/internal/logging"

	"github.com/spf13/cobra"
)

var (
	olderThan int
	dryRun    bool
)

var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Remove stale session directories older than a threshold",
	Long: `Scan the sessions directory and permanently delete session folders whose last
modification time exceeds the --older-than threshold.

Use --dry-run first to review what would be removed before committing to deletion.

Example:
  astra clean --older-than 7 --dry-run   # preview sessions older than 7 days
  astra clean --older-than 7             # delete them`,
	Run: func(cmd *cobra.Command, args []string) {
		baseDir := "./sessions"
		if config.GlobalConfig != nil && config.GlobalConfig.SessionDir != "" {
			baseDir = config.GlobalConfig.SessionDir
		}

		logging.Info("Scanning for sessions older than %d days in %s...", olderThan, baseDir)

		entries, err := os.ReadDir(baseDir)
		if err != nil {
			logging.Error("Failed to read sessions directory: %v", err)
			return
		}

		now := time.Now()
		count := 0
		var totalSize int64

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			path := filepath.Join(baseDir, entry.Name())
			info, err := entry.Info()
			if err != nil {
				continue
			}

			if now.Sub(info.ModTime()) > time.Duration(olderThan)*24*time.Hour {
				count++
				size := getDirSize(path)
				totalSize += size

				if dryRun {
					fmt.Printf("[DRY-RUN] Would delete: %s (%d MB)\n", entry.Name(), size/(1024*1024))
				} else {
					fmt.Printf("[*] Deleting session: %s...\n", entry.Name())
					if err := os.RemoveAll(path); err != nil {
						logging.Error("Failed to delete %s: %v", entry.Name(), err)
					}
				}
			}
		}

		if count == 0 {
			logging.Info("No stale sessions found.")
		} else {
			if dryRun {
				logging.Success("Scan complete. %d sessions identified for cleanup (Total: %d MB).", count, totalSize/(1024*1024))
			} else {
				logging.Success("Cleanup complete. Removed %d sessions, freeing %d MB.", count, totalSize/(1024*1024))
			}
		}
	},
}

func getDirSize(path string) int64 {
	var size int64
	filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
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
	RootCmd.AddCommand(cleanCmd)
}
