package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
	"wifi-astra/internal/logging"
	"wifi-astra/internal/ui"

	"github.com/spf13/cobra"
)

var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Manage old assessment sessions (archive or delete)",
	Run: func(cmd *cobra.Command, args []string) {
		days, _ := cmd.Flags().GetInt("days")
		force, _ := cmd.Flags().GetBool("force")
		
		baseDir := "./sessions"
		entries, err := os.ReadDir(baseDir)
		if err != nil {
			logging.Error("Failed to read sessions directory: %v", err)
			os.Exit(1)
		}

		cutoff := time.Now().AddDate(0, 0, -days)
		count := 0
		
		fmt.Printf("\n--- WiFi-Astra: Session Cleanup ---\n")
		fmt.Printf("Searching for sessions older than %d days...\n", days)

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			info, err := entry.Info()
			if err != nil {
				continue
			}

			if info.ModTime().Before(cutoff) {
				count++
				path := filepath.Join(baseDir, entry.Name())
				
				if force {
					os.RemoveAll(path)
					fmt.Printf("   [!] Deleted: %s\n", entry.Name())
				} else {
					fmt.Printf("   [?] Old session found: %s (Last modified: %s)\n", 
						entry.Name(), info.ModTime().Format("2006-01-02"))
				}
			}
		}

		if count == 0 {
			logging.Info("No old sessions found.")
			return
		}

		if !force {
			if ui.PromptConfirm(fmt.Sprintf("Delete these %d sessions?", count), false) {
				for _, entry := range entries {
					if !entry.IsDir() { continue }
					info, _ := entry.Info()
					if info.ModTime().Before(cutoff) {
						os.RemoveAll(filepath.Join(baseDir, entry.Name()))
					}
				}
				logging.Success("Cleanup complete.")
			} else {
				fmt.Println("Cleanup aborted.")
			}
		} else {
			logging.Success("Cleanup complete. %d sessions removed.", count)
		}
	},
}

func init() {
	cleanCmd.Flags().Int("days", 30, "Delete sessions older than X days")
	cleanCmd.Flags().Bool("force", false, "Delete without confirmation")
	RootCmd.AddCommand(cleanCmd)
}
