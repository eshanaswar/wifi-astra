package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"wifi-astra/internal/controller"
	"wifi-astra/pkg/constants"
	"wifi-astra/pkg/executor"
	"wifi-astra/pkg/hw"
	"wifi-astra/pkg/prereq"

	"github.com/spf13/cobra"
)

var (
	Verbose    bool
	ModDir     string
	ConfigFile string
	ExecMgr    *executor.Manager
	Ctrl       *controller.AssessmentController
)

var RootCmd = &cobra.Command{
	Use:   "astra",
	Short: "WiFi-Astra: Wireless Security Assessment Framework",
	Long: `WiFi-Astra is a professional wireless penetration testing framework for authorized engagements.

It covers the full 802.11 attack lifecycle — from passive discovery and client fingerprinting to
encryption attacks, rogue AP deployment, MitM pivoting, and automated report generation.

All operations require written authorization. The framework enforces scope boundaries at runtime:
modules are blocked from targeting BSSIDs outside the operator-defined scope list.

Run 'astra start' to launch an interactive session, or supply a JSON audit plan with --config
for unattended headless execution.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if err := prereq.VerifyEnvironment(); err != nil {
			fmt.Printf("%s[✗] Environment check failed: %v%s\n", constants.ThemeHigh, err, constants.ColorReset)
			os.Exit(1)
		}
		// Root-only operations handled here if global, 
		// but let's keep it minimal.
	},
}

func Execute() {
	ExecMgr = executor.NewManager()

	// Ensure hardware is always recovered even on panic
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "\n[!] PANIC: %v\n", r)
			fmt.Fprintln(os.Stderr, "[!] Attempting hardware recovery before exit...")
			ExecMgr.Cleanup()
			hw.Recover(false)
			os.Exit(2)
		}
	}()

	// Global signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		for {
			<-sigChan
			if Ctrl != nil && Ctrl.Running != "" {
				fmt.Printf("\n%s[!] Interrupt received. Aborting module %s...%s\n", constants.ThemeHigh, Ctrl.Running, constants.ColorReset)
				Ctrl.ExecMgr.Stop(Ctrl.Running)
				Ctrl.Running = ""
			} else {
				fmt.Printf("\n%s[!] Interrupt received. Cleaning up processes and restoring networking...%s\n", constants.ThemeHigh, constants.ColorReset)
				ExecMgr.Cleanup()
				// Restore system networking state
				hw.Recover(false)
				os.Exit(1)
			}
		}
	}()

	RootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "Enable debug-level logging to console and session log file")
	RootCmd.PersistentFlags().StringVar(&ModDir, "mod-dir", "./modules", "Path to directory containing assessment module scripts (*.sh)")
	RootCmd.PersistentFlags().StringVar(&ConfigFile, "config", "", "YAML config file (settings) or JSON audit plan (headless mode)")

	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	// Add commands here
}
