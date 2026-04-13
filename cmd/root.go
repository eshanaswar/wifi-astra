package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"wifi-astra/internal/controller"
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
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if err := prereq.VerifyEnvironment(); err != nil {
			fmt.Printf("[✗] Environment check failed: %v\n", err)
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
				fmt.Printf("\n[!] Interrupt received. Aborting module %s...\n", Ctrl.Running)
				Ctrl.ExecMgr.Stop(Ctrl.Running)
				Ctrl.Running = ""
			} else {
				fmt.Println("\n[!] Interrupt received. Cleaning up processes and restoring networking...")
				ExecMgr.Cleanup()
				// Restore system networking state
				hw.Recover(false)
				os.Exit(1)
			}
		}
	}()

	RootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "Enable verbose output")
	RootCmd.PersistentFlags().StringVar(&ModDir, "mod-dir", "./modules", "Path to assessment modules")
	RootCmd.PersistentFlags().StringVar(&ConfigFile, "config", "", "Path to global configuration file or headless audit plan")

	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	// Add commands here
}
