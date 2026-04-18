package cmd

import (
	"fmt"
	"strings"
	"wifi-astra/internal/ingest"

	"github.com/spf13/cobra"
)

var lookupOuiCmd = &cobra.Command{
	Use:   "lookup-oui [MAC/OUI]",
	Short: "Identify the hardware vendor for a MAC address or OUI prefix",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		input := strings.TrimSpace(args[0])
		if input == "" {
			return
		}

		vendor := ingest.LookupVendor(input)
		if vendor != "Unknown" {
			fmt.Println(vendor)
		} else {
			fmt.Println("Unknown Vendor")
		}
	},
}

func init() {
	RootCmd.AddCommand(lookupOuiCmd)
}
