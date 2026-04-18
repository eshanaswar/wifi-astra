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
	Long: `Look up the hardware manufacturer registered to a MAC address or OUI prefix
in the locally cached IEEE OUI database.

Accepts a full MAC address or just the first three octets (OUI prefix).
Run 'astra update-oui' to refresh the database if the result is "Unknown Vendor".

Examples:
  astra lookup-oui 00:1A:2B:3C:4D:5E
  astra lookup-oui 00:1A:2B`,
	Args: cobra.ExactArgs(1),
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
