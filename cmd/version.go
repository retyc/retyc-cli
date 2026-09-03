package cmd

import (
	"fmt"

	"github.com/retyc/retyc-cli/internal/config"
	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags.
var Version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number",
	RunE: func(cmd *cobra.Command, args []string) error {
		if jsonOutput {
			return printJSON(versionJSON{Version: Version, BuildMode: config.BuildMode})
		}
		fmt.Printf("retyc %s (%s build)\n", Version, config.BuildMode)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
