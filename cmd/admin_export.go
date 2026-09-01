package cmd

import (
	"fmt"
	"os"

	"github.com/retyc/retyc-cli/internal/service"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var adminExportCmd = &cobra.Command{
	Use:   "export-all-data <output_dir>",
	Short: "Export the whole organization to a folder (reversibility)",
	Long: `Export the organization's data into a self-contained folder:
organization and quota, members with identity details, blacklisted domains,
and every dataroom (clear-text metadata, activity feed, decrypted content).

Requires the organization API key and the organization private key file. Datarooms
the organization key cannot open are recorded in the manifest and skipped.
Transfers are not exported: the admin API exposes no transfer file download.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, client, err := newAdminClient()
		if err != nil {
			return err
		}
		orgKey, err := adminIdentity(cfg)
		if err != nil {
			return err
		}

		bars := map[string]*progressbar.ProgressBar{}
		logf := func(format string, a ...any) {
			fmt.Fprintf(os.Stderr, format+"\n", a...)
		}
		result, err := service.AdminExportAll(cmd.Context(), client, orgKey,
			service.AdminExportParams{OutputDir: args[0], CLIVersion: Version},
			cliProgressFn(bars), logf)
		if err != nil {
			return adminErrHint(err)
		}

		m := result.Manifest
		fmt.Printf("Export complete: %d member(s), %d blacklisted domain(s), %d/%d dataroom(s) to %s\n",
			m.Members, m.BlacklistDomains, m.DataroomsExported, m.Datarooms, args[0])
		for _, s := range m.DataroomsSkipped {
			fmt.Fprintf(os.Stderr, "Skipped dataroom %s (%s): %s\n", s.ID, s.Title, s.Reason)
		}
		if len(m.Errors) > 0 {
			for _, e := range m.Errors {
				fmt.Fprintln(os.Stderr, "ERROR:", e)
			}

			return fmt.Errorf("export finished with %d error(s), see export.json", len(m.Errors))
		}

		return nil
	},
}

func init() {
	adminCmd.AddCommand(adminExportCmd)
}
