package cmd

import (
	"fmt"
	"os"
	"path/filepath"

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

		return reportExportResult(result.Manifest, args[0])
	},
}

// reportExportResult prints the export summary and turns manifest errors into
// a non-zero exit. Under --json the contract is "result on stdout, or
// {"error":...} on stderr with an empty stdout": when the manifest records
// errors, nothing goes to stdout and the plain-text error lines are dropped
// (the full list is in export.json, which the error points at).
func reportExportResult(m service.AdminExportManifest, outputDir string) error {
	for _, s := range m.DataroomsSkipped {
		fmt.Fprintf(os.Stderr, "Skipped dataroom %s (%s): %s\n", s.ID, s.Title, s.Reason)
	}
	if len(m.Errors) > 0 {
		if !jsonOutput {
			for _, e := range m.Errors {
				fmt.Fprintln(os.Stderr, "ERROR:", e)
			}
		}

		return fmt.Errorf("export finished with %d error(s), see %s",
			len(m.Errors), filepath.Join(outputDir, "export.json"))
	}
	if jsonOutput {
		// The manifest is the same document written to export.json.
		return printJSON(m)
	}
	fmt.Printf("Export complete: %d member(s), %d blacklisted domain(s), %d/%d dataroom(s) to %s\n",
		m.Members, m.BlacklistDomains, m.DataroomsExported, m.Datarooms, outputDir)

	return nil
}

func init() {
	adminCmd.AddCommand(adminExportCmd)
}
