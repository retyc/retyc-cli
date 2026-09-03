package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/spf13/cobra"
)

var adminTransferCmd = &cobra.Command{
	Use:   "transfer",
	Short: "Administer the organization's transfers",
}

var adminTransferLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List the transfers sent by members of the organization",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		status, _ := cmd.Flags().GetString("status")
		userID, _ := cmd.Flags().GetString("user")
		_, client, err := newAdminClient()
		if err != nil {
			return err
		}
		var transfers []api.AdminTransfer
		for page := 1; ; page++ {
			p, err := client.AdminListTransfers(cmd.Context(), status, userID, page)
			if err != nil {
				return adminErrHint(err)
			}
			transfers = append(transfers, p.Items...)
			if page >= p.Pages {
				break
			}
		}
		if jsonOutput {
			return printJSON(newItemsJSON(transfers))
		}
		if len(transfers) == 0 {
			fmt.Println("No transfers found.")

			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "TRANSFER ID\tTITLE\tSTATUS\tRECIPIENTS\tCREATED")
		for _, tr := range transfers {
			fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\n",
				tr.ID, tr.Title, tr.Status, len(tr.Recipients), tr.CreatedAt.Format("2006-01-02"))
		}
		_ = w.Flush()

		return nil
	},
}

var adminTransferInfoCmd = &cobra.Command{
	Use:   "info <transfer_id>",
	Short: "Show a transfer with its recipients and key status",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, client, err := newAdminClient()
		if err != nil {
			return err
		}
		tr, err := client.AdminGetTransfer(cmd.Context(), args[0])
		if err != nil {
			return adminErrHint(err)
		}

		if jsonOutput {
			return printJSON(tr)
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "ID:\t%s\n", tr.ID)
		fmt.Fprintf(w, "Title:\t%s\n", tr.Title)
		fmt.Fprintf(w, "Status:\t%s\n", tr.Status)
		fmt.Fprintf(w, "URL:\t%s\n", tr.WebURL)
		fmt.Fprintf(w, "Passphrase access:\t%t\n", tr.UsePassphrase)
		orgKeyMaterial := "no (organization key not enabled at creation)"
		if tr.SessionPrivateKeyEnc != nil {
			orgKeyMaterial = "yes"
		}
		fmt.Fprintf(w, "Organization key material:\t%s\n", orgKeyMaterial)
		fmt.Fprintf(w, "Created:\t%s\n", tr.CreatedAt.Format("2006-01-02 15:04"))
		if tr.ExpiresAt != nil {
			fmt.Fprintf(w, "Expires:\t%s\n", tr.ExpiresAt.Format("2006-01-02 15:04"))
		}
		_ = w.Flush()

		if len(tr.Recipients) > 0 {
			fmt.Println()
			rw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(rw, "RECIPIENT\tKEY STATUS")
			for _, r := range tr.Recipients {
				label := "(external)"
				if r.Email != nil {
					label = *r.Email
				}
				keyStatus := "ok"
				switch {
				case r.IsServiceAccount:
					keyStatus = "service account"
				case r.KeyMismatch:
					keyStatus = "MISMATCH (rekey needed)"
				case !r.KeyEncrypted:
					keyStatus = "not encrypted for"
				}
				fmt.Fprintf(rw, "%s\t%s\n", label, keyStatus)
			}
			_ = rw.Flush()
		}

		return nil
	},
}

var adminTransferTrackingCmd = &cobra.Command{
	Use:   "tracking <transfer_id>",
	Short: "Show download tracking for a transfer",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, client, err := newAdminClient()
		if err != nil {
			return err
		}
		tr, err := client.AdminGetTransferTracking(cmd.Context(), args[0])
		if err != nil {
			return adminErrHint(err)
		}

		if jsonOutput {
			return printJSON(tr)
		}

		fmt.Printf("Total downloads: %d (%d identified, %d anonymous)\n",
			tr.TotalDownloadCount, tr.IdentifiedCount, tr.AnonymousCount)
		if tr.Truncated {
			fmt.Println("(event list truncated by the server)")
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "WHO\tDOWNLOADS\tLAST EVENT")
		printGroup := func(recipients []api.AdminTrackingRecipient, anonymousLabel string) {
			for _, r := range recipients {
				who := anonymousLabel
				if r.Email != nil {
					who = *r.Email
				}
				last := ""
				if len(r.Events) > 0 {
					last = r.Events[len(r.Events)-1].CreatedAt.Format("2006-01-02 15:04")
				}
				fmt.Fprintf(w, "%s\t%d\t%s\n", who, len(r.Events), last)
			}
		}
		printGroup(tr.Identified, "(identified)")
		printGroup(tr.Anonymous, "(anonymous)")
		_ = w.Flush()

		return nil
	},
}

var adminTransferDisableCmd = &cobra.Command{
	Use:   "disable <transfer_id>",
	Short: "Disable a transfer (reversible)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, client, err := newAdminClient()
		if err != nil {
			return err
		}
		if err := client.AdminDisableTransfer(cmd.Context(), args[0]); err != nil {
			return adminErrHint(err)
		}
		if jsonOutput {
			return printJSON(idStatusJSON{ID: args[0], Status: "disabled"})
		}
		fmt.Printf("Transfer %s disabled.\n", args[0])

		return nil
	},
}

var adminTransferEnableCmd = &cobra.Command{
	Use:   "enable <transfer_id>",
	Short: "Re-enable a disabled transfer",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, client, err := newAdminClient()
		if err != nil {
			return err
		}
		if err := client.AdminEnableTransfer(cmd.Context(), args[0]); err != nil {
			return adminErrHint(err)
		}
		if jsonOutput {
			return printJSON(idStatusJSON{ID: args[0], Status: "enabled"})
		}
		fmt.Printf("Transfer %s enabled.\n", args[0])

		return nil
	},
}

var adminTransferRmCmd = &cobra.Command{
	Use:   "rm <transfer_id>",
	Short: "Permanently delete the data of a transfer",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		force, _ := cmd.Flags().GetBool("force")
		yes, _ := cmd.Flags().GetBool("yes")
		if !force {
			return fmt.Errorf("this permanently removes the transfer data: re-run with --force")
		}
		_, client, err := newAdminClient()
		if err != nil {
			return err
		}
		ok, err := confirm(fmt.Sprintf("PERMANENTLY delete the data of transfer %s?", args[0]), yes)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(os.Stderr, "Aborted.")

			return nil
		}
		if err := client.AdminForceDeleteTransfer(cmd.Context(), args[0]); err != nil {
			return adminErrHint(err)
		}
		if jsonOutput {
			return printJSON(idStatusJSON{ID: args[0], Status: "deleted"})
		}
		fmt.Printf("Transfer %s permanently deleted.\n", args[0])

		return nil
	},
}

var adminTransferRekeyCmd = &cobra.Command{
	Use:   "rekey <transfer_id>",
	Short: "Re-encrypt the transfer session key for all current recipients",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, client, err := newAdminClient()
		if err != nil {
			return err
		}
		orgKey, err := adminIdentity(cfg)
		if err != nil {
			return err
		}
		result, err := service.AdminRekeyTransfer(cmd.Context(), client, orgKey, args[0])
		if err != nil {
			return adminErrHint(err)
		}
		if jsonOutput {
			return printJSON(newRekeyJSON(result))
		}
		fmt.Printf("Session key re-encrypted for %d key(s).\n", result.Reencrypted)
		for _, s := range result.Skipped {
			fmt.Fprintf(os.Stderr, "Skipped %s (no public key — passphrase access unaffected)\n", s)
		}

		return nil
	},
}

func init() {
	adminTransferLsCmd.Flags().String("status", "", "Filter by status (pending|expired|active|disabled|error|deleted)")
	adminTransferLsCmd.Flags().String("user", "", "Filter by sender user ID")
	adminTransferRmCmd.Flags().Bool("force", false, "Confirm permanent data removal")
	adminTransferRmCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")

	adminTransferCmd.AddCommand(
		adminTransferLsCmd, adminTransferInfoCmd, adminTransferTrackingCmd,
		adminTransferDisableCmd, adminTransferEnableCmd, adminTransferRmCmd,
		adminTransferRekeyCmd,
	)
	adminCmd.AddCommand(adminTransferCmd)
}
