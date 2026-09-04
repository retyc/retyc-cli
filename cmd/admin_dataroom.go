package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/ui"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var adminDataroomCmd = &cobra.Command{
	Use:   "dataroom",
	Short: "Administer the organization's datarooms",
}

var adminDataroomLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List the organization's datarooms",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		userID, _ := cmd.Flags().GetString("user")
		_, client, err := newAdminClient()
		if err != nil {
			return err
		}
		var rooms []api.AdminDataroom
		for page := 1; ; page++ {
			p, err := client.AdminListDatarooms(cmd.Context(), userID, page)
			if err != nil {
				return adminErrHint(err)
			}
			rooms = append(rooms, p.Items...)
			if page >= p.Pages {
				break
			}
		}
		if jsonOutput {
			return printJSON(newItemsJSON(rooms))
		}
		if len(rooms) == 0 {
			fmt.Println("No datarooms found.")

			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "DATAROOM ID\tTITLE\tOWNER\tSTATUS\tCREATED")
		for _, dr := range rooms {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				dr.ID, dr.Title, dr.OwnerEmail, dr.Status, dr.CreatedAt.Format("2006-01-02"))
		}
		_ = w.Flush()

		return nil
	},
}

var adminDataroomInfoCmd = &cobra.Command{
	Use:   "info <dataroom_id>",
	Short: "Show a dataroom, its users and their key status",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		cfg, client, err := newAdminClient()
		if err != nil {
			return err
		}

		type drRes struct {
			v   *api.AdminDataroom
			err error
		}
		type usersRes struct {
			v   []api.AdminDataroomUser
			err error
		}
		drCh := make(chan drRes, 1)
		usersCh := make(chan usersRes, 1)
		go func() { v, err := client.AdminGetDataroom(ctx, args[0]); drCh <- drRes{v, err} }()
		go func() { v, err := client.AdminListDataroomUsers(ctx, args[0]); usersCh <- usersRes{v, err} }()
		dr, ur := <-drCh, <-usersCh
		if dr.err != nil {
			return adminErrHint(dr.err)
		}
		if ur.err != nil {
			return adminErrHint(ur.err)
		}

		// The organization key opens the dataroom only if it was rekeyed for the org.
		orgKeyAccess := "unknown (no organization key file configured)"
		if cfg.Admin.PrivateKeyFile != "" {
			orgKey, idErr := adminIdentity(cfg)
			switch {
			case idErr != nil:
				orgKeyAccess = fmt.Sprintf("unknown (cannot load organization key: %v)", idErr)
			default:
				if _, decErr := crypto.DecryptToString(dr.v.SessionPrivateKeyEnc, orgKey); decErr == nil {
					orgKeyAccess = "yes"
				} else {
					orgKeyAccess = "no (never rekeyed for the organization)"
				}
			}
		}

		if jsonOutput {
			return printJSON(adminDataroomInfoJSON{
				Dataroom: dr.v, Users: nonNil(ur.v), OrganizationKeyAccess: orgKeyAccess,
			})
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "ID:\t%s\n", dr.v.ID)
		fmt.Fprintf(w, "Title:\t%s\n", dr.v.Title)
		fmt.Fprintf(w, "Owner:\t%s\n", dr.v.OwnerEmail)
		fmt.Fprintf(w, "Status:\t%s\n", dr.v.Status)
		fmt.Fprintf(w, "Created:\t%s\n", dr.v.CreatedAt.Format("2006-01-02 15:04"))
		fmt.Fprintf(w, "Organization key access:\t%s\n", orgKeyAccess)
		_ = w.Flush()

		fmt.Println()
		uw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(uw, "USER ID\tEMAIL\tROLE\tKEY STATUS")
		for _, u := range ur.v {
			keyStatus := "ok"
			switch {
			case u.IsServiceAccount:
				keyStatus = "service account"
			case u.KeyMismatch:
				keyStatus = "MISMATCH (rekey needed)"
			case u.PublicKey == nil:
				keyStatus = "no key"
			}
			fmt.Fprintf(uw, "%s\t%s\t%s\t%s\n", u.UserID, u.Email, u.Role, keyStatus)
		}
		_ = uw.Flush()

		return nil
	},
}

var adminDataroomActivityCmd = &cobra.Command{
	Use:   "activity <dataroom_id>",
	Short: "Show the activity feed of a dataroom",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		cfg, client, err := newAdminClient()
		if err != nil {
			return err
		}
		var msgs []api.AdminDataroomMessage
		for page := 1; ; page++ {
			p, err := client.AdminListDataroomMessages(ctx, args[0], page)
			if err != nil {
				return adminErrHint(err)
			}
			msgs = append(msgs, p.Items...)
			if page >= p.Pages {
				break
			}
		}
		if len(msgs) == 0 && !jsonOutput {
			fmt.Println("No activity.")

			return nil
		}

		// Best-effort: decrypt chat messages when the organization key is configured
		// and can open this dataroom's session key. Any failure here must not
		// break the activity feed — it just falls back to "[encrypted]".
		var sess *service.DataroomSession
		if cfg.Admin.PrivateKeyFile != "" {
			if orgKey, idErr := adminIdentity(cfg); idErr == nil {
				sess, _ = service.ResolveAdminDataroomSession(ctx, client, orgKey, args[0])
			}
		}

		if jsonOutput {
			// Same shape as the export's messages/N.json: raw message + decrypted
			// chat content when the organization key opens the dataroom.
			items := make([]service.AdminExportMessage, 0, len(msgs))
			for _, m := range msgs {
				entry := service.AdminExportMessage{AdminDataroomMessage: m}
				if m.MessageType == "chat" && sess != nil && m.ContentEnc != nil {
					if content, decErr := crypto.DecryptToString(*m.ContentEnc, sess.Identity); decErr == nil {
						entry.Content = &content
					}
				}
				items = append(items, entry)
			}

			return printJSON(newItemsJSON(items))
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "DATE\tUSER\tEVENT")
		for _, m := range msgs {
			user := ""
			if m.UserEmail != nil {
				user = *m.UserEmail
			}
			event := m.MessageType
			if m.EventType != nil {
				event = *m.EventType
			} else if m.MessageType == "chat" {
				event = "chat message [encrypted]"
				if sess != nil && m.ContentEnc != nil {
					if content, decErr := crypto.DecryptToString(*m.ContentEnc, sess.Identity); decErr == nil {
						event = "chat: " + content
					}
				}
			}
			fmt.Fprintf(w, "%s\t%s\t%s\n", m.CreatedAt.Format("2006-01-02 15:04"), user, event)
		}
		_ = w.Flush()

		return nil
	},
}

var adminDataroomNodesCmd = &cobra.Command{
	Use:   "nodes <dataroom_id>",
	Short: "List every node of a dataroom with decrypted names",
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

		s := ui.NewSpinner()
		s.Start()
		nodes, err := service.AdminListNodes(cmd.Context(), client, orgKey, args[0])
		s.Stop()
		if err != nil {
			return adminErrHint(err)
		}
		if jsonOutput {
			return printJSON(newItemsJSON(newAdminNodesJSON(nodes)))
		}
		if len(nodes) == 0 {
			fmt.Println("Empty dataroom.")

			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "TYPE\tPATH\tSIZE\tVERSION")
		for _, n := range nodes {
			if n.IsFolder {
				fmt.Fprintf(w, "DIR\t%s\t\t\n", n.Path)
			} else {
				fmt.Fprintf(w, "FILE\t%s\t%s\tv%d\n", n.Path, ui.FormatSize(n.Size), n.VersionNumber)
			}
		}
		_ = w.Flush()

		return nil
	},
}

var adminDataroomDownloadCmd = &cobra.Command{
	Use:   "download <dataroom_id> [glob]",
	Short: "Download and decrypt dataroom files with the organization key",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		outputDir, _ := cmd.Flags().GetString("output")
		pattern := ""
		if len(args) == 2 {
			pattern = args[1]
		}
		cfg, client, err := newAdminClient()
		if err != nil {
			return err
		}
		orgKey, err := adminIdentity(cfg)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(outputDir, 0o750); err != nil {
			return fmt.Errorf("creating output directory: %w", err)
		}

		bars := map[string]*progressbar.ProgressBar{}
		result, err := service.AdminDownloadNodes(
			cmd.Context(), client, orgKey, args[0], pattern, outputDir, cliProgressFn(bars))
		if err != nil {
			return adminErrHint(err)
		}
		for _, p := range result.SkippedFolders {
			fmt.Fprintf(os.Stderr, "Skipping folder %s (admin download does not recurse)\n", p)
		}
		// The dataroom's folder structure is recreated under outputDir, so
		// result.Downloaded holds paths relative to outputDir, not bare filenames.
		if jsonOutput {
			return printJSON(adminDownloadJSON{
				OutputDir:      outputDir,
				Downloaded:     nonNil(result.Downloaded),
				SkippedFolders: nonNil(result.SkippedFolders),
			})
		}
		fmt.Printf("Downloaded %d file(s) to %s\n", len(result.Downloaded), outputDir)

		return nil
	},
}

var adminDataroomChownCmd = &cobra.Command{
	Use:   "chown <dataroom_id> <user_id>",
	Short: "Transfer the dataroom ownership to an admin member",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, client, err := newAdminClient()
		if err != nil {
			return err
		}
		if err := client.AdminTransferDataroomOwnership(cmd.Context(), args[0], args[1]); err != nil {
			return adminErrHint(err)
		}
		if jsonOutput {
			return printJSON(struct {
				DataroomID string `json:"dataroom_id"`
				OwnerID    string `json:"owner_id"`
			}{args[0], args[1]})
		}
		fmt.Printf("Dataroom %s ownership transferred to %s.\n", args[0], args[1])

		return nil
	},
}

var adminDataroomUserCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage dataroom users",
}

var adminDataroomUserRmCmd = &cobra.Command{
	Use:   "rm <dataroom_id> <user_id>",
	Short: "Remove a user from a dataroom and rekey it",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		yes, _ := cmd.Flags().GetBool("yes")
		cfg, client, err := newAdminClient()
		if err != nil {
			return err
		}
		orgKey, err := adminIdentity(cfg)
		if err != nil {
			return err
		}
		ok, err := confirm(fmt.Sprintf("Remove user %s from dataroom %s and rekey?", args[1], args[0]), yes)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(os.Stderr, "Aborted.")

			return nil
		}
		// The service checks the organization key can open the dataroom before
		// the (irreversible) removal, then rekeys so the removal takes effect
		// cryptographically.
		result, err := service.AdminRemoveDataroomUser(cmd.Context(), client, orgKey, args[0], args[1])
		if err != nil {
			return adminErrHint(err)
		}
		if jsonOutput {
			return printJSON(struct {
				DataroomID string    `json:"dataroom_id"`
				UserID     string    `json:"user_id"`
				Status     string    `json:"status"`
				Rekey      rekeyJSON `json:"rekey"`
			}{args[0], args[1], "removed", newRekeyJSON(result)})
		}
		fmt.Printf("User removed; session key re-encrypted for %d key(s).\n", result.Reencrypted)

		return nil
	},
}

var adminDataroomRekeyCmd = &cobra.Command{
	Use:   "rekey <dataroom_id>",
	Short: "Re-encrypt the dataroom session key for all current members",
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
		result, err := service.AdminRekeyDataroom(cmd.Context(), client, orgKey, args[0])
		if err != nil {
			return adminErrHint(err)
		}
		if jsonOutput {
			return printJSON(newRekeyJSON(result))
		}
		fmt.Printf("Session key re-encrypted for %d key(s).\n", result.Reencrypted)
		for _, s := range result.Skipped {
			fmt.Fprintf(os.Stderr, "Skipped %s (no public key)\n", s)
		}

		return nil
	},
}

var adminDataroomRmCmd = &cobra.Command{
	Use:   "rm <dataroom_id>",
	Short: "Delete a dataroom",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		yes, _ := cmd.Flags().GetBool("yes")
		_, client, err := newAdminClient()
		if err != nil {
			return err
		}
		ok, err := confirm(fmt.Sprintf("Delete dataroom %s and all its contents?", args[0]), yes)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(os.Stderr, "Aborted.")

			return nil
		}
		if err := client.AdminDeleteDataroom(cmd.Context(), args[0]); err != nil {
			return adminErrHint(err)
		}
		if jsonOutput {
			return printJSON(idStatusJSON{ID: args[0], Status: "deleted"})
		}
		fmt.Printf("Dataroom %s deleted.\n", args[0])

		return nil
	},
}

func init() {
	adminDataroomLsCmd.Flags().String("user", "", "Filter by owner user ID")
	adminDataroomDownloadCmd.Flags().StringP("output", "o", ".", "Output directory")
	adminDataroomUserRmCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")
	adminDataroomRmCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")

	adminDataroomUserCmd.AddCommand(adminDataroomUserRmCmd)
	adminDataroomCmd.AddCommand(
		adminDataroomLsCmd, adminDataroomInfoCmd, adminDataroomActivityCmd,
		adminDataroomNodesCmd, adminDataroomDownloadCmd, adminDataroomChownCmd,
		adminDataroomUserCmd, adminDataroomRekeyCmd, adminDataroomRmCmd,
	)
	adminCmd.AddCommand(adminDataroomCmd)
}
