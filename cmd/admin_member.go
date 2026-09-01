package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/spf13/cobra"
)

var adminMemberCmd = &cobra.Command{
	Use:   "member",
	Short: "Manage organization members",
}

var adminMemberLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List organization members",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		search, _ := cmd.Flags().GetString("search")
		all, _ := cmd.Flags().GetBool("all")
		_, client, err := newAdminClient()
		if err != nil {
			return err
		}

		var members []api.AdminMember
		for page := 1; ; page++ {
			p, err := client.AdminListMembers(cmd.Context(), search, all, page)
			if err != nil {
				return adminErrHint(err)
			}
			members = append(members, p.Items...)
			if page >= p.Pages {
				break
			}
		}
		if len(members) == 0 {
			fmt.Println("No members found.")

			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "USER ID\tEMAIL\tNAME\tROLE\tSTATUS\tCREATED")
		for _, m := range members {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				m.ID, m.Email, m.FullName, m.OrganizationRole, m.Status,
				m.CreatedAt.Format("2006-01-02"))
		}
		_ = w.Flush()

		return nil
	},
}

var adminMemberInfoCmd = &cobra.Command{
	Use:   "info <user_id>",
	Short: "Show a member with their identity details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, client, err := newAdminClient()
		if err != nil {
			return err
		}
		m, err := client.AdminGetMember(cmd.Context(), args[0])
		if err != nil {
			return adminErrHint(err)
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "ID:\t%s\n", m.ID)
		fmt.Fprintf(w, "Email:\t%s\n", m.Email)
		fmt.Fprintf(w, "Name:\t%s\n", m.FullName)
		fmt.Fprintf(w, "Role:\t%s\n", m.OrganizationRole)
		fmt.Fprintf(w, "Status:\t%s\n", m.Status)
		fmt.Fprintf(w, "Created:\t%s\n", m.CreatedAt.Format("2006-01-02 15:04"))
		if m.Identity != nil {
			fmt.Fprintf(w, "Membership:\t%s\n", m.Identity.MembershipType)
			fmt.Fprintf(w, "Email verified:\t%t\n", m.Identity.EmailVerified)
			fmt.Fprintf(w, "TOTP:\t%t\n", m.Identity.TOTP)
		}
		_ = w.Flush()

		return nil
	},
}

var adminMemberRoleCmd = &cobra.Command{
	Use:       "role <user_id> <owner|admin|member>",
	Short:     "Change the organization role of a member",
	Args:      cobra.ExactArgs(2),
	ValidArgs: []string{"owner", "admin", "member"},
	RunE: func(cmd *cobra.Command, args []string) error {
		_, client, err := newAdminClient()
		if err != nil {
			return err
		}
		if err := client.AdminSetMemberRole(cmd.Context(), args[0], args[1]); err != nil {
			return adminErrHint(err)
		}
		fmt.Printf("Member %s role set to %s.\n", args[0], args[1])

		return nil
	},
}

var adminMemberEnableCmd = &cobra.Command{
	Use:   "enable <user_id>",
	Short: "Enable a member",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, client, err := newAdminClient()
		if err != nil {
			return err
		}
		if err := client.AdminEnableMember(cmd.Context(), args[0]); err != nil {
			return adminErrHint(err)
		}
		fmt.Printf("Member %s enabled.\n", args[0])

		return nil
	},
}

var adminMemberDisableCmd = &cobra.Command{
	Use:   "disable <user_id>",
	Short: "Disable a member",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, client, err := newAdminClient()
		if err != nil {
			return err
		}
		if err := client.AdminDisableMember(cmd.Context(), args[0]); err != nil {
			return adminErrHint(err)
		}
		fmt.Printf("Member %s disabled.\n", args[0])

		return nil
	},
}

var adminMemberRmCmd = &cobra.Command{
	Use:   "rm <user_id>",
	Short: "Remove a member from the organization",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		yes, _ := cmd.Flags().GetBool("yes")
		_, client, err := newAdminClient()
		if err != nil {
			return err
		}

		// Fetch the member first: a MANAGED member's account is deleted with
		// the membership, the confirmation must say so.
		m, err := client.AdminGetMember(cmd.Context(), args[0])
		if err != nil {
			return adminErrHint(err)
		}
		if !yes {
			prompt := fmt.Sprintf("Remove %s (%s) from the organization?", m.Email, m.OrganizationRole)
			if m.Identity != nil && m.Identity.MembershipType == "MANAGED" {
				prompt = fmt.Sprintf(
					"Remove %s from the organization? Their membership is MANAGED: their account will be DELETED.", m.Email)
			}
			if !askConfirm(prompt) {
				fmt.Fprintln(os.Stderr, "Aborted.")

				return nil
			}
		}
		if err := client.AdminRemoveMember(cmd.Context(), args[0]); err != nil {
			return adminErrHint(err)
		}
		fmt.Printf("Member %s removed.\n", m.Email)

		return nil
	},
}

func init() {
	adminMemberLsCmd.Flags().String("search", "", "Filter members by name or email")
	adminMemberLsCmd.Flags().Bool("all", false, "Include service accounts")
	adminMemberRmCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")

	adminMemberCmd.AddCommand(
		adminMemberLsCmd, adminMemberInfoCmd, adminMemberRoleCmd,
		adminMemberEnableCmd, adminMemberDisableCmd, adminMemberRmCmd,
	)
	adminCmd.AddCommand(adminMemberCmd)
}
