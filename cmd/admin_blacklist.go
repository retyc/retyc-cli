package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/spf13/cobra"
)

var adminBlacklistCmd = &cobra.Command{
	Use:   "blacklist",
	Short: "Manage the blacklisted email domains",
}

var adminBlacklistLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List blacklisted email domains",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		_, client, err := newAdminClient()
		if err != nil {
			return err
		}
		var domains []api.AdminDomain
		for page := 1; ; page++ {
			p, err := client.AdminListBlacklistDomains(cmd.Context(), page)
			if err != nil {
				return adminErrHint(err)
			}
			domains = append(domains, p.Items...)
			if page >= p.Pages {
				break
			}
		}
		if len(domains) == 0 {
			fmt.Println("No blacklisted domains.")

			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "DOMAIN ID\tDOMAIN\tCREATED")
		for _, d := range domains {
			fmt.Fprintf(w, "%s\t%s\t%s\n", d.ID, d.DomainName, d.CreatedAt.Format("2006-01-02"))
		}
		_ = w.Flush()

		return nil
	},
}

var adminBlacklistAddCmd = &cobra.Command{
	Use:   "add <domain>",
	Short: "Add an email domain to the blacklist",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, client, err := newAdminClient()
		if err != nil {
			return err
		}
		d, err := client.AdminAddBlacklistDomain(cmd.Context(), args[0])
		if err != nil {
			return adminErrHint(err)
		}
		fmt.Printf("Domain %s blacklisted (id %s).\n", d.DomainName, d.ID)

		return nil
	},
}

var adminBlacklistRmCmd = &cobra.Command{
	Use:   "rm <domain_id>",
	Short: "Remove a domain from the blacklist",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, client, err := newAdminClient()
		if err != nil {
			return err
		}
		if err := client.AdminRemoveBlacklistDomain(cmd.Context(), args[0]); err != nil {
			return adminErrHint(err)
		}
		fmt.Printf("Domain %s removed from the blacklist.\n", args[0])

		return nil
	},
}

func init() {
	adminBlacklistCmd.AddCommand(adminBlacklistLsCmd, adminBlacklistAddCmd, adminBlacklistRmCmd)
	adminCmd.AddCommand(adminBlacklistCmd)
}
