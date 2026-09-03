package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/spf13/cobra"
)

var adminOrgCmd = &cobra.Command{
	Use:   "org",
	Short: "Organization settings and quota",
}

var adminOrgInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show the organization and its member quota",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx := cmd.Context()
		_, client, err := newAdminClient()
		if err != nil {
			return err
		}

		type orgRes struct {
			v   *api.AdminOrganization
			err error
		}
		type quotaRes struct {
			v   *api.AdminQuota
			err error
		}
		orgCh := make(chan orgRes, 1)
		quotaCh := make(chan quotaRes, 1)
		go func() { v, err := client.AdminGetOrganization(ctx); orgCh <- orgRes{v, err} }()
		go func() { v, err := client.AdminGetQuota(ctx); quotaCh <- quotaRes{v, err} }()
		or, qr := <-orgCh, <-quotaCh
		if or.err != nil {
			return adminErrHint(or.err)
		}
		if qr.err != nil {
			return adminErrHint(qr.err)
		}

		if jsonOutput {
			return printJSON(adminOrgInfoJSON{Organization: or.v, Quota: qr.v})
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "ID:\t%s\n", or.v.ID)
		fmt.Fprintf(w, "Name:\t%s\n", or.v.Name)
		fmt.Fprintf(w, "Kind:\t%s\n", or.v.Kind)
		fmt.Fprintf(w, "Owner:\t%s\n", qr.v.OwnerEmail)
		plan := "(none)"
		if or.v.CurrentPlanID != nil {
			plan = *or.v.CurrentPlanID
		}
		fmt.Fprintf(w, "Plan:\t%s\n", plan)
		fmt.Fprintf(w, "Members:\t%d/%d\n", qr.v.CurrentUserCount, qr.v.MaxUserCount)
		if qr.v.IsOverQuota {
			fmt.Fprintf(w, "Quota:\tOVER QUOTA\n")
		}
		fmt.Fprintf(w, "Event retention:\t%d day(s)\n", or.v.DataroomEventRetentionDays)
		fmt.Fprintf(w, "Created:\t%s\n", or.v.CreatedAt.Format("2006-01-02 15:04"))
		_ = w.Flush()

		return nil
	},
}

var adminOrgUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update organization settings (only the flags you set are sent)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		var patch api.AdminOrgPatch
		if cmd.Flags().Changed("name") {
			v, _ := cmd.Flags().GetString("name")
			patch.Name = &v
		}
		if cmd.Flags().Changed("event-retention-days") {
			v, _ := cmd.Flags().GetInt("event-retention-days")
			patch.DataroomEventRetentionDays = &v
		}
		if cmd.Flags().Changed("api-key-ip-restriction") {
			v, _ := cmd.Flags().GetBool("api-key-ip-restriction")
			patch.APIKeyIPRestrictionEnabled = &v
		}
		if patch.Name == nil && patch.DataroomEventRetentionDays == nil && patch.APIKeyIPRestrictionEnabled == nil {
			return fmt.Errorf("nothing to update: set at least one of --name, --event-retention-days, --api-key-ip-restriction")
		}

		_, client, err := newAdminClient()
		if err != nil {
			return err
		}
		org, err := client.AdminPatchOrganization(cmd.Context(), patch)
		if err != nil {
			return adminErrHint(err)
		}
		if jsonOutput {
			return printJSON(org)
		}
		fmt.Printf("Organization %q updated.\n", org.Name)

		return nil
	},
}

var adminOrgScopesCmd = &cobra.Command{
	Use:   "scopes",
	Short: "List the scopes granted to the configured API key",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		_, client, err := newAdminClient()
		if err != nil {
			return err
		}
		scopes, err := client.AdminGetScopes(cmd.Context())
		if err != nil {
			return adminErrHint(err)
		}
		if jsonOutput {
			return printJSON(struct {
				Scopes []string `json:"scopes"`
			}{nonNil(scopes)})
		}
		fmt.Println(strings.Join(scopes, "\n"))

		return nil
	},
}

func init() {
	adminOrgUpdateCmd.Flags().String("name", "", "Organization name")
	adminOrgUpdateCmd.Flags().Int("event-retention-days", 0, "Dataroom event retention in days (2-365)")
	adminOrgUpdateCmd.Flags().Bool("api-key-ip-restriction", false, "Restrict API keys to the authorized IPs")

	adminOrgCmd.AddCommand(adminOrgInfoCmd, adminOrgUpdateCmd, adminOrgScopesCmd)
	adminCmd.AddCommand(adminOrgCmd)
}
