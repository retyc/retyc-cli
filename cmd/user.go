package cmd

import (
	"fmt"

	"github.com/retyc/retyc-cli/internal/ui"
	"github.com/spf13/cobra"
)

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "Manage user account",
}

var userInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show current user information",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		_, client, err := newAPIClient(ctx)
		if err != nil {
			return err
		}

		s := ui.NewSpinner()
		s.Start()
		u, err := client.GetMe(ctx)
		s.Stop()
		if err != nil {
			return fmt.Errorf("fetching user info: %w", err)
		}
		if jsonOutput {
			return printJSON(u)
		}

		fullName := "-"
		if u.FullName != nil && *u.FullName != "" {
			fullName = *u.FullName
		}

		orgID := "-"
		if u.MainOrganizationID != nil && *u.MainOrganizationID != "" {
			orgID = *u.MainOrganizationID
		}

		keyID := "-"
		if u.KeyID != nil && *u.KeyID != "" {
			keyID = *u.KeyID
		}

		fmt.Printf("ID:            %s\n", u.ID)
		fmt.Printf("Kind:          %s\n", u.Kind)
		fmt.Printf("Status:        %s\n", u.Status)
		fmt.Printf("Created:       %s\n", u.CreatedAt.Local().Format("2006-01-02 15:04"))
		fmt.Printf("Email:         %s\n", ui.Escape(u.Email))
		fmt.Printf("Full name:     %s\n", ui.Escape(fullName))
		fmt.Printf("Organization:  %s\n", orgID)
		fmt.Printf("Role:          %s\n", u.OrganizationRole)
		fmt.Printf("Plan:          %s\n", u.OrganizationPlanID)
		fmt.Printf("Key ID:        %s\n", keyID)
		fmt.Printf("Public key:    %s\n", u.PublicKey)

		return nil
	},
}

var userQuotaCmd = &cobra.Command{
	Use:   "quota",
	Short: "Show current user quota",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		_, client, err := newAPIClient(ctx)
		if err != nil {
			return err
		}

		s := ui.NewSpinner()
		s.Start()
		q, err := client.GetQuota(ctx)
		s.Stop()
		if err != nil {
			return fmt.Errorf("fetching quota: %w", err)
		}
		if jsonOutput {
			return printJSON(q)
		}

		readOnly := ""
		if q.IsUploadReadOnly {
			readOnly = " (read-only)"
		}

		fmt.Printf("Transfers:   %d / %s\n", q.CountShare, formatCount(q.MaxCountShare))
		fmt.Printf("Datarooms:   %d / %s\n", q.CountDataroom, formatCount(q.MaxCountDataroom))
		fmt.Printf("Storage:     %s / %s%s\n",
			ui.FormatSize(q.UsedStorage),
			ui.FormatSize(q.MaxStorage),
			readOnly,
		)

		return nil
	},
}

// formatCount formats a nullable count limit: nil means unlimited.
func formatCount(n *int) string {
	if n == nil {
		return "unlimited"
	}

	return fmt.Sprintf("%d", *n)
}

func init() {
	userCmd.AddCommand(userInfoCmd)
	userCmd.AddCommand(userQuotaCmd)
	userCmd.AddCommand(userKeyCmd)
	rootCmd.AddCommand(userCmd)
}
