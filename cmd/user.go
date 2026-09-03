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

		fmt.Printf("ID:            %s\n", u.ID)
		fmt.Printf("Email:         %s\n", u.Email)
		fmt.Printf("Full name:     %s\n", fullName)
		fmt.Printf("Role:          %s\n", u.OrganizationRole)
		fmt.Printf("Plan:          %s\n", u.OrganizationPlanID)
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
	rootCmd.AddCommand(userCmd)
}
