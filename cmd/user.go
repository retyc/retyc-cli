package cmd

import (
	"fmt"

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

		u, err := client.GetMe(ctx)
		if err != nil {
			return fmt.Errorf("fetching user info: %w", err)
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

func init() {
	userCmd.AddCommand(userInfoCmd)
	rootCmd.AddCommand(userCmd)
}
