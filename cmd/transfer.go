package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/spf13/cobra"
)

var transferCmd = &cobra.Command{
	Use:   "transfer",
	Short: "Manage transfers",
}

var transferLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List transfers",
	RunE: func(cmd *cobra.Command, args []string) error {
		sent, _ := cmd.Flags().GetBool("sent")
		received, _ := cmd.Flags().GetBool("received")

		if sent && received {
			return fmt.Errorf("--sent and --received are mutually exclusive")
		}

		listType := "sent"
		if received {
			listType = "received"
		}

		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		ctx := context.Background()
		tok, err := auth.GetValidToken(ctx, cfg.OIDC, newHTTPClient(insecure))
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrNoToken), errors.Is(err, auth.ErrNoRefreshToken):
				return fmt.Errorf("not authenticated, run `retyc auth login`")
			default:
				return fmt.Errorf("authentication failed: %w", err)
			}
		}

		client := api.New(cfg.API.BaseURL, tok, insecure)
		result, err := client.ListTransfers(ctx, listType, 1)
		if err != nil {
			return fmt.Errorf("listing transfers: %w", err)
		}

		if len(result.Items) == 0 {
			fmt.Printf("No %s transfers found.\n", listType)
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tSTATUS\tTITLE\tCREATED")
		for _, t := range result.Items {
			title := ""
			if t.Title != nil {
				title = *t.Title
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				t.ID,
				t.Status,
				title,
				t.CreatedAt.Format("2006-01-02 15:04"),
			)
		}
		w.Flush()

		if result.Pages > 1 {
			fmt.Printf("\nPage %d/%d · %d transfert(s) au total\n", result.Page, result.Pages, result.Total)
		}

		return nil
	},
}

func init() {
	transferLsCmd.Flags().Bool("sent", false, "List sent transfers (default)")
	transferLsCmd.Flags().Bool("received", false, "List received transfers")

	transferCmd.AddCommand(transferLsCmd)
	rootCmd.AddCommand(transferCmd)
}
