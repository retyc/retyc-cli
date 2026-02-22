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
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"golang.org/x/term"
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
		tok, err := mustGetToken(ctx, cfg)
		if err != nil {
			return err
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

var transferInfoCmd = &cobra.Command{
	Use:   "info <share_id>",
	Short: "Show details of a transfer (decrypts metadata)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		shareID := args[0]

		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		ctx := context.Background()
		tok, err := mustGetToken(ctx, cfg)
		if err != nil {
			return err
		}

		client := api.New(cfg.API.BaseURL, tok, insecure)

		// Fetch transfer details and user key in parallel.
		type detailsResult struct {
			v   *api.TransferDetails
			err error
		}
		type keyResult struct {
			v   *api.UserKey
			err error
		}
		detailsCh := make(chan detailsResult, 1)
		keyCh := make(chan keyResult, 1)

		go func() {
			v, err := client.GetTransferDetails(ctx, shareID)
			detailsCh <- detailsResult{v, err}
		}()
		go func() {
			v, err := client.GetActiveKey(ctx)
			keyCh <- keyResult{v, err}
		}()

		dr := <-detailsCh
		if dr.err != nil {
			return fmt.Errorf("fetching transfer: %w", dr.err)
		}
		details := dr.v

		kr := <-keyCh
		if kr.err != nil {
			return fmt.Errorf("fetching encryption key: %w", kr.err)
		}
		userKey := kr.v

		// Display basic metadata (no crypto required).
		fmt.Printf("ID:      %s\n", ptrOr(details.ID, "—"))
		fmt.Printf("Title:   %s\n", ptrOr(details.Title, "—"))
		fmt.Printf("Status:  %s\n", details.Status)
		if details.CreatedAt != nil {
			fmt.Printf("Created: %s\n", details.CreatedAt.Format("2006-01-02 15:04"))
		}
		if details.ExpiresAt != nil {
			fmt.Printf("Expires: %s\n", details.ExpiresAt.Format("2006-01-02 15:04"))
		}

		if len(details.Recipients) > 0 {
			fmt.Println("\nRecipients:")
			for _, r := range details.Recipients {
				email := ptrOr(r.Email, "(external)")
				status := "password only"
				if r.KeyEncrypted {
					status = "user key encrypted"
				}
				fmt.Printf("  %s  [%s]\n", email, status)
			}
		}

		// Crypto section: requires session_private_key_enc.
		if details.SessionPrivateKeyEnc == nil {
			fmt.Println("\n(Transfer not yet completed — no encrypted content available.)")
			return nil
		}
		if userKey == nil {
			return fmt.Errorf("no active encryption key found — set up your key in the web interface first")
		}

		// Prompt passphrase without echo, then erase the prompt line.
		fmt.Fprint(os.Stderr, "Passphrase: ")
		passphraseBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprint(os.Stderr, "\r\033[2K")
		if err != nil {
			return fmt.Errorf("reading passphrase: %w", err)
		}

		// Decrypt user's AGE private key (scrypt).
		identityStr, err := crypto.DecryptToStringWithPassphrase(userKey.PrivateKeyEnc, string(passphraseBytes))
		if err != nil {
			return fmt.Errorf("wrong passphrase")
		}
		identity, err := crypto.ParseIdentity(identityStr)
		if err != nil {
			return fmt.Errorf("parsing AGE identity: %w", err)
		}

		// Decrypt session private key (X25519).
		sessionKeyStr, err := crypto.DecryptToString(*details.SessionPrivateKeyEnc, identity)
		if err != nil {
			return fmt.Errorf("decrypting session key (key mismatch?): %w", err)
		}
		sessionIdentity, err := crypto.ParseIdentity(sessionKeyStr)
		if err != nil {
			return fmt.Errorf("parsing session AGE identity: %w", err)
		}

		// Decrypt message if present.
		if details.MessageEnc != nil {
			msg, err := crypto.DecryptToString(*details.MessageEnc, sessionIdentity)
			if err == nil && msg != "" {
				fmt.Printf("\nMessage:\n  %s\n", msg)
			}
		}

		// Fetch and display files.
		filePage, err := client.ListFiles(ctx, shareID, 1)
		if err != nil {
			return fmt.Errorf("fetching files: %w", err)
		}

		if filePage.Total == 0 {
			fmt.Println("\nNo files.")
			return nil
		}

		fmt.Printf("\nFiles (%d):\n", filePage.Total)
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  NAME\tSIZE")
		for _, f := range filePage.Items {
			name, err := crypto.DecryptToString(f.NameEnc, sessionIdentity)
			if err != nil {
				name = "(encrypted)"
			}
			fmt.Fprintf(w, "  %s\t%s\n", name, formatSize(f.OriginalSize))
		}
		w.Flush()

		if filePage.Pages > 1 {
			fmt.Printf("  … and more (page 1/%d, %d files total)\n", filePage.Pages, filePage.Total)
		}

		return nil
	},
}

// mustGetToken retrieves a valid OAuth2 token, returning a user-friendly error
// if authentication is missing or expired.
func mustGetToken(ctx context.Context, cfg *config.Config) (*oauth2.Token, error) {
	tok, err := auth.GetValidToken(ctx, cfg.OIDC, newHTTPClient(insecure))
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrNoToken), errors.Is(err, auth.ErrNoRefreshToken):
			return nil, fmt.Errorf("not authenticated, run `retyc auth login`")
		default:
			return nil, fmt.Errorf("authentication failed: %w", err)
		}
	}
	return tok, nil
}

// ptrOr returns the dereferenced value of s, or fallback if s is nil.
func ptrOr(s *string, fallback string) string {
	if s == nil {
		return fallback
	}
	return *s
}

// formatSize formats a byte count as a human-readable string (e.g. "1.4 MiB").
func formatSize(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(1024), 0
	for n := bytes / 1024; n >= 1024; n /= 1024 {
		div *= 1024
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func init() {
	transferLsCmd.Flags().Bool("sent", false, "List sent transfers (default)")
	transferLsCmd.Flags().Bool("received", false, "List received transfers")

	transferCmd.AddCommand(transferLsCmd)
	transferCmd.AddCommand(transferInfoCmd)
	rootCmd.AddCommand(transferCmd)
}
