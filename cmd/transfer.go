package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/service"
	"github.com/retyc/retyc-cli/internal/ui"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
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

		ctx := cmd.Context()
		_, client, err := newAPIClient(ctx)
		if err != nil {
			return err
		}

		s := ui.NewSpinner()
		s.Start()
		result, err := service.ListTransfers(ctx, client, listType, 1)
		s.Stop()
		if err != nil {
			return err
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
		_ = w.Flush()

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

		ctx := cmd.Context()
		cfg, client, err := newAPIClient(ctx)
		if err != nil {
			return err
		}

		s := ui.NewSpinner()
		s.Start()
		info, err := service.GetTransferInfo(ctx, cfg, client, shareID, spinnerReader(s))
		s.Stop()
		if err != nil {
			return err
		}

		d := info.Details
		fmt.Printf("ID:      %s\n", ptrOr(d.ID, "-"))
		fmt.Printf("Title:   %s\n", ptrOr(d.Title, "-"))
		fmt.Printf("Status:  %s\n", d.Status)
		if d.CreatedAt != nil {
			fmt.Printf("Created: %s\n", d.CreatedAt.Format("2006-01-02 15:04"))
		}
		if d.ExpiresAt != nil {
			fmt.Printf("Expires: %s\n", d.ExpiresAt.Format("2006-01-02 15:04"))
		}
		if d.WebURL != "" {
			fmt.Printf("URL:     %s\n", d.WebURL)
		}

		if len(d.Recipients) > 0 {
			fmt.Println("\nRecipients:")
			for _, r := range d.Recipients {
				email := ptrOr(r.Email, "(external)")
				status := "password only"
				if r.KeyEncrypted {
					status = "user key encrypted"
				}
				fmt.Printf("  %s  [%s]\n", email, status)
			}
		}

		if d.SessionPrivateKeyEnc == nil {
			fmt.Println("\n(Transfer not yet completed - no encrypted content available.)")

			return nil
		}

		if info.Message != "" {
			printBoxedMessage(info.Message)
		}

		if len(info.Files) == 0 {
			fmt.Println("\nNo files.")

			return nil
		}

		fmt.Printf("\nFiles (%d):\n", len(info.Files))
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "  NAME\tSIZE")
		for _, f := range info.Files {
			fmt.Fprintf(w, "  %s\t%s\n", f.Name, ui.FormatSize(f.Size))
		}
		_ = w.Flush()

		return nil
	},
}

// promptTransferPassphrase prompts the user to enter and confirm a new transfer passphrase.
func promptTransferPassphrase(minLen int) (string, error) {
	for {
		fmt.Fprint(os.Stderr, "Transfer passphrase: ")
		pb, err := term.ReadPassword(int(os.Stdin.Fd())) //nolint:gosec // G115
		fmt.Fprint(os.Stderr, "\r\033[2K")
		if err != nil {
			return "", fmt.Errorf("reading passphrase: %w", err)
		}
		if len(pb) < minLen {
			fmt.Fprintf(os.Stderr, "Passphrase must be at least %d characters.\n", minLen)

			continue
		}
		fmt.Fprint(os.Stderr, "Confirm passphrase: ")
		pb2, err := term.ReadPassword(int(os.Stdin.Fd())) //nolint:gosec // G115
		fmt.Fprint(os.Stderr, "\r\033[2K")
		if err != nil {
			return "", fmt.Errorf("reading passphrase confirmation: %w", err)
		}
		if string(pb) != string(pb2) {
			fmt.Fprintln(os.Stderr, "Passphrases do not match.")

			continue
		}

		return string(pb), nil
	}
}

// fetchTransferDetailsAndKey fetches transfer details and the active user key concurrently.
// Used as a CLI pre-flight check before prompting for a transfer passphrase.
func fetchTransferDetailsAndKey(
	ctx context.Context, client *api.Client, shareID string,
) (*api.TransferDetails, *api.UserKey, error) {
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
	go func() { v, err := client.GetTransferDetails(ctx, shareID); detailsCh <- detailsResult{v, err} }()
	go func() { v, err := client.GetActiveKey(ctx); keyCh <- keyResult{v, err} }()

	dr := <-detailsCh
	if dr.err != nil {
		return nil, nil, fmt.Errorf("fetching transfer: %w", dr.err)
	}
	kr := <-keyCh
	if kr.err != nil {
		return nil, nil, fmt.Errorf("fetching encryption key: %w", kr.err)
	}

	return dr.v, kr.v, nil
}

// confirmFileList prints a summary of files and prompts the user to proceed.
func confirmFileList(names []string, sizes []int64, totalSize int64, extras []string) bool {
	const lineWidth = 44
	fmt.Fprintln(os.Stderr)
	for i, name := range names {
		runes := []rune(name)
		if len(runes) > lineWidth-10 {
			name = string(runes[:lineWidth-13]) + "…"
		}
		fmt.Fprintf(os.Stderr, "  %-*s  %s\n", lineWidth-10, name, ui.FormatSize(sizes[i]))
	}
	fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat("─", lineWidth))
	noun := "file"
	if len(names) > 1 {
		noun = "files"
	}
	fmt.Fprintf(os.Stderr, "  %-*s  %s\n", lineWidth-10, fmt.Sprintf("%d %s", len(names), noun), ui.FormatSize(totalSize))
	fmt.Fprintln(os.Stderr)
	for _, extra := range extras {
		fmt.Fprintln(os.Stderr, extra)
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprint(os.Stderr, "Proceed? [y/N] ")
	answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	fmt.Fprintln(os.Stderr)

	return strings.ToLower(strings.TrimSpace(answer)) == "y"
}

// printBoxedMessage prints a decrypted message with a left vertical bar.
func printBoxedMessage(msg string) {
	fmt.Println("\nMessage:")
	scanner := bufio.NewScanner(strings.NewReader(msg))
	for scanner.Scan() {
		fmt.Printf(" │ %s\n", scanner.Text())
	}
	fmt.Println()
}

// ptrOr returns the dereferenced value of s, or fallback if s is nil.
func ptrOr(s *string, fallback string) string {
	if s == nil {
		return fallback
	}

	return *s
}

var transferCreateCmd = &cobra.Command{
	Use:   "create [flags] file...",
	Short: "Create and upload a new transfer",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		title, _ := cmd.Flags().GetString("title")
		expire, _ := cmd.Flags().GetInt("expire")
		message, _ := cmd.Flags().GetString("message")
		passphrase, _ := cmd.Flags().GetString("passphrase")
		yes, _ := cmd.Flags().GetBool("yes")
		toEmails, _ := cmd.Flags().GetStringArray("to")
		genPassphrase, _ := cmd.Flags().GetBool("generate-passphrase")
		passphraseExplicit := cmd.Flags().Changed("passphrase")

		if passphraseExplicit && len(passphrase) < minPassphraseLen {
			return fmt.Errorf("transfer passphrase must be at least %d characters", minPassphraseLen)
		}

		type fileEntry struct {
			path string
			name string
			size int64
		}
		entries := make([]fileEntry, 0, len(args))
		var totalSize int64
		for _, p := range args {
			info, err := os.Stat(p)
			if err != nil {
				return err
			}
			if info.IsDir() {
				return fmt.Errorf("%s: directories are not supported", p)
			}
			entries = append(entries, fileEntry{p, info.Name(), info.Size()})
			totalSize += info.Size()
		}

		if !yes {
			names := make([]string, len(entries))
			sizes := make([]int64, len(entries))
			for i, e := range entries {
				names[i] = e.name
				sizes[i] = e.size
			}
			var extras []string
			if title != "" {
				extras = append(extras, fmt.Sprintf("  Title:    %s", title))
			}
			if len(toEmails) > 0 {
				extras = append(extras, fmt.Sprintf("  To:       %s", strings.Join(toEmails, ", ")))
			}
			extras = append(extras, fmt.Sprintf("  Expires:  %s", formatExpiry(expire)))
			if !confirmFileList(names, sizes, totalSize, extras) {
				fmt.Fprintln(os.Stderr, "Aborted.")

				return nil
			}
		}

		// Prompt for the transfer passphrase before any API call so a Ctrl+C during
		// entry leaves nothing on the server.
		if !genPassphrase && passphrase == "" && len(toEmails) == 0 {
			p, err := promptTransferPassphrase(minPassphraseLen)
			if err != nil {
				return err
			}
			passphrase = p
		}

		ctx := cmd.Context()
		cfg, client, err := newAPIClient(ctx)
		if err != nil {
			return err
		}

		uploadCtx, cancelUpload := context.WithCancel(ctx)
		defer cancelUpload()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sigCh)

		go func() {
			select {
			case <-sigCh:
				fmt.Fprintln(os.Stderr, "\nInterrupted.")
				cancelUpload()
			case <-uploadCtx.Done():
			}
		}()

		bars := make(map[string]*progressbar.ProgressBar)
		filePaths := make([]string, len(entries))
		for i, e := range entries {
			filePaths[i] = e.path
		}

		result, err := service.SendTransfer(uploadCtx, cfg, client, service.SendTransferParams{
			FilePaths:          filePaths,
			Title:              title,
			Message:            message,
			Passphrase:         passphrase,
			GeneratePassphrase: genPassphrase,
			ToEmails:           toEmails,
			ExpireSecs:         expire,
		}, readKeyPassphrase, cliProgressFn(bars))
		if err != nil {
			return err
		}

		fmt.Printf("Transfer %s ready.\n", result.ID)
		if result.WebURL != "" {
			fmt.Printf("URL: %s\n", result.WebURL)
		}
		if result.Passphrase != "" && genPassphrase {
			fmt.Printf("Passphrase: %s\n", result.Passphrase)
		}

		return nil
	},
}

// formatExpiry returns a human-readable description of an expiry duration in seconds.
func formatExpiry(seconds int) string {
	if seconds == 0 {
		return "never"
	}
	if seconds < 3600 {
		return fmt.Sprintf("in %dm", seconds/60)
	}
	if seconds < 86400 {
		return fmt.Sprintf("in %dh", seconds/3600)
	}

	return fmt.Sprintf("in %dd", seconds/86400)
}

var transferDisableCmd = &cobra.Command{
	Use:   "disable <transfer_id>",
	Short: "Disable a transfer",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		_, client, err := newAPIClient(ctx)
		if err != nil {
			return err
		}

		s := ui.NewSpinner()
		s.Start()
		err = service.DisableTransfer(ctx, client, args[0])
		s.Stop()
		if err != nil {
			return err
		}

		fmt.Printf("Transfer %s disabled.\n", args[0])

		return nil
	},
}

var transferEnableCmd = &cobra.Command{
	Use:   "enable <transfer_id>",
	Short: "Re-enable a disabled transfer",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		_, client, err := newAPIClient(ctx)
		if err != nil {
			return err
		}

		s := ui.NewSpinner()
		s.Start()
		err = service.EnableTransfer(ctx, client, args[0])
		s.Stop()
		if err != nil {
			return err
		}

		fmt.Printf("Transfer %s enabled.\n", args[0])

		return nil
	},
}

var transferDownloadCmd = &cobra.Command{
	Use:   "download <transfer_id>",
	Short: "Download and decrypt a transfer",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		shareID := args[0]
		outputDir, _ := cmd.Flags().GetString("output")
		yes, _ := cmd.Flags().GetBool("yes")

		ctx := cmd.Context()
		cfg, client, err := newAPIClient(ctx)
		if err != nil {
			return err
		}

		s := ui.NewSpinner()
		s.Start()
		details, userKey, err := fetchTransferDetailsAndKey(ctx, client, shareID)
		s.Stop()
		if err != nil {
			return err
		}

		// Prompt for the transfer passphrase when the user key path is unavailable.
		var transferPassphrase string
		if userKey == nil || details.SessionPrivateKeyEnc == nil {
			if details.EphemeralPrivateKeyEnc == nil || details.SessionPrivateKeyEncForPassphrase == nil {
				return fmt.Errorf("no decryption path available - neither user key nor passphrase data found")
			}
			fmt.Fprint(os.Stderr, "Transfer passphrase: ")
			pb, err := term.ReadPassword(int(os.Stdin.Fd())) //nolint:gosec // G115
			fmt.Fprint(os.Stderr, "\r\033[2K")
			if err != nil {
				return fmt.Errorf("reading passphrase: %w", err)
			}
			transferPassphrase = string(pb)
		}

		if !yes {
			// Fetch file list for the confirmation summary.
			s.Start()
			filePage, err := client.ListFiles(ctx, shareID, 1)
			s.Stop()
			if err != nil {
				return fmt.Errorf("fetching files: %w", err)
			}
			names := make([]string, len(filePage.Items))
			sizes := make([]int64, len(filePage.Items))
			var totalSize int64
			for i, f := range filePage.Items {
				names[i] = f.ID // names are encrypted; use ID as placeholder
				sizes[i] = f.OriginalSize
				totalSize += f.OriginalSize
			}
			dest := outputDir
			if dest == "" {
				dest = "transfer-<random>"
			}
			if !confirmFileList(names, sizes, totalSize, []string{fmt.Sprintf("  Destination:  %s/", dest)}) {
				fmt.Fprintln(os.Stderr, "Aborted.")

				return nil
			}
		}

		bars := make(map[string]*progressbar.ProgressBar)
		result, err := service.DownloadTransfer(ctx, cfg, client, service.DownloadTransferParams{
			ShareID:    shareID,
			OutputDir:  outputDir,
			Passphrase: transferPassphrase,
		}, readKeyPassphrase, cliProgressFn(bars))
		if err != nil {
			return err
		}

		fmt.Fprintf(os.Stderr, "\nDownloaded to %s/\n", result.OutputDir)

		return nil
	},
}

func init() {
	transferLsCmd.Flags().Bool("sent", false, "List sent transfers (default)")
	transferLsCmd.Flags().Bool("received", false, "List received transfers")

	transferCreateCmd.Flags().String("title", "", "Title of the transfer")
	transferCreateCmd.Flags().Int("expire", 3600, "Expiration in seconds (0 = no expiration)")
	transferCreateCmd.Flags().String("message", "", "Optional message to include")
	transferCreateCmd.Flags().String("passphrase", "", "Transfer passphrase (prompted if required and omitted)")
	transferCreateCmd.Flags().Bool("generate-passphrase", false, "Generate and display a random transfer passphrase")
	transferCreateCmd.MarkFlagsMutuallyExclusive("passphrase", "generate-passphrase")
	transferCreateCmd.Flags().StringArray("to", nil, "Recipient email address (repeatable)")
	transferCreateCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")

	transferDownloadCmd.Flags().StringP("output", "o", "", "Destination directory (default: transfer-<random>)")
	transferDownloadCmd.Flags().BoolP("yes", "y", false, "Skip confirmation prompt")

	transferCmd.AddCommand(transferLsCmd)
	transferCmd.AddCommand(transferInfoCmd)
	transferCmd.AddCommand(transferCreateCmd)
	transferCmd.AddCommand(transferDownloadCmd)
	transferCmd.AddCommand(transferDisableCmd)
	transferCmd.AddCommand(transferEnableCmd)
	rootCmd.AddCommand(transferCmd)
}
