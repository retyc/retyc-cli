package cmd

import (
	"bufio"
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"filippo.io/age"
	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/keyring"
	"github.com/schollz/progressbar/v3"
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

		client := api.New(cfg.API.BaseURL, cliUserAgent(), tok, insecure, debug)
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

		client := api.New(cfg.API.BaseURL, cliUserAgent(), tok, insecure, debug)

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
		if details.WebURL != "" {
			fmt.Printf("URL:     %s\n", details.WebURL)
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

		// Try the kernel keyring cache first (skippable via config).
		var identityStr string
		if cfg.Keyring.Enabled {
			var err error
			identityStr, err = keyring.Load()
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: keyring load: %v\n", err)
			}
		}

		if identityStr == "" {
			passphrase, err := readKeyPassphrase()
			if err != nil {
				return err
			}

			// Decrypt user's AGE private key (scrypt).
			identityStr, err = crypto.DecryptToStringWithPassphrase(userKey.PrivateKeyEnc, passphrase)
			if err != nil {
				return fmt.Errorf("wrong key passphrase")
			}

			// Cache in the kernel keyring if enabled.
			if cfg.Keyring.Enabled {
				if err := keyring.Store(identityStr, cfg.Keyring.TTL); err != nil {
					fmt.Fprintf(os.Stderr, "warning: keyring store: %v\n", err)
				}
			}
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

// readKeyPassphrase returns the key passphrase from the RETYC_KEY_PASSPHRASE
// environment variable, or prompts the user interactively if the variable is not set.
// Returns a clear error when stdin is not a terminal and RETYC_KEY_PASSPHRASE is unset.
func readKeyPassphrase() (string, error) {
	if v := os.Getenv("RETYC_KEY_PASSPHRASE"); v != "" {
		return v, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("no TTY detected and RETYC_KEY_PASSPHRASE is not set")
	}
	fmt.Fprint(os.Stderr, "Key passphrase: ")
	pb, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprint(os.Stderr, "\r\033[2K")
	if err != nil {
		return "", fmt.Errorf("reading key passphrase: %w", err)
	}
	return string(pb), nil
}

// mustGetToken retrieves a valid OAuth2 token, returning a user-friendly error
// if authentication is missing or expired.
func mustGetToken(ctx context.Context, cfg *config.Config) (*oauth2.Token, error) {
	httpClient := newHTTPClient(insecure, debug)

	oidcCfg, err := api.FetchOIDCConfig(ctx, cfg.API.BaseURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("fetching OIDC config: %w", err)
	}

	tok, err := auth.GetValidToken(ctx, *oidcCfg, httpClient)
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

// uploadChunkSize is the size of each plaintext chunk before encryption.
const uploadChunkSize = 8 * 1024 * 1024 // 8 MB

// minPassphraseLen is the minimum number of characters required for a transfer passphrase.
const minPassphraseLen = 8

// uploadConcurrency is the number of chunks uploaded simultaneously per file.
const uploadConcurrency = 4

// downloadConcurrency is the number of chunks downloaded simultaneously per file.
const downloadConcurrency = 4

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

		// Fail fast if --passphrase was provided explicitly but is too short.
		if passphraseExplicit && len(passphrase) < minPassphraseLen {
			return fmt.Errorf("transfer passphrase must be at least %d characters", minPassphraseLen)
		}

		// Generate a random passphrase if requested.
		if genPassphrase {
			var err error
			passphrase, err = generateTransferPassphrase()
			if err != nil {
				return fmt.Errorf("generating passphrase: %w", err)
			}
		}

		// Stat all files up front — needed for the summary and to fail early.
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

		// Confirmation prompt (skip with --yes / -y).
		if !yes {
			const lineWidth = 44
			fmt.Fprintln(os.Stderr)
			for _, e := range entries {
				name := e.name
				if len(name) > lineWidth-10 {
					name = name[:lineWidth-13] + "…"
				}
				fmt.Fprintf(os.Stderr, "  %-*s  %s\n", lineWidth-10, name, formatSize(e.size))
			}
			fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat("─", lineWidth))
			noun := "file"
			if len(entries) > 1 {
				noun = "files"
			}
			fmt.Fprintf(os.Stderr, "  %-*s  %s\n", lineWidth-10, fmt.Sprintf("%d %s", len(entries), noun), formatSize(totalSize))
			fmt.Fprintln(os.Stderr)
			if title != "" {
				fmt.Fprintf(os.Stderr, "  Title:    %s\n", title)
			}
			if len(toEmails) > 0 {
				fmt.Fprintf(os.Stderr, "  To:       %s\n", strings.Join(toEmails, ", "))
			}
			fmt.Fprintf(os.Stderr, "  Expires:  %s\n", formatExpiry(expire))
			fmt.Fprintln(os.Stderr)
			fmt.Fprint(os.Stderr, "Proceed? [y/N] ")
			answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			fmt.Fprintln(os.Stderr)
			if strings.ToLower(strings.TrimSpace(answer)) != "y" {
				fmt.Fprintln(os.Stderr, "Aborted.")
				return nil
			}
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

		client := api.New(cfg.API.BaseURL, cliUserAgent(), tok, insecure, debug)

		// Fetch the user's own public key and create the share in parallel.
		var titlePtr *string
		if title != "" {
			titlePtr = &title
		}

		type keyResult struct {
			v   *api.UserKey
			err error
		}
		type shareResult struct {
			v   *api.ShareCreateResponse
			err error
		}
		keyCh := make(chan keyResult, 1)
		shareCh := make(chan shareResult, 1)

		go func() {
			v, err := client.GetActiveKey(ctx)
			keyCh <- keyResult{v, err}
		}()
		go func() {
			v, err := client.CreateShare(ctx, expire, titlePtr, true, toEmails)
			shareCh <- shareResult{v, err}
		}()

		kr := <-keyCh
		if kr.err != nil {
			return fmt.Errorf("fetching encryption key: %w", kr.err)
		}
		userKey := kr.v
		if userKey == nil {
			return fmt.Errorf("no active encryption key — set up your key in the web interface first")
		}

		sr := <-shareCh
		if sr.err != nil {
			return fmt.Errorf("creating transfer: %w", sr.err)
		}
		share := sr.v
		fmt.Fprintf(os.Stderr, "Transfer %s created, uploading…\n", share.ID)

		// Decide whether a transfer passphrase is needed.
		// A passphrase is not needed only when all specified recipients already have a key.
		allHaveKeys := len(toEmails) > 0 && len(share.PublicKeys) == len(toEmails)
		needPassphrase := !allHaveKeys || passphraseExplicit || genPassphrase

		// Inform the user if some recipients have no key and a passphrase is therefore required.
		if len(toEmails) > 0 && len(share.PublicKeys) < len(toEmails) {
			fmt.Fprintf(os.Stderr, "Note: %d recipient(s) have no encryption key — a transfer passphrase is required.\n",
				len(toEmails)-len(share.PublicKeys))
		}

		// Prompt for transfer passphrase if required and not provided via flag.
		// Re-prompt on invalid input or mismatched confirmation.
		if needPassphrase && passphrase == "" {
			for {
				fmt.Fprint(os.Stderr, "Transfer passphrase: ")
				pb, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Fprint(os.Stderr, "\r\033[2K")
				if err != nil {
					return fmt.Errorf("reading passphrase: %w", err)
				}
				if len(pb) < minPassphraseLen {
					fmt.Fprintf(os.Stderr, "Passphrase must be at least %d characters.\n", minPassphraseLen)
					continue
				}
				fmt.Fprint(os.Stderr, "Confirm passphrase: ")
				pb2, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Fprint(os.Stderr, "\r\033[2K")
				if err != nil {
					return fmt.Errorf("reading passphrase confirmation: %w", err)
				}
				if string(pb) != string(pb2) {
					fmt.Fprintln(os.Stderr, "Passphrases do not match.")
					continue
				}
				passphrase = string(pb)
				break
			}
		}

		// Generate session keypair — used to encrypt file content and metadata.
		sessionIdentity, err := crypto.GenerateKeyPair()
		if err != nil {
			return fmt.Errorf("generating session key: %w", err)
		}
		sessionPrivKey := sessionIdentity.String()
		sessionPubKey := sessionIdentity.Recipient().String()

		// Encrypt session private key for the owner and all recipients who have a key.
		allPubKeys := append([]string{userKey.PublicKey}, share.PublicKeys...)
		sessionPrivKeyEnc, err := crypto.EncryptStringForKeys(sessionPrivKey, allPubKeys)
		if err != nil {
			return fmt.Errorf("encrypting session key: %w", err)
		}

		// Generate ephemeral keypair only when a passphrase is required.
		// The backend now accepts nil ephemeral fields (updated API), so we omit them
		// entirely when all recipients have a key — no passphrase path needed.
		var ephemeralPrivKeyEnc, ephemeralPubKey, sessionPrivKeyEncForPassphrase string
		if needPassphrase {
			ephemeralIdentity, err := crypto.GenerateKeyPair()
			if err != nil {
				return fmt.Errorf("generating ephemeral key: %w", err)
			}
			ephPubKey := ephemeralIdentity.Recipient().String()
			ephPrivKey := ephemeralIdentity.String()

			enc, err := crypto.EncryptWithPassphrase([]byte(ephPrivKey), passphrase)
			if err != nil {
				return fmt.Errorf("encrypting ephemeral key: %w", err)
			}
			sesEnc, err := crypto.EncryptStringForKeys(sessionPrivKey, []string{ephPubKey})
			if err != nil {
				return fmt.Errorf("encrypting session key for passphrase access: %w", err)
			}

			ephemeralPrivKeyEnc = enc
			ephemeralPubKey = ephPubKey
			sessionPrivKeyEncForPassphrase = sesEnc
		}

		// Upload each file.
		for _, e := range entries {
			if err := uploadTransferFile(ctx, client, share.ID, e.path, sessionPubKey); err != nil {
				return fmt.Errorf("%s: %w", e.name, err)
			}
		}

		// Encrypt message if provided.
		var messageEnc *string
		if message != "" {
			enc, err := crypto.EncryptStringForKeys(message, []string{sessionPubKey})
			if err != nil {
				return fmt.Errorf("encrypting message: %w", err)
			}
			messageEnc = &enc
		}

		// Complete the transfer — ephemeral fields included only when a passphrase is used.
		req := api.CompleteTransferRequest{
			SessionPrivateKeyEnc: sessionPrivKeyEnc,
			SessionPublicKey:     sessionPubKey,
			MessageEnc:           messageEnc,
		}
		if needPassphrase {
			req.EphemeralPrivateKeyEnc = &ephemeralPrivKeyEnc
			req.EphemeralPublicKey = &ephemeralPubKey
			req.SessionPrivateKeyEncForPassphrase = &sessionPrivKeyEncForPassphrase
		}
		if err := client.CompleteTransfer(ctx, share.ID, req); err != nil {
			return fmt.Errorf("completing transfer: %w", err)
		}

		details, err := client.GetTransferDetails(ctx, share.ID)
		if err != nil {
			// Non-fatal: the transfer is complete even if we can't fetch the URL.
			fmt.Printf("Transfer %s ready.\n", share.ID)
			if genPassphrase {
				fmt.Printf("Passphrase: %s\n", passphrase)
			}
			return nil
		}

		fmt.Printf("Transfer %s ready.\n", share.ID)
		if details.WebURL != "" {
			fmt.Printf("URL: %s\n", details.WebURL)
		}
		if genPassphrase {
			fmt.Printf("Passphrase: %s\n", passphrase)
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

// newTransferBar creates a consistently styled progress bar for file transfers.
// It is used for both uploads and downloads.
func newTransferBar(name string, sizeBytes int64) *progressbar.ProgressBar {
	const descWidth = 24
	desc := name
	if len(desc) > descWidth {
		desc = desc[:descWidth-1] + "…"
	}
	return progressbar.NewOptions64(
		sizeBytes,
		progressbar.OptionSetDescription(fmt.Sprintf("  %-*s", descWidth, desc)),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWidth(28),
		progressbar.OptionThrottle(100*time.Millisecond),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
		progressbar.OptionOnCompletion(func() {
			fmt.Fprintln(os.Stderr)
		}),
	)
}

// uploadTransferFile encrypts and uploads a single file in chunks to shareID.
//
// The main goroutine reads and encrypts chunks sequentially (sequential disk reads
// are optimal). Each encrypted chunk is immediately dispatched to its own upload
// goroutine. A semaphore limits the number of in-flight uploads to uploadConcurrency,
// keeping multiple HTTP connections busy in parallel.
func uploadTransferFile(ctx context.Context, client *api.Client, shareID, filePath, sessionPubKey string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}

	name := filepath.Base(filePath)
	mimeType := mime.TypeByExtension(filepath.Ext(filePath))
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	// Encrypt file metadata (name and MIME type) with the session public key.
	nameEnc, err := crypto.EncryptStringForKeys(name, []string{sessionPubKey})
	if err != nil {
		return fmt.Errorf("encrypting filename: %w", err)
	}
	typeEnc, err := crypto.EncryptStringForKeys(mimeType, []string{sessionPubKey})
	if err != nil {
		return fmt.Errorf("encrypting MIME type: %w", err)
	}

	fileModel, err := client.CreateFile(ctx, shareID, nameEnc, typeEnc, info.Size())
	if err != nil {
		return fmt.Errorf("registering file: %w", err)
	}

	bar := newTransferBar(name, info.Size())

	// sem limits the number of concurrent upload goroutines.
	sem := make(chan struct{}, uploadConcurrency)
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)

	setErr := func(err error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
	}
	hasErr := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return firstErr != nil
	}

	buf := make([]byte, uploadChunkSize)
	for chunkID := 0; ; chunkID++ {
		// Stop reading if an upload has already failed.
		if hasErr() {
			break
		}

		n, readErr := io.ReadFull(f, buf)
		if n > 0 {
			encrypted, encErr := crypto.EncryptBinaryForKey(buf[:n], sessionPubKey)
			if encErr != nil {
				setErr(fmt.Errorf("encrypting chunk %d: %w", chunkID, encErr))
				break
			}

			// Acquire a semaphore slot — blocks when uploadConcurrency uploads are in flight.
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				setErr(ctx.Err())
				break
			}
			if hasErr() {
				break
			}

			id, enc, sz := chunkID, encrypted, n
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				if err := client.UploadChunk(ctx, fileModel.ID, id, enc); err != nil {
					setErr(fmt.Errorf("uploading chunk %d: %w", id, err))
					return
				}
				_ = bar.Add(sz)
			}()
		}

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			setErr(fmt.Errorf("reading file: %w", readErr))
			break
		}
	}

	wg.Wait()

	if firstErr != nil {
		return firstErr
	}

	_ = bar.Finish()
	return nil
}

var transferDisableCmd = &cobra.Command{
	Use:   "disable <transfer_id>",
	Short: "Disable a transfer",
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

		client := api.New(cfg.API.BaseURL, cliUserAgent(), tok, insecure, debug)
		if err := client.DisableTransfer(ctx, shareID); err != nil {
			return fmt.Errorf("disabling transfer: %w", err)
		}

		fmt.Printf("Transfer %s disabled.\n", shareID)
		return nil
	},
}

var transferEnableCmd = &cobra.Command{
	Use:   "enable <transfer_id>",
	Short: "Re-enable a disabled transfer",
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

		client := api.New(cfg.API.BaseURL, cliUserAgent(), tok, insecure, debug)
		if err := client.EnableTransfer(ctx, shareID); err != nil {
			return fmt.Errorf("enabling transfer: %w", err)
		}

		fmt.Printf("Transfer %s enabled.\n", shareID)
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

		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}

		ctx := context.Background()
		tok, err := mustGetToken(ctx, cfg)
		if err != nil {
			return err
		}

		client := api.New(cfg.API.BaseURL, cliUserAgent(), tok, insecure, debug)

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
		go func() { v, err := client.GetTransferDetails(ctx, shareID); detailsCh <- detailsResult{v, err} }()
		go func() { v, err := client.GetActiveKey(ctx); keyCh <- keyResult{v, err} }()

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

		if details.SessionPrivateKeyEnc == nil && details.SessionPrivateKeyEncForPassphrase == nil {
			return fmt.Errorf("transfer not yet completed — no encrypted content available")
		}

		// Resolve session private key: try user key path first, then transfer passphrase.
		var identityStr string

		if userKey != nil && details.SessionPrivateKeyEnc != nil {
			// Try keyring cache first.
			if cfg.Keyring.Enabled {
				identityStr, _ = keyring.Load()
			}
			if identityStr == "" {
				passphrase, err := readKeyPassphrase()
				if err != nil {
					return err
				}
				identityStr, err = crypto.DecryptToStringWithPassphrase(userKey.PrivateKeyEnc, passphrase)
				if err != nil {
					return fmt.Errorf("wrong key passphrase")
				}
				if cfg.Keyring.Enabled {
					if err := keyring.Store(identityStr, cfg.Keyring.TTL); err != nil {
						fmt.Fprintf(os.Stderr, "warning: keyring store: %v\n", err)
					}
				}
			}
			identity, err := crypto.ParseIdentity(identityStr)
			if err != nil {
				return fmt.Errorf("parsing identity: %w", err)
			}
			sessionPrivKey, err := crypto.DecryptToString(*details.SessionPrivateKeyEnc, identity)
			if err != nil {
				return fmt.Errorf("decrypting session key (key mismatch?): %w", err)
			}
			identityStr = sessionPrivKey
		} else {
			// Ephemeral path: use transfer passphrase.
			if details.EphemeralPrivateKeyEnc == nil || details.SessionPrivateKeyEncForPassphrase == nil {
				return fmt.Errorf("no decryption path available — neither user key nor passphrase data found")
			}
			fmt.Fprint(os.Stderr, "Transfer passphrase: ")
			pb, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprint(os.Stderr, "\r\033[2K")
			if err != nil {
				return fmt.Errorf("reading passphrase: %w", err)
			}
			ephemeralPrivKey, err := crypto.DecryptToStringWithPassphrase(*details.EphemeralPrivateKeyEnc, string(pb))
			if err != nil {
				return fmt.Errorf("wrong transfer passphrase")
			}
			ephemeralIdentity, err := crypto.ParseIdentity(ephemeralPrivKey)
			if err != nil {
				return fmt.Errorf("parsing ephemeral identity: %w", err)
			}
			sessionPrivKey, err := crypto.DecryptToString(*details.SessionPrivateKeyEncForPassphrase, ephemeralIdentity)
			if err != nil {
				return fmt.Errorf("decrypting session key: %w", err)
			}
			identityStr = sessionPrivKey
		}

		sessionIdentity, err := crypto.ParseIdentity(identityStr)
		if err != nil {
			return fmt.Errorf("parsing session identity: %w", err)
		}

		// Fetch all files (paginate).
		var allFiles []api.TransferFile
		for page := 1; ; page++ {
			p, err := client.ListFiles(ctx, shareID, page)
			if err != nil {
				return fmt.Errorf("listing files: %w", err)
			}
			allFiles = append(allFiles, p.Items...)
			if page >= p.Pages {
				break
			}
		}
		if len(allFiles) == 0 {
			return fmt.Errorf("no files in this transfer")
		}

		// Decrypt file names up front (needed for conflict check and confirmation).
		type decryptedFile struct {
			api.TransferFile
			name string
		}
		decFiles := make([]decryptedFile, 0, len(allFiles))
		var totalSize int64
		for _, f := range allFiles {
			name, err := crypto.DecryptToString(f.NameEnc, sessionIdentity)
			if err != nil {
				name = f.ID // fallback
			}
			decFiles = append(decFiles, decryptedFile{f, name})
			totalSize += f.OriginalSize
		}

		// Determine destination directory.
		if outputDir == "" {
			outputDir = "transfer-" + randomLetters(8)
		}

		// Fail-fast: if destination exists, check for file name conflicts.
		if _, err := os.Stat(outputDir); err == nil {
			for _, f := range decFiles {
				dest := filepath.Join(outputDir, f.name)
				if _, err := os.Stat(dest); err == nil {
					return fmt.Errorf("file already exists: %s", dest)
				}
			}
		}

		// Confirmation prompt (skip with --yes / -y).
		if !yes {
			const lineWidth = 44
			fmt.Fprintln(os.Stderr)
			for _, f := range decFiles {
				name := f.name
				if len(name) > lineWidth-10 {
					name = name[:lineWidth-13] + "…"
				}
				fmt.Fprintf(os.Stderr, "  %-*s  %s\n", lineWidth-10, name, formatSize(f.OriginalSize))
			}
			fmt.Fprintf(os.Stderr, "  %s\n", strings.Repeat("─", lineWidth))
			noun := "file"
			if len(decFiles) > 1 {
				noun = "files"
			}
			fmt.Fprintf(os.Stderr, "  %-*s  %s\n", lineWidth-10, fmt.Sprintf("%d %s", len(decFiles), noun), formatSize(totalSize))
			fmt.Fprintln(os.Stderr)
			fmt.Fprintf(os.Stderr, "  Destination:  %s/\n", outputDir)
			fmt.Fprintln(os.Stderr)
			fmt.Fprint(os.Stderr, "Proceed? [y/N] ")
			answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			fmt.Fprintln(os.Stderr)
			if strings.ToLower(strings.TrimSpace(answer)) != "y" {
				fmt.Fprintln(os.Stderr, "Aborted.")
				return nil
			}
		}

		// Create destination directory.
		if err := os.MkdirAll(outputDir, 0700); err != nil {
			return fmt.Errorf("creating destination directory: %w", err)
		}

		// Download and decrypt each file.
		for _, f := range decFiles {
			if err := downloadTransferFile(ctx, client, outputDir, f.TransferFile, f.name, sessionIdentity); err != nil {
				return fmt.Errorf("%s: %w", f.name, err)
			}
		}

		fmt.Fprintf(os.Stderr, "\nDownloaded to %s/\n", outputDir)
		return nil
	},
}

// downloadTransferFile downloads all chunks of a file in parallel, decrypts them,
// and writes them to disk in the correct order.
//
// Workers download and decrypt concurrently. A reorder buffer holds chunks that
// arrive ahead of the next expected write position, so disk writes always happen
// sequentially (chunk 0 → 1 → 2 → …) regardless of network arrival order.
func downloadTransferFile(ctx context.Context, client *api.Client, outputDir string, f api.TransferFile, name string, identity *age.HybridIdentity) error {
	dest := filepath.Join(outputDir, name)
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer out.Close()

	bar := newTransferBar(name, f.OriginalSize)

	type chunkResult struct {
		id   int
		data []byte
		err  error
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	concurrency := downloadConcurrency
	if f.ChunkCount < concurrency {
		concurrency = f.ChunkCount
	}

	jobs := make(chan int, concurrency)
	results := make(chan chunkResult, concurrency*2)

	// Workers: download + decrypt concurrently.
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				encrypted, err := client.DownloadChunk(ctx, f.ID, id)
				if err != nil {
					results <- chunkResult{id: id, err: fmt.Errorf("downloading chunk %d: %w", id, err)}
					return
				}
				plaintext, err := crypto.DecryptBinary(encrypted, identity)
				if err != nil {
					results <- chunkResult{id: id, err: fmt.Errorf("decrypting chunk %d: %w", id, err)}
					return
				}
				results <- chunkResult{id: id, data: plaintext}
			}
		}()
	}

	// Feed chunk IDs to workers; stop early if context is cancelled.
	go func() {
		defer close(jobs)
		for i := 0; i < f.ChunkCount; i++ {
			select {
			case jobs <- i:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Close results once all workers have exited.
	go func() {
		wg.Wait()
		close(results)
	}()

	// Reorder buffer: chunks may arrive out of order; only write when the next
	// expected chunk is available so the file is always composed correctly.
	reorder := make(map[int][]byte)
	nextWrite := 0

	for r := range results {
		if r.err != nil {
			cancel()
			for range results {} // drain so workers can unblock and exit
			return r.err
		}
		reorder[r.id] = r.data

		for {
			data, ok := reorder[nextWrite]
			if !ok {
				break
			}
			if _, err := out.Write(data); err != nil {
				cancel()
				for range results {}
				return fmt.Errorf("writing chunk %d: %w", nextWrite, err)
			}
			_ = bar.Add(len(data))
			delete(reorder, nextWrite)
			nextWrite++
		}
	}

	_ = bar.Finish()
	return nil
}

// generateTransferPassphrase generates a cryptographically secure 32-character
// passphrase drawn uniformly from the 94 printable non-space ASCII characters (0x21–0x7E).
// crypto/rand.Int is used to avoid modulo bias.
func generateTransferPassphrase() (string, error) {
	const chars = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
	max := big.NewInt(int64(len(chars)))
	result := make([]byte, 32)
	for i := range result {
		n, err := cryptorand.Int(cryptorand.Reader, max)
		if err != nil {
			return "", err
		}
		result[i] = chars[n.Int64()]
	}
	return string(result), nil
}

// randomLetters returns a string of n random lowercase ASCII letters.
func randomLetters(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, n)
	_, _ = cryptorand.Read(b)
	for i, c := range b {
		b[i] = letters[int(c)%len(letters)]
	}
	return string(b)
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
