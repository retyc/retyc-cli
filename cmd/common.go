// Package cmd — shared helpers used by multiple command files.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"filippo.io/age"
	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/keyring"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/oauth2"
	"golang.org/x/term"
)

// uploadChunkSize is the size of each plaintext chunk before encryption.
const uploadChunkSize = 8 * 1024 * 1024 // 8 MB

// minPassphraseLen is the minimum number of characters for a transfer passphrase.
const minPassphraseLen = 8

// uploadConcurrency is the number of chunks uploaded simultaneously per file.
const uploadConcurrency = 4

// downloadConcurrency is the number of chunks downloaded simultaneously per file.
const downloadConcurrency = 4

// readKeyPassphrase returns the key passphrase from RETYC_KEY_PASSPHRASE, or
// prompts the user interactively. Returns an error when stdin is not a terminal
// and the env var is unset.
func readKeyPassphrase() (string, error) {
	if v := os.Getenv("RETYC_KEY_PASSPHRASE"); v != "" {
		return v, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) { //nolint:gosec // G115: Fd() fits in int on all supported platforms
		return "", fmt.Errorf("no TTY detected and RETYC_KEY_PASSPHRASE is not set")
	}
	fmt.Fprint(os.Stderr, "Key passphrase: ")
	pb, err := term.ReadPassword(int(os.Stdin.Fd())) //nolint:gosec // G115: Fd() fits in int on all supported platforms
	fmt.Fprint(os.Stderr, "\r\033[2K")
	if err != nil {
		return "", fmt.Errorf("reading key passphrase: %w", err)
	}

	return string(pb), nil
}

// mustGetToken retrieves a refreshing OAuth2 token source, returning a
// user-friendly error if authentication is missing or expired.
func mustGetToken(ctx context.Context, cfg *config.Config) (oauth2.TokenSource, error) {
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

	persist := os.Getenv("RETYC_TOKEN") == ""

	return auth.NewRefreshingTokenSource(tok, *oidcCfg, httpClient, persist), nil
}

// newAPIClient loads config, obtains a valid token, and returns both the config
// and an authenticated API client ready to use.
func newAPIClient(ctx context.Context) (*config.Config, *api.Client, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, nil, fmt.Errorf("loading config: %w", err)
	}
	tok, err := mustGetToken(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}

	return cfg, api.New(cfg.API.BaseURL, cliUserAgent(), tok, insecure, debug), nil
}

// resolveUserIdentity decrypts the user's AGE private key using the passphrase,
// reading from the keyring cache first when enabled.
func resolveUserIdentity(cfg *config.Config, userKey *api.UserKey) (*age.HybridIdentity, error) {
	var identityStr string
	fromKeyring := false
	if cfg.Keyring.Enabled {
		var err error
		identityStr, err = keyring.Load()
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: keyring load: %v\n", err)
		} else if identityStr != "" {
			fromKeyring = true
		}
	}

	if identityStr == "" {
		passphrase, err := readKeyPassphrase()
		if err != nil {
			return nil, err
		}
		identityStr, err = crypto.DecryptToStringWithPassphrase(userKey.PrivateKeyEnc, passphrase)
		if err != nil {
			return nil, fmt.Errorf("wrong key passphrase")
		}
	}

	identity, err := crypto.ParseIdentity(identityStr)
	if err != nil {
		return nil, fmt.Errorf("parsing AGE identity: %w", err)
	}

	if cfg.Keyring.Enabled && !fromKeyring {
		if err := keyring.Store(identityStr, cfg.Keyring.TTL); err != nil {
			fmt.Fprintf(os.Stderr, "warning: keyring store: %v\n", err)
		}
	}

	return identity, nil
}

// newTransferBar creates a consistently styled progress bar for file transfers.
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

// uploadChunks reads f in uploadChunkSize chunks, encrypts each with sessionPubKey,
// and calls uploadFn for each encrypted chunk using up to uploadConcurrency
// concurrent goroutines. displayName is shown in the progress bar.
func uploadChunks(
	ctx context.Context,
	f *os.File,
	fileSize int64,
	displayName string,
	sessionPubKey string,
	uploadFn func(ctx context.Context, chunkID int, data []byte) error,
) error {
	bar := newTransferBar(displayName, fileSize)

	sem := make(chan struct{}, uploadConcurrency)
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)

	setErr := func(e error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = e
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
				if err := uploadFn(ctx, id, enc); err != nil {
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

// downloadChunks downloads chunkCount chunks concurrently via downloadFn, decrypts
// each with identity, and writes them in order to outputDir/name using a reorder
// buffer so network arrival order does not affect the output file.
func downloadChunks(
	ctx context.Context,
	outputDir string,
	name string,
	originalSize int64,
	chunkCount int,
	identity *age.HybridIdentity,
	downloadFn func(ctx context.Context, chunkID int) ([]byte, error),
) error {
	dest := filepath.Join(outputDir, name)
	//nolint:gosec // G304: dest is built from validated outputDir + decrypted filename
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer out.Close() //nolint:errcheck

	bar := newTransferBar(name, originalSize)

	type chunkResult struct {
		id   int
		data []byte
		err  error
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	concurrency := downloadConcurrency
	if chunkCount < concurrency {
		concurrency = chunkCount
	}

	jobs := make(chan int, concurrency)
	results := make(chan chunkResult, concurrency*2)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range jobs {
				encrypted, err := downloadFn(ctx, id)
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

	go func() {
		defer close(jobs)
		for i := 0; i < chunkCount; i++ {
			select {
			case jobs <- i:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	reorder := make(map[int][]byte)
	nextWrite := 0

	for r := range results {
		if r.err != nil {
			cancel()
			for range results {
			}

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
				for range results {
				}

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
