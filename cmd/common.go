// Package cmd — shared helpers used by multiple command files.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/oauth2"
	"golang.org/x/term"
)

// minPassphraseLen is the minimum number of characters for a transfer passphrase.
const minPassphraseLen = 8

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

// cliProgressFn returns a service.ProgressFn that updates a per-file progress bar.
// bars is a map keyed by filename; bars are created lazily on first call.
// A mutex guards the map because UploadChunks calls progress from multiple goroutines.
func cliProgressFn(bars map[string]*progressbar.ProgressBar) func(filename string, chunkBytes int, totalSize int64) {
	var mu sync.Mutex

	return func(filename string, chunkBytes int, totalSize int64) {
		mu.Lock()
		if _, ok := bars[filename]; !ok {
			bars[filename] = newTransferBar(filename, totalSize)
		}
		bar := bars[filename]
		mu.Unlock()

		_ = bar.Add(chunkBytes)
	}
}
