package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"filippo.io/age"
	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/keyring"
)

// ResolveUserIdentity decrypts the user's AGE private key using the passphrase.
// It checks the keyring cache first (when enabled), falling back to reader().
func ResolveUserIdentity(cfg *config.Config, userKey *api.UserKey, reader PassphraseReader) (
	*age.HybridIdentity, error,
) {
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
		passphrase, err := reader()
		if err != nil {
			return nil, err
		}
		identityStr, err = crypto.DecryptToStringWithPassphrase(userKey.PrivateKeyEnc, passphrase)
		if err != nil {
			return nil, fmt.Errorf("wrong key passphrase: %w", err)
		}
		// The scrypt above needs ~256 MiB of working memory (age work factor 2^18).
		// Hand it back to the OS now rather than letting the runtime scavenge it over
		// minutes: long-running servers (webdav, mcp) would otherwise sit at a
		// misleading RSS and trip container memory limits.
		debug.FreeOSMemory()
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

// — Auth flow (device flow + logout) ——————————————————————————————————————————

// oidcCache caches FetchOIDCConfig results to avoid 2 round-trips per LoginPoll call.
var oidcCache struct {
	sync.Mutex
	entries map[string]*oidcCacheEntry
}

type oidcCacheEntry struct {
	cfg       *config.OIDCConfig
	expiresAt time.Time
}

const oidcCacheTTL = 5 * time.Minute

// fetchOIDCCached returns a cached OIDCConfig for baseURL, fetching it when
// the cache is empty or expired. Under concurrent callers on a cold cache,
// multiple redundant fetches may occur; this is acceptable because the MCP
// server serializes requests over a single stdio connection.
// The returned pointer is shared — callers must not mutate it.
func fetchOIDCCached(ctx context.Context, baseURL string, httpClient *http.Client) (*config.OIDCConfig, error) {
	oidcCache.Lock()
	if oidcCache.entries == nil {
		oidcCache.entries = make(map[string]*oidcCacheEntry)
	}
	if e, ok := oidcCache.entries[baseURL]; ok && time.Now().Before(e.expiresAt) {
		cfg := e.cfg
		oidcCache.Unlock()

		return cfg, nil
	}
	oidcCache.Unlock()

	cfg, err := api.FetchOIDCConfig(ctx, baseURL, httpClient)
	if err != nil {
		return nil, err
	}

	oidcCache.Lock()
	oidcCache.entries[baseURL] = &oidcCacheEntry{cfg: cfg, expiresAt: time.Now().Add(oidcCacheTTL)}
	oidcCache.Unlock()

	return cfg, nil
}

// LoginStartResult is returned by LoginStart.
type LoginStartResult struct {
	AlreadyAuthenticated    bool
	ExpiresAt               time.Time // set when AlreadyAuthenticated is true
	VerificationURIComplete string
	VerificationURI         string
	UserCode                string
	DeviceCode              string
	Interval                int
	ExpiresIn               int
}

// LoginStart initiates an OIDC device flow login. If a valid token is already
// stored on disk, it returns AlreadyAuthenticated=true without starting a new flow.
func LoginStart(ctx context.Context, baseURL string, httpClient *http.Client) (*LoginStartResult, error) {
	if tok, err := config.LoadToken(); err == nil && tok.Valid() {
		return &LoginStartResult{AlreadyAuthenticated: true, ExpiresAt: tok.Expiry}, nil
	}
	oidcCfg, err := fetchOIDCCached(ctx, baseURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("fetching OIDC config: %w", err)
	}
	dar, err := auth.RequestDeviceCode(*oidcCfg, httpClient)
	if err != nil {
		return nil, fmt.Errorf("requesting device code: %w", err)
	}
	if dar.ExpiresIn == 0 {
		dar.ExpiresIn = 300
	}
	if dar.Interval == 0 {
		dar.Interval = 5
	}

	return &LoginStartResult{
		VerificationURIComplete: dar.VerificationURIComplete,
		VerificationURI:         dar.VerificationURI,
		UserCode:                dar.UserCode,
		DeviceCode:              dar.DeviceCode,
		Interval:                dar.Interval,
		ExpiresIn:               dar.ExpiresIn,
	}, nil
}

// Poll status values returned by LoginPoll.
const (
	PollDone     = "done"
	PollPending  = "pending"
	PollExpired  = "expired"
	PollDenied   = "denied"
	PollSlowDown = "slow_down"
)

// LoginPollResult is returned by LoginPoll.
type LoginPollResult struct {
	Status         string
	ExpiresAt      time.Time // set when Status == PollDone
	ExtraDelaySecs int       // set when Status == PollSlowDown
}

// LoginPoll polls the OIDC token endpoint once for a device flow started with
// LoginStart. On success (Status==PollDone) the token is saved to disk.
// Callers should wait Interval seconds between calls and add ExtraDelaySecs to
// the interval when Status==PollSlowDown.
func LoginPoll(ctx context.Context, baseURL, deviceCode string, httpClient *http.Client) (*LoginPollResult, error) {
	oidcCfg, err := fetchOIDCCached(ctx, baseURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("fetching OIDC config: %w", err)
	}
	tok, err := auth.PollToken(*oidcCfg, deviceCode, httpClient)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrDeviceCodeExpired):
			return &LoginPollResult{Status: PollExpired}, nil
		case errors.Is(err, auth.ErrAccessDenied):
			return &LoginPollResult{Status: PollDenied}, nil
		case errors.Is(err, auth.ErrSlowDown):
			return &LoginPollResult{Status: PollSlowDown, ExtraDelaySecs: 5}, nil
		default:
			return nil, err
		}
	}
	if tok == nil {
		return &LoginPollResult{Status: PollPending}, nil
	}
	if err := config.SaveToken(tok); err != nil {
		return nil, fmt.Errorf("saving token: %w", err)
	}

	return &LoginPollResult{Status: PollDone, ExpiresAt: tok.Expiry}, nil
}

// Logout revokes the server-side session (best-effort) and deletes the stored
// token file. Server revocation errors are returned as non-fatal warnings;
// local deletion failure is fatal.
func Logout(ctx context.Context, baseURL string, httpClient *http.Client) (warnings []error, err error) {
	tok, lerr := config.LoadToken()
	if lerr == nil && tok.RefreshToken != "" && baseURL != "" {
		oidcCfg, oerr := fetchOIDCCached(ctx, baseURL, httpClient)
		if oerr != nil {
			warnings = append(warnings, fmt.Errorf("fetching OIDC config: %w", oerr))
		} else if rerr := auth.Revoke(ctx, *oidcCfg, tok.RefreshToken, httpClient); rerr != nil {
			warnings = append(warnings, fmt.Errorf("revoking token: %w", rerr))
		}
	}
	if err = config.DeleteToken(); err != nil {
		return warnings, fmt.Errorf("removing token: %w", err)
	}

	return warnings, nil
}
