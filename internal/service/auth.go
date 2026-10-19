package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/keyring"
	"github.com/retyc/retyc-cli/internal/telemetry"
	"go.opentelemetry.io/otel/trace"
)

// ErrWrongKeyPassphrase is returned when the key passphrase does not decrypt
// the user's private key. Retrying with the same passphrase cannot succeed.
var ErrWrongKeyPassphrase = errors.New("wrong key passphrase")

// ErrAgeKeyMismatch is returned when the machine's age.key is not the private
// half of the account's active key. It is wrapped with config.ErrMachineConfig.
var ErrAgeKeyMismatch = errors.New("the AGE key does not match the machine account's key")

// classicAgeKeyPrefix starts an X25519 identity, which this CLI never accepts.
const classicAgeKeyPrefix = "AGE-SECRET-KEY-1"

// MachineIdentity reads the machine's AGE identity from its key file and checks
// that it is the private half of userKey. No passphrase, keyring or scrypt is
// involved. Errors wrap config.ErrMachineConfig and never quote the file.
func MachineIdentity(_ context.Context, userKey *api.UserKey) (*age.HybridIdentity, error) {
	m, err := config.LoadMachine()
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, fmt.Errorf("%w: not in machine mode", config.ErrMachineConfig)
	}
	if userKey == nil {
		return nil, fmt.Errorf("%w: no active key", config.ErrMachineConfig)
	}
	data, err := config.ReadMachineFile(m.AgeKeyFile)
	if err != nil {
		return nil, err
	}
	identity, err := parseMachineAgeKey(data, m.AgeKeyFile)
	if err != nil {
		return nil, err
	}
	if identity.Recipient().String() != userKey.PublicKey {
		return nil, fmt.Errorf("%w: %w", config.ErrMachineConfig, ErrAgeKeyMismatch)
	}

	return identity, nil
}

// parseMachineAgeKey parses the content of a machine age.key: comment lines
// and blank lines are skipped, exactly one post-quantum identity must remain.
// name is the file name used in errors, which wrap config.ErrMachineConfig and
// never quote the content.
func parseMachineAgeKey(data []byte, name string) (*age.HybridIdentity, error) {
	// The standard age-keygen format puts comment lines before the key.
	var keyLines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keyLines = append(keyLines, line)
	}
	if len(keyLines) != 1 {
		return nil, fmt.Errorf("%w: %s must hold exactly one identity (expected one identity, found %d)",
			config.ErrMachineConfig, name, len(keyLines))
	}
	content := keyLines[0]
	if strings.HasPrefix(content, classicAgeKeyPrefix) {
		return nil, fmt.Errorf("%w: %s holds a classic X25519 key, a post-quantum key is required",
			config.ErrMachineConfig, name)
	}
	identity, err := crypto.ParseIdentity(content)
	if err != nil {
		// The parse error is dropped on purpose: it could quote the key.
		return nil, fmt.Errorf("%w: %s is not a valid post-quantum AGE identity", config.ErrMachineConfig, name)
	}

	return identity, nil
}

// decryptKeyWithPassphrase runs the scrypt that unlocks a private key with a
// passphrase, as one crypto.unlock_key span under the caller's span. kind is
// "user" (the account key) or "transfer" (the ephemeral key of a transfer);
// the passphrase and the key never reach the span.
func decryptKeyWithPassphrase(ctx context.Context, kind, ciphertext, passphrase string) (string, error) {
	_, span := telemetry.Tracer().Start(ctx, "crypto.unlock_key", trace.WithAttributes(
		telemetry.AttrKeyKind.String(kind), telemetry.AttrKeySource.String("passphrase")))
	defer span.End()
	plaintext, err := crypto.DecryptToStringWithPassphrase(ciphertext, passphrase)
	if err != nil {
		telemetry.RecordError(span, err)

		return "", err
	}

	return plaintext, nil
}

// ResolveUserIdentity decrypts the user's AGE private key using the passphrase.
// It checks the keyring cache first (when enabled), falling back to reader().
// A keyring hit is exported as a crypto.unlock_key span with key.source
// "keyring", so a trace shows whether the scrypt ran.
func ResolveUserIdentity(
	ctx context.Context, cfg *config.Config, userKey *api.UserKey, reader PassphraseReader,
) (*age.HybridIdentity, error) {
	if config.MachineMode() {
		return MachineIdentity(ctx, userKey)
	}

	var identityStr string
	fromKeyring := false

	if cfg.Keyring.Enabled {
		// The keyring lookup is the cheap path; its span shows whether the
		// scrypt below was avoided.
		_, span := telemetry.Tracer().Start(ctx, "crypto.unlock_key", trace.WithAttributes(
			telemetry.AttrKeyKind.String("user"), telemetry.AttrKeySource.String("keyring")))
		var err error
		identityStr, err = keyring.Load()
		span.SetAttributes(telemetry.AttrCacheHit.Bool(err == nil && identityStr != ""))
		span.End()
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
		identityStr, err = decryptKeyWithPassphrase(ctx, "user", userKey.PrivateKeyEnc, passphrase)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrWrongKeyPassphrase, err)
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

// UnlockUserIdentity fetches the user's active key and decrypts it with the
// passphrase returned by reader. Unlike ResolveUserIdentity it deliberately
// bypasses the keyring cache: long-running servers (webdav) must fail fast at
// startup on a wrong passphrase, not hours later when the cached identity
// expires. The returned identity can then be reused for the life of the process
// (see GetDataroomSessionWithIdentity), so the scrypt runs exactly once.
func UnlockUserIdentity(ctx context.Context, client *api.Client, reader PassphraseReader) (
	*age.HybridIdentity, error,
) {
	userKey, err := client.GetActiveKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching user key: %w", err)
	}
	if config.MachineMode() {
		// A nil key is reported by MachineIdentity as a machine configuration error.
		return MachineIdentity(ctx, userKey)
	}
	if userKey == nil {
		return nil, fmt.Errorf("no active encryption key - set up your key in the web interface first")
	}
	passphrase, err := reader()
	if err != nil {
		return nil, err
	}
	identityStr, err := decryptKeyWithPassphrase(ctx, "user", userKey.PrivateKeyEnc, passphrase)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrWrongKeyPassphrase, err)
	}
	// Same reasoning as ResolveUserIdentity: release the ~256 MiB scrypt buffer now.
	debug.FreeOSMemory()

	identity, err := crypto.ParseIdentity(identityStr)
	if err != nil {
		return nil, fmt.Errorf("parsing AGE identity: %w", err)
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
	// Drop decrypted dataroom material before the token: even if the token
	// removal fails, nothing resolved under this identity must outlive it.
	ResetSessionCache()
	if err = config.DeleteToken(); err != nil {
		return warnings, fmt.Errorf("removing token: %w", err)
	}

	return warnings, nil
}
