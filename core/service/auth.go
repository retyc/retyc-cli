package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"filippo.io/age"
	"go.opentelemetry.io/otel/trace"

	"github.com/retyc/retyc-cli/core/api"
	"github.com/retyc/retyc-cli/core/auth"
	"github.com/retyc/retyc-cli/core/config"
	"github.com/retyc/retyc-cli/core/crypto"
	"github.com/retyc/retyc-cli/core/diag"
	"github.com/retyc/retyc-cli/core/keyring"
	"github.com/retyc/retyc-cli/core/telemetry"
)

// ErrWrongKeyPassphrase is returned when the key passphrase does not decrypt
// the user's private key. Retrying with the same passphrase cannot succeed.
var ErrWrongKeyPassphrase = errors.New("wrong key passphrase")

// ErrAgeKeyMismatch is returned when the machine's age.key is not the private
// half of the account's active key. It is wrapped with config.ErrMachineConfig.
var ErrAgeKeyMismatch = errors.New("the AGE key does not match the machine account's key")

// MachineIdentity returns the AGE identity of the machine account m after
// checking that it is the private half of userKey, the account's active key.
// No passphrase, keyring or scrypt is involved. Errors wrap
// config.ErrMachineConfig.
func MachineIdentity(_ context.Context, m *config.MachineIdentity, userKey *api.UserKey) (*age.HybridIdentity, error) {
	if m == nil || m.AgeIdentity == nil {
		return nil, fmt.Errorf("%w: not in machine mode", config.ErrMachineConfig)
	}
	if userKey == nil {
		return nil, fmt.Errorf("%w: no active key", config.ErrMachineConfig)
	}
	if m.AgeIdentity.Recipient().String() != userKey.PublicKey {
		return nil, fmt.Errorf("%w: %w", config.ErrMachineConfig, ErrAgeKeyMismatch)
	}

	return m.AgeIdentity, nil
}

// machineOf is the machine identity of cfg, nil for a user account (or a nil
// cfg).
func machineOf(cfg *config.Config) *config.MachineIdentity {
	if cfg == nil {
		return nil
	}

	return cfg.Machine
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

// IdentityCache keeps the decrypted identity of the user's key between
// unlocks, so that the scrypt of the passphrase runs once. It is consulted
// only when cfg.Keyring.Enabled is set. The CLI uses the Linux session keyring
// (KeyringCache, the default); a program that imports the core gives its own
// (an OS vault) to SetIdentityCache.
type IdentityCache interface {
	// Load returns the identity (AGE-SECRET-KEY-PQ-1…) cached for keyID, or
	// "" and no error when there is none.
	Load(keyID string) (string, error)
	// Store caches identity for keyID. ttl is keyring.ttl, in seconds; a
	// cache may ignore it.
	Store(keyID, identity string, ttl int) error
}

// KeyringCache is the identity cache of the CLI: the Linux session keyring
// (a no-op on other systems, see package keyring).
type KeyringCache struct{}

// Load reads the keyring (keyring.Load).
func (KeyringCache) Load(keyID string) (string, error) { return keyring.Load(keyID) }

// Store writes the keyring (keyring.Store).
func (KeyringCache) Store(keyID, identity string, ttl int) error {
	return keyring.Store(keyID, identity, ttl)
}

var (
	identityCacheMu sync.RWMutex
	identityCache   IdentityCache = KeyringCache{}
)

// SetIdentityCache sets the cache of the decrypted identity; nil restores
// the default, the session keyring (KeyringCache).
func SetIdentityCache(c IdentityCache) {
	identityCacheMu.Lock()
	defer identityCacheMu.Unlock()
	if c == nil {
		c = KeyringCache{}
	}
	identityCache = c
}

func currentIdentityCache() IdentityCache {
	identityCacheMu.RLock()
	defer identityCacheMu.RUnlock()

	return identityCache
}

// ResolveUserIdentity decrypts the user's AGE private key using the passphrase.
// It checks the keyring cache first (when enabled), falling back to reader().
// A keyring hit is exported as a crypto.unlock_key span with key.source
// "keyring", so a trace shows whether the scrypt ran.
func ResolveUserIdentity(
	ctx context.Context, cfg *config.Config, userKey *api.UserKey, reader PassphraseReader,
) (*age.HybridIdentity, error) {
	if m := machineOf(cfg); m != nil {
		return MachineIdentity(ctx, m, userKey)
	}

	if cfg.Keyring.Enabled {
		if identity := cachedUserIdentity(ctx, userKey); identity != nil {
			return identity, nil
		}
	}

	passphrase, err := reader()
	if err != nil {
		return nil, err
	}
	identityStr, err := decryptKeyWithPassphrase(ctx, "user", userKey.PrivateKeyEnc, passphrase)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrWrongKeyPassphrase, err)
	}
	// The scrypt above needs ~256 MiB of working memory (age work factor 2^18).
	// Hand it back to the OS now rather than letting the runtime scavenge it over
	// minutes: long-running servers (webdav, mcp) would otherwise sit at a
	// misleading RSS and trip container memory limits.
	debug.FreeOSMemory()

	identity, err := crypto.ParseIdentity(identityStr)
	if err != nil {
		return nil, fmt.Errorf("parsing AGE identity: %w", err)
	}

	if cfg.Keyring.Enabled {
		if err := currentIdentityCache().Store(userKey.ID, identityStr, cfg.Keyring.TTL); err != nil {
			fmt.Fprintf(diag.Writer(), "warning: keyring store: %v\n", err)
		}
	}

	return identity, nil
}

// cachedUserIdentity returns the identity of userKey cached in the keyring, or
// nil. A cached identity whose recipient is not the public key of userKey (a
// key ID reused, an entry written by hand) reads as a miss: it would decrypt
// nothing of this account, and is overwritten once the key is unlocked.
func cachedUserIdentity(ctx context.Context, userKey *api.UserKey) *age.HybridIdentity {
	// The keyring lookup is the cheap path; its span shows whether the
	// scrypt was avoided.
	_, span := telemetry.Tracer().Start(ctx, "crypto.unlock_key", trace.WithAttributes(
		telemetry.AttrKeyKind.String("user"), telemetry.AttrKeySource.String("keyring")))
	defer span.End()

	identityStr, err := currentIdentityCache().Load(userKey.ID)
	if err != nil {
		fmt.Fprintf(diag.Writer(), "warning: keyring load: %v\n", err)
	}
	var identity *age.HybridIdentity
	if err == nil && identityStr != "" {
		if parsed, perr := crypto.ParseIdentity(identityStr); perr == nil &&
			parsed.Recipient().String() == userKey.PublicKey {
			identity = parsed
		}
	}
	span.SetAttributes(telemetry.AttrCacheHit.Bool(identity != nil))

	return identity
}

// ResolveActiveUserIdentity fetches the user's active key and unlocks it as
// ResolveUserIdentity does: from the keyring cache when it holds the identity,
// otherwise with the passphrase returned by reader, the identity being cached
// afterwards. The long-running servers use it when no passphrase is set in
// the environment, so that a user who started them from a terminal is not
// asked again for a key a one-shot command already unlocked.
func ResolveActiveUserIdentity(
	ctx context.Context, cfg *config.Config, client *api.Client, reader PassphraseReader,
) (*age.HybridIdentity, error) {
	userKey, err := client.GetActiveKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching user key: %w", err)
	}
	if userKey == nil && machineOf(cfg) == nil {
		// In machine mode a nil key is reported by MachineIdentity.
		return nil, errNoActiveKey(false)
	}

	return ResolveUserIdentity(ctx, cfg, userKey, reader)
}

// UnlockUserIdentity fetches the user's active key and decrypts it with the
// passphrase returned by reader. Unlike ResolveUserIdentity it deliberately
// bypasses the keyring cache: the long-running servers use it for a passphrase
// set in the environment, which must fail fast at startup when wrong rather
// than be masked by a cached identity. The returned identity can then be reused for the life of the process
// (see GetDataroomSessionWithIdentity), so the scrypt runs exactly once.
// For a machine account (cfg.Machine), no passphrase is read: see
// MachineIdentity.
func UnlockUserIdentity(ctx context.Context, cfg *config.Config, client *api.Client, reader PassphraseReader) (
	*age.HybridIdentity, error,
) {
	userKey, err := client.GetActiveKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching user key: %w", err)
	}
	if m := machineOf(cfg); m != nil {
		// A nil key is reported by MachineIdentity as a machine configuration error.
		return MachineIdentity(ctx, m, userKey)
	}
	if userKey == nil {
		return nil, errNoActiveKey(false)
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
// in the token store (auth.Tokens), it returns AlreadyAuthenticated=true without starting a new flow.
func LoginStart(ctx context.Context, baseURL string, httpClient *http.Client) (*LoginStartResult, error) {
	// A store that fails reads as "no token" here: the login that follows
	// rewrites it (an unreadable token.json heals itself). An importer whose
	// store can be locked checks it before calling LoginStart.
	if tok, err := auth.Tokens().Load(); err == nil && tok.Valid() {
		return &LoginStartResult{AlreadyAuthenticated: true, ExpiresAt: tok.Expiry}, nil
	}
	oidcCfg, err := fetchOIDCCached(ctx, baseURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("fetching OIDC config: %w", err)
	}
	dar, err := auth.RequestDeviceCode(ctx, *oidcCfg, httpClient)
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
// LoginStart. On success (Status==PollDone) the token is saved to the token store.
// Callers should wait Interval seconds between calls and add ExtraDelaySecs to
// the interval when Status==PollSlowDown.
func LoginPoll(ctx context.Context, baseURL, deviceCode string, httpClient *http.Client) (*LoginPollResult, error) {
	oidcCfg, err := fetchOIDCCached(ctx, baseURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("fetching OIDC config: %w", err)
	}
	tok, err := auth.PollToken(ctx, *oidcCfg, deviceCode, httpClient)
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
	if err := auth.Tokens().Save(tok); err != nil {
		return nil, fmt.Errorf("saving token: %w", err)
	}

	return &LoginPollResult{Status: PollDone, ExpiresAt: tok.Expiry}, nil
}

// Logout revokes the server-side session (best-effort) and deletes the stored
// token (auth.Tokens). Server revocation errors are returned as non-fatal warnings;
// local deletion failure is fatal.
func Logout(ctx context.Context, baseURL string, httpClient *http.Client) (warnings []error, err error) {
	tok, lerr := auth.Tokens().Load()
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
	if err = auth.Tokens().Delete(); err != nil {
		return warnings, fmt.Errorf("removing token: %w", err)
	}

	return warnings, nil
}
