# CLAUDE.md — retyc-cli

## Project

Go CLI for the RETYC platform. Module: `github.com/retyc/retyc-cli`

## Structure

```
main.go                        # Entry point — calls cmd.Execute()
cmd/
  root.go                      # cobra root, --config / --insecure / --debug flags, viper init
  auth.go                      # auth login / logout / status + newHTTPClient + debugTransport
  transfer.go                  # transfer ls/info/create/download/enable/disable
  version.go                   # version command (shows version + build mode)
internal/
  auth/oidc.go                  # DeviceFlow, Refresh, GetValidToken
  api/
    client.go                   # Authenticated REST client (oauth2 transport)
                                #   Get, Post, Put, Delete, PostMultipartChunk, GetBytes
    login.go                    # FetchOIDCConfig (unauthenticated, GET /login/config/public)
    transfer.go                 # Transfer types + ListTransfers, GetTransferDetails,
                                #   ListFiles, CreateShare, CreateFile, UploadChunk,
                                #   CompleteTransfer, DisableTransfer, EnableTransfer
    user.go                     # UserKey type + GetActiveKey
  config/
    config.go                   # Structs, SetDefaults(), Load(), token persistence
    paths_dev.go                # configDir() + defaultAPIBaseURL for dev
    paths_prod.go               # configDir() + defaultAPIBaseURL for prod
  crypto/age.go                 # AGE encrypt/decrypt helpers (PQ-only, see below)
  keyring/keyring.go            # Linux kernel session keyring cache (TTL-based)
Dockerfile                      # Multi-stage scratch image (golang:1.24 builder → scratch)
.dockerignore
.github/workflows/ci.yml        # CI + release workflow
```

## Build modes

Two mutually exclusive build tags control config location, `BuildMode` constant, and default API URL.

| Command | Tag | Config dir | API default | `retyc version` |
|---|---|---|---|---|
| `go build .` | `!prod` (default) | `.retyc/` (CWD) | `https://api.triplesfer.traefik.me` | `x.y.z (dev build)` |
| `go build -tags prod .` | `prod` | `~/.config/retyc/` | `https://api.retyc.com` | `x.y.z (prod build)` |

Override config dir at runtime: `RETYC_CONFIG_DIR=/some/path retyc ...`

`defaultAPIBaseURL` is defined in `paths_dev.go` / `paths_prod.go` (not in `config.go`).

## Version injection

`cmd.Version` is set via ldflags at build time:

```bash
go build -tags prod -ldflags "-X github.com/retyc/retyc-cli/cmd.Version=v1.2.3" .
```

Default value is `"dev"`. CI injects `github.ref_name` on tag pushes.

## Docker

Multi-stage scratch image — builder `golang:1.24`, final `scratch`:
- `CGO_ENABLED=0` static binary, `-tags prod`, ldflags version injection via `ARG VERSION`
- Copies only: binary, CA certs, `/etc/passwd`, `/home/retyc` (with `.config/retyc/` pre-created)
- Non-root user `retyc` (uid 1000), `VOLUME ["/home/retyc/.config/retyc"]`

```bash
docker build --build-arg VERSION=v1.2.3 -t retyc-cli:v1.2.3 .
docker run -it --rm -v retyc-config:/home/retyc/.config/retyc retyc-cli:v1.2.3 auth login
```

## Key defaults (API)

Registered via `viper.SetDefault` in `SetDefaults()` in `internal/config/config.go`.
All overridable from `~/.config/retyc/config.yaml` (prod) or `.retyc/config.yaml` (dev).

- Device auth URL: `.../protocol/openid-connect/auth/device`
- API base URL: per build mode (see above)
- Keyring: enabled by default, TTL 3600s (configurable via `keyring.enabled` / `keyring.ttl`)

## Persistent flags (root)

| Flag | Short | Default | Description |
|---|---|---|---|
| `--insecure` | `-k` | false | Skip TLS verification (self-signed certs) |
| `--debug` | `-d` | false | Print all HTTP requests + raw responses to stderr |
| `--config` | | auto | Override config file path |

`--debug` covers **all** HTTP traffic: API calls (via `api.Client.do` / `GetBytes`) and unauthenticated calls (`FetchOIDCConfig`, device flow, token refresh) via `debugTransport` wrapping the `*http.Client` RoundTripper in `newHTTPClient`.

Format: `> METHOD URL` then `< STATUS` + pretty-printed JSON body (or `(N bytes, binary)` for binary).

## TLS self-signed certificates

Use `--insecure` / `-k` (persistent flag on root) to skip TLS verification.
Applies to both the OIDC device flow HTTP client and the API REST client.
`InsecureSkipVerify` is annotated `#nosec G402` where used.

## Auth flow

`GetValidToken(ctx, cfg, httpClient)` in `internal/auth/oidc.go` is the single
entry point for obtaining a valid token:
1. Loads stored token → return if valid
2. If expired + refresh token present → `Refresh()` → save → return
3. Otherwise → `ErrNoToken` or `ErrNoRefreshToken` (callers re-run device flow)

Tokens are stored in `<configDir>/token.json` with permissions `0600`.

## Crypto — AGE post-quantum only

All keys use **MLKEM768-X25519 hybrid** (post-quantum). No legacy X25519 support.

- Private keys: `AGE-SECRET-KEY-PQ-1…` parsed with `age.ParseHybridIdentity`
- Public keys: `age1pq1…` parsed with `age.ParseHybridRecipient`

### Key chain for `transfer create`

```
user passphrase
  └─ DecryptToStringWithPassphrase(userKey.PrivateKeyEnc) → AGE identity
       (cached in Linux session keyring, TTL configurable)

session keypair (generated fresh per transfer)
  ├─ session_private_key_enc   = Encrypt(sessionPrivKey, userKey.PublicKey)
  │                              → allows transfer info to decrypt later
  ├─ session_public_key        → used to encrypt file chunks + metadata + message
  │
  └─ ephemeral keypair (generated fresh per transfer)
       ├─ ephemeral_private_key_enc = EncryptWithPassphrase(ephPrivKey, transferPassphrase)
       └─ session_private_key_enc_for_passphrase = Encrypt(sessionPrivKey, ephPublicKey)
            → allows recipient access via transfer passphrase
```

### Encryption formats

| Data | Format | Function |
|---|---|---|
| File chunks | **Raw binary AGE** (no armor) | `EncryptBinaryForKey(data, pubKey)` |
| Metadata (`name_enc`, `type_enc`, `message_enc`, key fields) | **Armored AGE** | `EncryptStringForKeys(value, []pubKeys)` |
| `ephemeral_private_key_enc` (passphrase) | **Armored AGE** scrypt | `EncryptWithPassphrase(data, passphrase)` |
| `userKey.PrivateKeyEnc` (from API) | **Armored AGE** scrypt | `DecryptToStringWithPassphrase(...)` |

### Keyring (`internal/keyring`)

Caches the decrypted AGE identity string in the **Linux kernel session keyring**
(`KEY_SPEC_SESSION_KEYRING`). Shared across all processes in the same terminal session.
Uses `unix.AddKey` + `KEYCTL_SET_TIMEOUT`. TTL and enable/disable via config.

## Transfer commands

### `transfer ls [--sent|--received]`
Lists transfers (default: sent). Tabwriter output. No crypto needed (title is plaintext).

### `transfer info <id>`
Fetches `GET /share/{id}/details` + `GET /user/me/key/active` in parallel.
Decrypts crypto chain → displays message and file list with decrypted names/sizes.
Displays `web_url` from `ShareDetailsResponse`. Passphrase cached in keyring after first use.

### `transfer create [flags] file...`
Full flow:
1. Stat files → show confirmation summary (bypass with `--yes` / `-y`)
2. Prompt transfer passphrase (or `--passphrase`)
3. `GET /user/me/key/active` → user's public key
4. `POST /share` (`use_passphrase=true`, no email recipients for now)
5. Generate session + ephemeral keypairs
6. Encrypt keys (see key chain above)
7. `POST /share/{id}/file` + chunk upload in **8 MB** chunks (`POST /file/{id}/{chunk}`, multipart)
   — **4 concurrent uploads** per file (semaphore pattern, `uploadConcurrency = 4`)
   — main goroutine reads+encrypts sequentially; each encrypted chunk is dispatched immediately
8. `PUT /share/{id}/complete`
9. `GET /share/{id}/details` → display `web_url`

Progress bar per file (`schollz/progressbar/v3`), reusable via `newTransferBar(name, size)`.

Flags: `--title`, `--expire` (seconds, default 3600), `--message`, `--passphrase`, `--yes`/`-y`

### `transfer download <id> [-o dir] [-y]`
Downloads and decrypts all files of a transfer into a local directory.
- **4 concurrent downloads** per file (`downloadConcurrency = 4`)
- Reorder buffer (`map[int][]byte`) ensures chunks are always written to disk in order (0→1→2→…)
  regardless of network arrival order
- On error: context cancellation propagated to all workers, channels drained cleanly

### `transfer disable <id>` / `transfer enable <id>`
- disable → `DELETE /share/{id}`
- enable → `PUT /share/{id}/re-enable`

## API — backend nomenclature

The backend uses `share` internally (`/share`, `ShareModel`, etc.).
The CLI exposes everything as `transfer`. Do not rename backend routes.

## Dependencies

| Package | Purpose |
|---|---|
| `github.com/spf13/cobra` | CLI commands |
| `github.com/spf13/viper` | Config file + env var binding |
| `golang.org/x/oauth2` | Token struct + authenticated HTTP transport |
| `filippo.io/age` | AGE PQ encryption (MLKEM768-X25519) |
| `golang.org/x/sys/unix` | Linux kernel keyring syscalls |
| `golang.org/x/term` | Password prompt without echo |
| `github.com/schollz/progressbar/v3` | Upload/download progress bars |

## CI

- **`ci` job**: runs on push/PR to main/master and on tag pushes → vet, test (race), build dev + prod
- **`release` job**: runs only on `v*` tags, needs `ci` → prod build with ldflags → `gh release create`

## Conventions

- All code comments in **English**
- No `vendor/` directory — dependencies fetched from module cache
- `.retyc/` in CWD is gitignored (dev token/config should not be committed)
- `SilenceUsage: true` + `SilenceErrors: true` on rootCmd — errors printed once by `RunE`, not by cobra
- No auto-commit
