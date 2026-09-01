# CLAUDE.md — retyc-cli

## Project

Go CLI for the RETYC platform. Module: `github.com/retyc/retyc-cli`

## Structure

```
main.go                        # Entry point — calls cmd.Execute()
cmd/
  root.go                      # cobra root, --config / --insecure / --debug flags, viper init
  auth.go                      # auth login / logout / status + newHTTPClient + debugTransport
  common.go                    # Shared helpers: constants, newAPIClient, resolveUserIdentity,
                               #   newTransferBar, uploadChunks, downloadChunks
  transfer.go                  # transfer ls/info/create/download/enable/disable
  dataroom.go                  # dataroom commands (ls, cp, mv, rm, mkdir, create, info, user)
  admin*.go                    # admin org/member/blacklist/dataroom/transfer (organization API key auth)
  mcp.go                       # mcp serve (stdio MCP server) + tool registry
  mcp_manifest.go              # mcp manifest — full MCPB manifest.json (version + tools injected)
  mcpb_manifest_base.json      # static MCPB manifest metadata (go:embed into mcp_manifest.go)
  version.go                   # version command (shows version + build mode)
internal/
  auth/oidc.go                  # DeviceFlow, Refresh, GetValidToken
  api/
    client.go                   # Authenticated REST client (oauth2 transport)
                                #   Get, Post, Put, Patch, Delete, PostMultipartChunk, GetBytes
    login.go                    # FetchOIDCConfig (unauthenticated, GET /login/config/public)
    transfer.go                 # Transfer types + ListTransfers, GetTransferDetails,
                                #   ListFiles, CreateShare, CreateFile, UploadChunk,
                                #   CompleteTransfer, DisableTransfer, EnableTransfer
    dataroom.go                 # Dataroom types + all dataroom API methods
    user.go                     # UserKey type + GetActiveKey
    admin*.go                   # Admin* types + Admin* API methods (org/member/blacklist/dataroom/transfer)
  service/
    admin*.go                    # AdminListNodes, AdminDownloadNodes, AdminRekeyDataroom/Transfer, LoadAdminIdentity
  config/
    config.go                   # Structs, SetDefaults(), Load(), token persistence
    paths_dev.go                # configDir() + defaultAPIBaseURL for dev
    paths_prod.go               # configDir() + defaultAPIBaseURL for prod
  crypto/age.go                 # AGE encrypt/decrypt helpers (PQ-only, see below)
  keyring/keyring.go            # Linux kernel session keyring cache (TTL-based)
mcpb/icon.png                   # MCPB bundle icon (512×512)
scripts/build-mcpb.sh           # Builds dist/retyc-<version>.mcpb from goreleaser dist/ (jq+zip, no Node)
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

Progress bar per file (`schollz/progressbar/v3`), via `newTransferBar(name, size)` in `cmd/common.go`.

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

## Shared chunk helpers (`cmd/common.go`)

Upload and download chunk logic is factored out of both transfer and dataroom commands:

- **`uploadChunks(ctx, f, size, displayName, sessionPubKey, uploadFn)`** — reads the file
  sequentially in 8 MB chunks, encrypts each, dispatches to `uploadFn` with a semaphore
  (4 concurrent goroutines). Progress bar via `newTransferBar`.
- **`downloadChunks(ctx, outputDir, name, size, chunkCount, identity, downloadFn)`** —
  downloads chunks via `downloadFn` concurrently (4 goroutines), decrypts, writes in order
  using a reorder buffer. Creates the output file.

Both `uploadTransferFile` and `uploadDataroomFile` call `uploadChunks` with their respective
API method as `uploadFn`. Same for the download pair.

## Dataroom commands

All node operations use the **`retyc://dataroom_id/path`** URI scheme. Path components support
glob patterns (`*`, `?`, `[...]`) resolved against decrypted node names at each level.

### `dataroom ls [retyc://id[/path]]`
- No arg: lists all datarooms (ID, title, created date)
- With URI: lists nodes at that path. Glob → filtered listing. Requires crypto (decrypts names).

### `dataroom cp <src...> <dst>`
Direction detected from which argument is a `retyc://` URI:
- **Upload** (`local → retyc://`): one or more local paths, last arg is remote dest folder.
  Directories are uploaded recursively (BFS). SIGINT cancels and deletes any orphaned node
  created mid-upload (`DeleteDataroomNode`).
- **Download** (`retyc:// → local`): one remote path (or glob) → local dir. Directories in
  glob results are skipped with a warning.
- 409 on upload → existing node found by name → new version created instead.

Flags: `--yes`/`-y`

### `dataroom mv retyc://id/src retyc://id/dst`
Rename or move within the same dataroom. Resolves both paths, re-encrypts the name with the
session public key, calls `PUT /dataroom/node/{id}`.

### `dataroom rm retyc://id[/path] [-y]`
- **`retyc://id`** (path = `/`): deletes the entire dataroom. No crypto needed — calls `DELETE /dataroom/{id}` directly.
- **`retyc://id/path`**: deletes a single node.
- **Glob** (`retyc://id/*.log`): lists matching nodes (type + name) before confirmation, then deletes each.

### `dataroom mkdir retyc://id/path`
Creates directory node. Parent path must exist.

### `dataroom create --title <title>`
1. `GET /user/me/key/active` → user's public key
2. Generate session keypair
3. `EncryptStringForKeys(sessionPrivKey, [userPublicKey])` → `session_private_key_enc`
4. `POST /dataroom/` with title, session_private_key_enc, session_public_key

### `dataroom info <id>`
Parallel fetch of `GET /dataroom/{id}`, `GET /dataroom/{id}/stats`,
`GET /dataroom/{id}/users`. Displays metadata, file count, encrypted size, and users with roles.

### `dataroom user add <dr_id> <email> [--role viewer|editor|admin]`
### `dataroom user rm <dr_id> <user_id>`
Both commands decrypt the session key, perform the add/remove, then **rekey the dataroom**:
re-encrypt `session_private_key_enc` for all current users via
`PUT /dataroom/{id}/users/rekey`. This grants access to the new user (or revokes it).

## Dataroom crypto — key chain

Each dataroom has a **permanent session keypair** (not ephemeral per operation):

```
user passphrase
  └─ DecryptToStringWithPassphrase(userKey.PrivateKeyEnc) → AGE user identity

dataroom session keypair (generated once at dataroom creation)
  ├─ session_private_key_enc = EncryptStringForKeys(sessionPrivKey, allUsersPublicKeys)
  │                            → re-encrypted on every user add/remove (rekey)
  └─ session_public_key      → used to encrypt all node names, types, and file chunks

node name_hash = SHA-256(nameSalt + filename)  ← nameSalt decrypted from node_name_salt_enc
node name_enc  = EncryptStringForKeys(filename, [sessionPublicKey])   ← armored AGE
node type_enc  = EncryptStringForKeys(mimeType, [sessionPublicKey])   ← armored AGE (files only)
file chunks    = EncryptBinaryForKey(chunk, sessionPublicKey)          ← raw binary AGE
```

`resolveDataroomSession(ctx, cfg, client, dataroomID)` is the single entry point for obtaining
the session material. Returns `*dataroomSession{Identity, PublicKey, PrivateKey, NameSalt}`.
Fetches dataroom + user key concurrently (with internal spinner), stops spinner before passphrase
prompt, decrypts the session key, then decrypts `node_name_salt_enc` if present. All node
commands call this. The `NameSalt` is "" for datarooms that pre-date the salt field.

## Admin commands (`retyc admin`)

Organization administration through the public API (`<api.base_url>/v1`,
OpenAPI at `/v1/openapi.json`). Auth: organization API key (`ryc_...`) as a
bearer token — the existing `api.Client` is reused with
`oauth2.StaticTokenSource`. Scopes: `organization|dataroom|transfer` ×
`read|write`; on 403 the CLI hints at `retyc admin org scopes`.

Config (`admin:` section / env):
- `admin.api_key` / `RETYC_ADMIN_API_KEY` — required by all admin commands
- `admin.private_key_file` / `RETYC_ADMIN_PRIVATE_KEY_FILE` — organization
  organization AGE PQ identity file; only required by decrypt/rekey commands
- `admin.base_url` — default `<api.base_url>/v1`

Crypto: the organization private key stays local (never fetched, no passphrase, no
keyring). `service.ResolveAdminDataroomSession` decrypts
`session_private_key_enc` with it (NameSalt empty — admin is read-only on
nodes, no name_hash). Rekey (dataroom + transfer): decrypt session key with
the organization identity, re-encrypt with `expected_public_key` (falling back to
`public_key`) of every current member/recipient — service account included,
keyless external recipients skipped (their passphrase access is separate) —
then PUT the blob; the server stores it as-is. `admin dataroom user rm`
chains a rekey automatically.

`admin dataroom download <id> [glob]` recreates the dataroom's folder tree
under the output directory (`-o`, default `.`) — files are written at their
relative path, not flattened; folders matched by the glob are skipped
(admin download does not recurse into them).

Command groups: `admin org` (info/update/scopes), `admin member`
(ls/info/role/enable/disable/rm — rm warns when membership is MANAGED),
`admin blacklist` (ls/add/rm), `admin dataroom`
(ls/info/activity/nodes/download/chown/user rm/rekey/rm), `admin transfer`
(ls/info/tracking/disable/enable/rm --force/rekey).

`admin export-all-data <output_dir>` (`service.AdminExportAll`) exports the
whole organization for data reversibility: `export.json` manifest,
`organization.json`, `members.json` (with identity details),
`blacklist_domains.json`, and per dataroom `meta.json` + `messages/N.json`
(one file per activity page, chat decrypted when possible) + `data/`
(decrypted tree via `AdminDownloadNodes`). Output dir must be missing or
empty. Undecryptable datarooms keep meta+messages, are listed as skipped in
the manifest; per-dataroom failures are recorded and the export continues
(non-zero exit at the end). Transfers excluded (no admin file download).

## MCPB bundle (Claude Desktop extension)

`make mcpb` → goreleaser snapshot + `scripts/build-mcpb.sh` → `dist/retyc-<version>.mcpb`.
Single fat bundle: macOS universal binary (goreleaser `universal_binaries`), linux amd64,
windows amd64, selected via manifest `platform_overrides` (MCPB has no arch dimension).
`retyc mcp manifest` generates the full manifest.json (base embedded from
`cmd/mcpb_manifest_base.json`, version from ldflags with `v` stripped, tools from the live
registry). Release CI builds it after goreleaser, asserts manifest version == tag
(`--expect-version`), validates with `npx @anthropic-ai/mcpb validate`, uploads to the
release. Reference: `doc/mcpb.md`.

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
- Always perform linting with `make lint-fix` after editing code (uses `golangci-lint` with `--fix` to auto-apply simple fixes)
