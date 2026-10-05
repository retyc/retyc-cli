# CLAUDE.md — retyc-cli

## Project

Go CLI for the RETYC platform. Module: `github.com/retyc/retyc-cli`

## Structure

```
main.go                        # Entry point — calls cmd.Execute()
cmd/
  root.go                      # cobra root, --config / --debug / --json flags, viper init
  insecure_dev.go              # --insecure / -k, dev builds only (insecure_prod.go: const false)
  auth.go                      # auth login / logout / status + newHTTPClient + debugTransport
  common.go                    # Shared helpers: constants, newAPIClient, resolveUserIdentity,
                               #   newTransferBar, uploadChunks, downloadChunks
  output.go                    # --json support: printJSON, printError, confirm, JSON view types
  transfer.go                  # transfer ls/info/create/download/enable/disable
  dataroom.go                  # dataroom commands (ls, cp, mv, rm, mkdir, create, info, user)
  admin*.go                    # admin org/member/blacklist/dataroom/transfer (organization API key auth)
  webdav_metrics.go            # webdav serve observability listener: /metrics (Prometheus,
                               #   dedicated registry), /healthz, /readyz, webdavHealth state,
                               #   instrumentWebdav middleware, sessionsCachedGauge
  mcp.go                       # mcp serve (stdio MCP server) + tool registry
  mcp_manifest.go              # mcp manifest — full MCPB manifest.json (version + tools injected)
  mcpb_manifest_base.json      # static MCPB manifest metadata (go:embed into mcp_manifest.go)
  config.go                    # config path / config show — effective values, secrets masked
  version.go                   # version command (shows version + build mode)
internal/
  auth/oidc.go                  # DeviceFlow, Refresh, GetValidToken
  api/
    client.go                   # Authenticated REST client (oauth2 transport)
                                #   Get, Post, Put, Patch, Delete, PostMultipartChunk, GetBytes
    transport.go                # BaseTransport (env proxy + custom root CAs) + InitTLSRoots
    login.go                    # FetchOIDCConfig (unauthenticated, GET /login/config/public)
    transfer.go                 # Transfer types + ListTransfers, GetTransferDetails,
                                #   ListFiles, CreateShare, CreateFile, UploadChunk,
                                #   CompleteTransfer, DisableTransfer, EnableTransfer
    dataroom.go                 # Dataroom types + all dataroom API methods
    user.go                     # UserKey type + GetActiveKey
    admin*.go                   # Admin* types + Admin* API methods (org/member/blacklist/dataroom/transfer)
  service/
    session_cache.go             # SessionCache (process-lifetime dataroom sessions, single-flight, one scrypt at a
                                 #   time) + EnableSessionCache() used by mcp serve; webdav serve holds its own instance
    admin*.go                    # AdminListNodes, AdminDownloadNodes, AdminRekeyDataroom/Transfer, LoadAdminIdentity
  config/
    config.go                   # Structs, SetDefaults(), Load(), token persistence
    env.go                      # Env-only settings kept out of viper (secrets, RETYC_CONFIG_DIR)
    paths_dev.go                # configDir() + defaultAPIBaseURL for dev
    paths_prod.go               # configDir() + defaultAPIBaseURL for prod
  crypto/age.go                 # AGE encrypt/decrypt helpers (PQ-only, see below)
  metrics/                      # Prometheus metric declarations (retyc_cli_* / retyc_cli_webdav_*),
                                #   Register(reg), NormalizeRoute, RoundTripper (API client wrapper)
  telemetry/                    # OpenTelemetry tracing: env.go (only OTEL_*/TRACEPARENT reads), Init/Shutdown,
                                #   RoundTripper (API spans), privacy helpers; telemetrytest/ for tests
  keyring/keyring.go            # Linux kernel session keyring cache (TTL-based)
mcpb/icon.png                   # MCPB bundle icon (512×512)
scripts/build-mcpb.sh           # Builds dist/retyc-<version>.mcpb from goreleaser dist/ (jq+zip, no Node)
scripts/webdav-bench.sh         # Benchmark small-file writes through `retyc webdav serve` 
scripts/start-jaeger.sh         # Local Jaeger (OTLP 4318/4317, UI 16686) for manual tracing checks
Dockerfile                      # Multi-stage scratch image (golang:1.26 builder → scratch)
.dockerignore
.github/workflows/            # main.yml + _ci.yml + _docker.yml + release.yml
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

Multi-stage scratch image — builder `golang:1.26`, final `scratch`:
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

- OIDC (issuer, client_id, device_auth_url, token_url, ...): **not** local defaults —
  fetched at runtime by `api.FetchOIDCConfig` (`GET /login/config/public`), which fills
  `config.OIDCConfig`. Nothing in `SetDefaults()` covers them.
- API base URL: per build mode (see above)
- Keyring: enabled by default, TTL 60s (configurable via `keyring.enabled` / `keyring.ttl`)
- Concurrency: `api.concurrency.list` / `.upload` / `.download`, default 4 each, between 1
  and `config.MaxConcurrency` (32) — `config.Load` rejects anything else. The service reads them process-wide through
  `service.Concurrency()`: `applyServiceConfig`, in `rootCmd.PersistentPreRunE`, calls
  `service.SetConcurrency` once and ignores a config that does not load (each command
  reports it itself). The API is HTTP/2 only: one multiplexed connection, so these bound
  backend load, not a connection pool.

## Persistent flags (root)

| Flag | Short | Default | Description |
|---|---|---|---|
| `--insecure` | `-k` | false | Skip TLS verification (self-signed certs). **Dev builds only** — `cmd/insecure_prod.go` defines it as a `const false` |
| `--debug` | `-d` | false | Print all HTTP requests + raw responses to stderr |
| `--config` | | auto | Override config file path |
| `--json` | | false | Results as JSON on stdout, errors as `{"error":...}` on stderr |

## Config, env and flags — the single rule

`internal/config.SetDefaults()` owns the whole binding:

- every viper key `a.b` is settable from `RETYC_A_B`
  (`SetEnvPrefix("RETYC")` + `SetEnvKeyReplacer(".", "_")` + `AutomaticEnv()`).
  The prefix is a security requirement: without it, viper resolved `insecure`
  from a bare `INSECURE` variable, so an unrelated environment variable could
  disable TLS verification. Precedence is flag > env > config file > default.
- `internal/config/env.go` holds the settings that are **deliberately not**
  viper keys — `RETYC_TOKEN`, `RETYC_KEY_PASSPHRASE`, `RETYC_WEBDAV_PASSWORD`
  (secrets: a viper key would also make them settable from `config.yaml`),
  `RETYC_CONFIG_DIR` (read before viper is initialised). Never
  call `os.Getenv("RETYC_...")` outside this file; use the accessors
  `config.Token()`, `config.KeyPassphrase()`, `config.RequireKeyPassphrase()`,
  `config.WebdavPassword()`.
- Both rules are enforced by tests, not just stated here:
  `TestRetycEnvReadOnlyHere` (`internal/config/env_test.go`) walks the syntax
  tree of every `.go` file and fails on `os.Getenv` / `os.LookupEnv` called
  outside `internal/config/` with a `RETYC_` literal, or with a same-file
  constant holding one; `TestEnvVarsDocumented` (`internal/config/config_test.go`)
  fails when a viper key or a `RETYC_` constant of `env.go` is missing from
  `doc/configuration.md`. The env-only list is parsed out of `env.go`, so a new
  env-only variable needs its `Env…Name` constant there and a doc row — nothing
  to update in the tests.
- Not test-enforced, convention only: `OTEL_*`, `TRACEPARENT` and
  `TRACESTATE` are read only in `internal/telemetry/env.go`, never through
  `internal/config`: they are the OTel SDK's contract, not CLI settings, and
  the CLI never parses the endpoint value (it only tests that one is set).
- Tests that call `SetDefaults()` or `initConfig()` must isolate themselves from
  the developer's shell: `resetViper` (`internal/config`) and `isolateConfig`
  (`cmd`) unset every inherited `RETYC_` variable for the test's duration.
- `retyc config show` / `retyc config path` print the effective values and the
  file locations. viper does not report which source won, so `show` is labelled
  "effective value", not "origin". `insecure` is read from the Go variable, not
  viper, because only the variable sees `-k`.
- A config file that exists but fails to load (unreadable `--config` path, YAML
  error) is still skipped — defaults and env apply — but no longer silently:
  `initConfig` keeps the error in `configFileErr`, printed by `config path`
  (`config_file_error` in JSON) and under `--debug`. A missing file in the
  search path (`viper.ConfigFileNotFoundError`) is the normal case, not an error.

Adding a config key: `viper.SetDefault` in `SetDefaults()`, a field in the
`Config` struct, a row in `doc/configuration.md`. Nothing else.

The `SetDefault` is **mandatory, even for a zero value**: `viper.AllKeys()` only
reports keys that carry a default, so a key without one is invisible to
`retyc config show` and to `TestEnvVarsDocumented` — it would silently escape
the documentation check. This is why `insecure` has a `SetDefault(false)` even
though it is a dev-only flag.

## JSON output (`--json`)

Convention: **stdout = results only, stderr = everything else** (prompts, spinners,
progress bars, service warnings, device-flow instructions). `cmd/output.go` holds
`jsonOutput`, `printJSON`, `printError` (used by `Execute()`), `confirm(prompt, yes)`
and the CLI-only JSON view types (`pagedJSON`, `itemsJSON`, `idStatusJSON`,
`transferInfoJSON`, `dataroomNodeJSON`, `rekeyJSON`, ...).

Rules when adding a command:
- Branch `if jsonOutput { return printJSON(v) }` right where human formatting starts.
- Reuse tagged `api.*` structs directly; **never add `json` tags to `internal/service`
  result structs** — they are marshalled as-is by the MCP server and its output must
  not change. Build a view type in `cmd/output.go` instead.
- Confirmation prompts go through `confirm()`: with `--json` and no `--yes` it returns
  `errJSONNeedsYes` instead of prompting.
- Empty lists are `[]`, never `null` (`nonNil`, `newPagedJSON`, `newItemsJSON`).

`--debug` covers **all** HTTP traffic: API calls (via `api.Client.do` / `GetBytes`) and unauthenticated calls (`FetchOIDCConfig`, device flow, token refresh) via `debugTransport` wrapping the `*http.Client` RoundTripper in `newHTTPClient`.

Format: `> METHOD URL` then `< STATUS` + pretty-printed JSON body (or `(N bytes, binary)` for binary).

## TLS, proxy and custom CAs

`api.BaseTransport(insecure)` in `internal/api/transport.go` is the **single**
place where an `http.Transport` is built. Both `cmd/auth.go:newHTTPClient` (OIDC
device flow, refresh, `FetchOIDCConfig`) and `api.New` (all REST traffic) go
through it — never construct an `http.Transport` elsewhere, it would silently
lose the proxy and CA settings.

- **Proxy**: `Proxy: http.ProxyFromEnvironment` → `HTTP_PROXY`, `HTTPS_PROXY`,
  `NO_PROXY` (upper and lower case). `ALL_PROXY` is not supported by Go.
- **Root CAs**: `SSL_CERT_FILE` / `SSL_CERT_DIR` are read explicitly, because Go
  honours them natively on Linux only (`crypto/x509/root_unix.go` excludes
  darwin and windows). The certificates are **added** to `x509.SystemCertPool()`,
  never substituted for it, so a corporate MITM CA does not cost the public
  roots. `SSL_CERT_DIR` accepts several directories, separated by `:` on Unix
  and `;` on Windows (`filepath.SplitList`).
- `platformRoots()` clears both variables around the `x509.SystemCertPool()`
  call. Without it, on Linux, setting **both** variables makes Go replace the
  default file *and* directory lists, so the "system" pool would hold nothing
  but the custom CAs and the union would silently be a replacement. It relies
  on being the first caller of `SystemCertPool()`, which caches on first use.
- `InitTLSRoots()` is called from `rootCmd.PersistentPreRunE`: the bundle is
  loaded and validated once at startup so a bad path fails immediately instead
  of mid-transfer. It returns a description of the roots, printed under `--debug`.
  Commands annotated `annotationOffline` (`version`, `mcp manifest`) skip it —
  they open no connection, and the release CI runs `retyc mcp manifest`.
  Beware: cobra runs only the closest `PersistentPreRun(E)` unless
  `cobra.EnableTraverseRunHooks` is set, so adding one to a subcommand would
  silently skip the CA loading.
- `--debug` prints the proxy used per request through `api.ProxyLabel()`, on
  both the OIDC client (`debugTransport`) and the REST client
  (`Client.do` / `GetBytes`). It calls `url.Redacted()`, so proxy credentials
  never reach the logs.
- `BaseTransport` also pins `MinVersion: tls.VersionTLS12` — a no-op against
  the Go client default, kept explicit for gosec.

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
   — **4 concurrent uploads** per file by default (semaphore pattern, `api.concurrency.upload`)
   — main goroutine reads+encrypts sequentially; each encrypted chunk is dispatched immediately
8. `PUT /share/{id}/complete`
9. `GET /share/{id}/details` → display `web_url`

Progress bar per file (`schollz/progressbar/v3`), via `newTransferBar(name, size)` in `cmd/common.go`.

Flags: `--title`, `--expire` (seconds, default 3600), `--message`, `--passphrase`, `--yes`/`-y`

### `transfer download <id> [-o dir] [-y]`
Downloads and decrypts all files of a transfer into a local directory.
- **4 concurrent downloads** per file by default (`api.concurrency.download`)
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
  (`api.concurrency.upload` goroutines). Progress bar via `newTransferBar`.
- **`downloadChunks(ctx, outputDir, name, size, chunkCount, identity, downloadFn)`** —
  downloads chunks via `downloadFn` concurrently (`api.concurrency.download` goroutines), decrypts, writes in order
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
  Directories are uploaded recursively (BFS). SIGINT or a failed upload discards what the
  upload created (`service.DiscardFailedUpload`): the node if it was new, otherwise only the
  new version (`DeleteDataroomNodeVersion`) — best-effort, deleting needs `can_delete`.
- A file that fits in one chunk (≤ `service.UploadChunkSize`, empty included) goes through
  `service.UploadSmallFile` → `POST /dataroom/{id}/node/file` (operationId
  `createDataroomFileNode`, via `api.Client.CreateDataroomFileNode`, multipart): node + version + the single encrypted chunk in one request, `overwrite=true`
  so an existing file gets a new version, 410 → `ErrNameBeingDeleted`. The server drops a
  failed request: no `DiscardFailedUpload`. WebDAV does the same (`smallWriteHandle`, body
  kept in memory, sent on Close); larger files keep the path below.
- `api.unsafe_write` (default false, `--unsafe-write` on `webdav serve`) is sent as the
  `unsafe_write` query parameter of **both** upload routes, always explicitly (the server's
  default is true): `api.WithUnsafeWrite`, passed by `newAPIClient` and `webdav serve`.
  When true the API answers before the chunk reaches S3 and a failed background store is
  never reported, so a version can be listed complete with a chunk missing. Chunk downloads
  (`api.Client.getChunk`, user and admin routes) retry a 404 after 300 ms then 600 ms (the
  store window is ~450 ms), then return `api.ErrChunkMissing` (also matches `ErrNotFound`);
  a 410 is not retried.
- Version creation announces `chunk_count_expected` = `service.ChunkCount(size)`; the API
  refuses any chunk index beyond it (422) and never overwrites a stored chunk, so
  `UploadChunks` fails when the source does not yield exactly the declared size.
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
4. `POST /dataroom` with title, session_private_key_enc, session_public_key

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
`public_key`) of every current member/recipient — the organization key's own
recipient is always added even when the service account is listed without a
key, keyless external recipients skipped (their passphrase access is separate)
— then PUT the blob; the server stores it as-is. `admin dataroom user rm`
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

## WebDAV server flags

`webdav serve` binds `--addr host:port` (`webdav.addr`, `RETYC_WEBDAV_ADDR`,
default `127.0.0.1:8888`); there is no separate port flag. Like the
`--metrics-*` flags, it is bound to its viper key in `resolveWebdavAddr`,
called from `RunE`, never in `init()`. `isLoopbackAddr` takes the same
`host:port` form.

## Metrics (`webdav serve --metrics-addr`)

`internal/metrics` declares every metric as a package-level collector, observed
where the event happens and registered into the dedicated registry only by
`cmd/webdav_metrics.go:newObservabilityHandler`. Unregistered collectors still
accept observations, so the MCP server and one-shot commands pay nothing.
Prefixes: `retyc_cli_*` for what is not WebDAV-specific (API round trips via
`api.WrapTransport(metrics.RoundTripper)`, token keepalive, per-chunk
crypto), `retyc_cli_webdav_*` for the server (requests, bytes, caches).

Adding a metric: declare it in `internal/metrics/metrics.go`, add it to `all`,
observe it at the event, add a row to `doc/webdav.md`. Labels must stay
bounded: routes go through `metrics.NormalizeRoute`, WebDAV methods outside
the RFC set become `OTHER`, never an ID or a raw path. Collectors that need a
handle on the running server (`retyc_cli_sessions_cached`) are built in `cmd`
and passed to `newObservabilityHandler` through `observabilityOptions.extra`.
`observabilityOptions.runtime` (`--metrics-runtime`, `webdav.metrics.runtime`,
default true) toggles the `go_*` / `process_*` collectors so a parent process
that aggregates several instances (the CSI driver) can drop them;
`observabilityOptions.labels` (`--metrics-label key=value`, repeatable,
`webdav.metrics.labels`, env space-separated) wraps the registerer with
`prometheus.WrapRegistererWith` so every series carries them, and a colliding
or invalid name is an error at startup, not a panic. All three flags bind to
their viper key in `resolveMetrics*`, never in `init()`; `config.Load` copies
the labels through `GetStringSlice` because `Unmarshal` does not split an
environment value.

## Tracing (OpenTelemetry)

`internal/telemetry`. Off unless `OTEL_EXPORTER_OTLP_ENDPOINT` or
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` is set (and `OTEL_SDK_DISABLED` is not
`true`); environment only, no flag, no config key. `http/protobuf` by default,
`grpc` on `OTEL_EXPORTER_OTLP_PROTOCOL=grpc`. `Init` runs in
`rootCmd.PersistentPreRunE`, `run()` closes the command span and flushes
within 2 s; a failed init or export never changes the exit code.
`annotationOffline` commands (`version`, `mcp manifest`) never initialise
tracing, since `Init` runs in `PersistentPreRunE` after that early return.

Span model:
- one-shot command: span `retyc <command path>`, child of `TRACEPARENT`,
  attributes `retyc.command`, `retyc.cli.version`;
- the request or command span is tagged with `retyc.dataroom.id` when a
  dataroom title is resolved (`dataroomCache.idForName`) and `retyc.node.id`
  when a path resolves to a node (`service.resolvePath`): UUIDs only, never
  the title or the name;
- `retyc:long-running` commands (`webdav serve`, `mcp serve`) get no command
  span: `webdav serve` opens `retyc webdav serve init` (child of
  `TRACEPARENT`, ended once the port is bound) then one root `WEBDAV <method>`
  per request (`instrumentWebdav`, `WithNewRoot`, incoming `traceparent`
  ignored); `mcp serve` opens one root `MCP <tool>` per call; `toolErr`
  records the failure on that span;
- API calls: `telemetry.RoundTripper` (installed by `cmd.apiTransport()` on
  every `api.New`, and by `newHTTPClient` for the OIDC client: discovery,
  token refresh, device flow — Keycloak routes are templates, the realm is
  folded; a refresh made by `auth.RefreshingTokenSource` runs on
  `context.Background()`, so each one, e.g. the `webdav serve` keepalive every
  60 s, is a root trace of its own), CLIENT span named by `metrics.NormalizeRoute`, `traceparent`
  injected, route identifiers as named attributes (`retyc.dataroom.id`,
  `retyc.node.id`, `retyc.version.id`, `retyc.transfer.id`, `retyc.file.id`,
  `retyc.chunk.index`, ... keyed by the resource segment before the UUID,
  `retyc.path.params` as the fallback; the upload routes also carry
`retyc.upload.unsafe_write`, read from the `unsafe_write` query parameter — the only
query parameter a span records, and only when it parses as a boolean); `metrics.NormalizeRoute` matches the
  path against `routeTemplates` position by position and folds every `{id}` /
  `{n}` position whatever its value (an identifier equal to a route word is
  folded too); a path matching no template falls back to the vocabulary
  (`routeWords` kept, anything else folded), so a user-typed title or e-mail
  never reaches a span name or the Prometheus `route` label; the span ends when the response
  headers arrive, body streaming is not included;
- crypto and session work are child spans of the current span:
  `crypto.encrypt` / `crypto.decrypt` (one per chunk, `retyc.chunk.index` and
  `retyc.chunk.plaintext_bytes` / `retyc.chunk.ciphertext_bytes`; about 300
  bytes each, so a 1 GB file adds 128 spans next to its 128 chunk POSTs),
  `crypto.decrypt_names` (one per listing, or one per page where pages are
  decrypted as they arrive — `ListNodesByIDWithSession`, the WebDAV path;
  `retyc.node.count`),
  `crypto.unlock_key` (every scrypt: `retyc.key.kind` user|transfer,
  `retyc.key.source` passphrase|keyring, `retyc.cache.hit` on the keyring
  lookup; all sites go through `service.decryptKeyWithPassphrase`,
  never the passphrase), `session.unlock` (one per cached dataroom session
  resolution, i.e. the `webdav serve` / `mcp serve` path through
  `SessionCache.Get`; one-shot commands resolve uncached and emit none);
  cache lookups and path resolution stay events (`cache.lookup`,
  `dataroom.resolve_path`).

Every attribute key lives in `internal/telemetry/attrs.go` under the
`retyc.` prefix (`retyc.chunk.plaintext_bytes` on `crypto.encrypt`,
`retyc.chunk.ciphertext_bytes` on `crypto.decrypt`, `retyc.key.kind`,
`retyc.cache.hit`, ...); instrumentation sites never spell a key literal.

Privacy rule, enforced by `cmd/tracing_privacy_test.go`: no span name,
attribute, event, status description or resource ever carries a WebDAV path,
a file or folder name, a dataroom title, a command argument, an HTTP body or
header, an error message or the user's e-mail. Errors are status `Error` +
`error.type` (`telemetry.RecordError`). No `otelhttp` on the WebDAV server
(it records `url.path`), no `resource.WithProcess()` (it records
`process.command_args`).

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
| `github.com/prometheus/client_golang` | `webdav serve --metrics-addr` exposition (`cmd/webdav_metrics.go`) |

## CI

- **`main.yml`**: orchestrator on push/PR → calls `_ci.yml` (vet, test with race, build dev + prod) then `_docker.yml`
- **`release.yml`**: on `v*` tags only → prod build with ldflags, goreleaser, MCPB bundle, `gh release create`

## Conventions

- All code comments in **English**
- No `vendor/` directory — dependencies fetched from module cache
- `.retyc/` in CWD is gitignored (dev token/config should not be committed)
- `SilenceUsage: true` + `SilenceErrors: true` on rootCmd — errors printed once by `RunE`, not by cobra
- Exit codes: `exitCode` (`cmd/root.go`) returns `exitAuthRequired` (77) when the error wraps
  `auth.ErrNoToken` / `auth.ErrNoRefreshToken`, `exitConfig` (78) for `config.ErrNoKeyPassphrase` /
  `service.ErrWrongKeyPassphrase`, 1 otherwise. Supervisors (`retyc-k8s-csi`) rely on 77/78 to stop
  restarting `webdav serve`: keep those sentinels wrapped (`%w`) up to `RunE`
- No auto-commit
- Always perform linting with `make lint-fix` after editing code (uses `golangci-lint` with `--fix` to auto-apply simple fixes)
