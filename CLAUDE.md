# CLAUDE.md — retyc-cli

Go CLI for the RETYC platform. Module: `github.com/retyc/retyc-cli`. Go 1.26.

This file is a map and a list of rules. Behaviour is documented for users in `doc/`
(`commands.md`, `configuration.md`, `webdav.md`, `retycfs.md`, `mcp.md`, `mcpb.md`,
`docker.md`, `ci-cd.md`) and for developers in the code comments: read them before
changing a subsystem, and update them with it. Do not copy their content here.

## Layout

```
main.go                  # → cmd.Execute()
cmd/                     # cobra commands, flag/viper binding, output; thin adapters
  root.go                #   root flags, initConfig, PersistentPreRunE, exitCode
  common.go output.go errorjson.go   # shared helpers, --json output, error kinds
  auth.go transfer.go dataroom.go admin*.go config.go version.go
  mcp*.go                #   mcp serve (stdio) + manifest for the MCPB bundle
  fs.go                  #   `fs` group: parent of `webdav serve` and `mount`
  webdav*.go             #   WebDAV adapter over internal/vfs
  mount*.go              #   fs mount (mount_linux.go: runMount / serveMount)
  serve_common.go metastore.go observability.go   # shared by webdav serve and fs mount
internal/
  api/                   # REST client: transport.go (only http.Transport), retry.go (429),
                         #   errorcodes.go, one file per API area
  auth/                  # OIDC device flow, refresh, GetValidToken
  config/                # viper defaults, Config structs, env.go (env-only settings), envfile.go
  crypto/                # AGE helpers (PQ only)
  keyring/               # Linux session keyring cache of the decrypted identity
  service/               # business logic shared by commands and MCP (sessions, uploads, …)
  vfs/                   # file-tree service shared by WebDAV and FUSE (caches, mutations, I/O)
    metastore/           #   MetaStore interface; memstore/ (default), redisstore/ (shared)
  retycfs/               # FUSE driver (linux build tag), go-fuse v2 `fs` API
  metrics/               # Prometheus collectors of `fs mount`, all retycfs_*
  telemetry/             # OpenTelemetry tracing of `fs mount`; env.go is the only reader of OTEL_*
scripts/                 # build-mcpb.sh, benches, start-jaeger.sh, start-redis.sh,
                         #   redis-cache-dump (diagnostic, not released)
```

## Build

| Command | Tag | Config dir | API default |
|---|---|---|---|
| `go build .` | `!prod` | `.retyc/` (CWD, gitignored) | `https://api.triplesfer.traefik.me` |
| `go build -tags prod .` | `prod` | `~/.config/retyc/` | `https://api.retyc.com` |

- `paths_dev.go` / `paths_prod.go` hold `configDir()`, `defaultAPIBaseURL` and the
  build-specific defaults. `RETYC_CONFIG_DIR` overrides the config dir.
- Version: `-ldflags "-X github.com/retyc/retyc-cli/cmd.Version=v1.2.3"` (default
  `dev`). The API answers **426** to a CLI below its minimum version, `dev` included:
  build with a version to test against it.
- `--insecure` / `-k` exists in dev builds only (`cmd/insecure_prod.go`: `const false`;
  a prod build has no `insecure` key at all).
- Docker: scratch image, static `-tags prod` binary, user 1000; see `doc/docker.md`.
- MCPB bundle: `make mcpb`; see `doc/mcpb.md`.

## Conventions

- Code comments in English. No `vendor/`. No auto-commit.
- Run `make lint-fix` after editing code.
- `SilenceUsage` + `SilenceErrors` on root: errors are printed once, by `Execute()`.
- Exit codes (`exitCode`, `cmd/root.go`): 77 no/expired login (`auth.ErrNoToken`,
  `ErrNoRefreshToken`), 78 config (`config.ErrNoKeyPassphrase`,
  `service.ErrWrongKeyPassphrase`, `config.ErrEnvFile`), 75 writes lost at unmount,
  1 otherwise. Supervisors (`retyc-k8s-csi`) rely on 77/78: keep those errors wrapped
  with `%w` up to `RunE`.
- The backend says `share`, the CLI says `transfer`. Do not rename backend routes.
- Say "organization key", never "master key".

## Configuration — the single rule

`config.SetDefaults()` owns the binding. Every viper key `a.b` is settable from
`RETYC_A_B` (prefix mandatory: security). Precedence: flag > env > env file > config
file > default.

- **Adding a key**: `viper.SetDefault` (mandatory, even for a zero value: a key
  without default is invisible to `config show` and to the doc test), a field in
  `Config`, a row in `doc/configuration.md`. Flags are bound to their key in a
  `resolve…` function called from `RunE`, never in `init()`.
- Secrets and pre-viper settings are **not** viper keys: they live in
  `internal/config/env.go` (`RETYC_TOKEN`, `RETYC_KEY_PASSPHRASE`,
  `RETYC_WEBDAV_PASSWORD`, `RETYC_CONFIG_DIR`, `RETYC_ENV_FILE`), read through its
  accessors only. A new one needs its `Env…Name` constant there and a doc row.
- Enforced by tests: `TestRetycEnvReadOnlyHere` (no `os.Getenv("RETYC_…")` outside
  `internal/config`), `TestEnvVarsDocumented` (every key and env var in
  `doc/configuration.md`).
- `OTEL_*` / `TRACEPARENT` / `TRACESTATE` are read only in `internal/telemetry/env.go`.
- Tests touching viper isolate themselves: `resetViper` (config), `isolateConfig` (cmd).
- `config.Load` validates ranges and refuses removed keys (`removedKeys`, e.g. the
  former `webdav.cache.*`).
- Env file (`--env-file` / `RETYC_ENV_FILE`, `envfile.go`): `RETYC_*` names only, mode
  0600 required, real env wins, applied in `cobra.OnInitialize` before viper. Errors
  never quote a line (it may be the secret). Details in `doc/configuration.md`.
- `config show` masks `secretKeys` (the Redis URL among them).

## Output (`--json`)

stdout = results only, stderr = everything else (prompts, progress, warnings).

- Branch `if jsonOutput { return printJSON(v) }` where human formatting starts.
- Reuse tagged `api.*` structs; **never add `json` tags to `internal/service` result
  structs** (the MCP server marshals them as they are): add a view type in
  `cmd/output.go`.
- Prompts go through `confirm()` (with `--json` and no `--yes`: `errJSONNeedsYes`).
- Empty lists are `[]`, never `null`.
- Errors: `{"error", "kind", …}` (`cmd/errorjson.go`); a `kind` is never renamed, the
  table is in `doc/commands.md`.

## HTTP

- `api.BaseTransport(insecure)` (`internal/api/transport.go`) is the **only** place an
  `http.Transport` is built (proxy from env, `SSL_CERT_FILE` / `SSL_CERT_DIR` added to
  the system pool, TLS ≥ 1.2). The OIDC client (`newHTTPClient`) and `api.New` both use
  it. HTTP/2 only, one multiplexed connection: concurrency settings bound backend load.
- `InitTLSRoots()` runs in `rootCmd.PersistentPreRunE`, skipped by `annotationOffline`
  commands. **Never add a `PersistentPreRun(E)` to a subcommand or group** (cobra would
  run it instead of the root's).
- `--debug` prints every request and response body to stderr; proxy credentials are
  redacted.
- Rate limit (`internal/api/retry.go`): 429 is replayed (ingress limit, safe for every
  method) with a per-client `throttleGate`, bounded by `api.retry.max_wait` /
  `max_attempts`, then `*api.RateLimitError`. Request bodies must be rebuildable
  (`bytes.Reader`, `strings.Reader`…), never a stream. Tests never sleep (`fakeClock`).
  `webdav serve` answers 429 + `Retry-After` (`cmd/webdav_ratelimit.go`), which
  requires API errors to stay wrapped through `vfs`.
- Errors: `api.HTTPError{Status, Body, Code}`. **Branch on `api.ErrorCode(err)`** (the
  `X-Error-Code` header, constants in `errorcodes.go`); read `detail` only as the
  fallback for an API that sends no code. `errors.Is` matches `ErrNotFound`,
  `ErrConflict`, `ErrGone`, `ErrRateLimited`…

## Auth

`auth.GetValidToken` is the single entry point (stored token → refresh → `ErrNoToken` /
`ErrNoRefreshToken`). Token in `<configDir>/token.json`, mode 0600. OIDC settings are
fetched at runtime (`api.FetchOIDCConfig`), not defaults. Admin commands use an
organization API key as a static bearer token.

## Crypto — AGE post-quantum only

MLKEM768-X25519 hybrid only (`AGE-SECRET-KEY-PQ-1…`, `age1pq1…`), no X25519.

- The user's identity is the scrypt-encrypted `PrivateKeyEnc` of their active key,
  cached in the Linux session keyring (TTL `keyring.ttl`).
- Transfer: fresh session keypair per transfer, its private key encrypted for the user
  and, through an ephemeral key, for the transfer passphrase.
- Dataroom: one permanent session keypair; `session_private_key_enc` re-encrypted for
  all members on every member change (rekey). Names, types and chunks are encrypted for
  the session public key. `name_hash = SHA-256(nameSalt + name)` (salt empty on old
  datarooms).
- Formats: chunks = raw binary AGE; metadata (names, types, keys) = armored AGE.
- Admin: the organization identity is a local file, never fetched, no passphrase.

## API behaviour that code must respect

- Node kinds: `IsFolder()` / `IsSymlink()` / `IsFile()` are the only tests (never test
  `TypeEnc`; `!IsFolder()` is not "file").
- MIME types: per-dataroom table; read through `sess.mimeTypeOf`, write through
  `sess.withMIME` (falls back to legacy `type_enc`).
- Legacy API detection: the first `GET /mime-types` of a session (404 without code →
  legacy for good). The CLI must keep working against an API that predates node types
  and lookup by name hash.
- Uploads: ≤ 8 MiB (`service.SmallUploadMaxSize`, one chunk) → one multipart request
  (`POST /dataroom/{id}/node/file`); above → node + version + 8 MiB chunks. Version
  creation declares `chunk_count_expected`; the API refuses extra chunks and never
  overwrites one. `api.unsafe_write` is always sent explicitly. Storage refusals:
  `api.IsStorageExceeded`, can happen at any chunk.
- `PUT /dataroom/node/{id}` is `exclude_unset` (`api.NodeUpdate`); `replace: true` only
  on a non-legacy API.
- `access_mode` `"0000"` is a mode, not an absence (`HasMode()`).
- **The chunk size is a property of the version** (8 MiB for this CLI, other values for
  the web app or a copy). Never compute `offset / UploadChunkSize` on the read side.
- Listings and lookups only show complete versions.

## Commands

Behaviour in `doc/commands.md`. Notes for code:

- Chunked transfer and dataroom I/O share `uploadChunks` / `downloadChunks`
  (`cmd/common.go`); concurrency from `service.Concurrency()` (`api.concurrency.*`).
- Dataroom paths use `retyc://<id>/path` with globs per component;
  `resolveDataroomSession` is the single entry point to session material.
- A failed upload discards what it created (`service.DiscardFailedUpload`).
- `dataroom user add/rm` and `admin dataroom user rm` chain a rekey.
- Admin commands: organization API (`<api.base_url>/v1`), scopes
  `organization|dataroom|transfer` × `read|write`.

## internal/vfs

Service layer behind `webdav serve` and `fs mount`, addressed by dataroom ID and
absolute path. Package comments and `doc/webdav.md` / `doc/retycfs.md` describe the
behaviour; the rules:

- **Dependency rule** (`TestDependencyRule`, `deps_test.go`): no `net/http`,
  `x/net/webdav`, go-fuse, cobra, viper, `internal/config` nor `cmd` imported by
  `vfs` or its sub-packages. Settings arrive as plain values in `vfs.Options`; `vfs`
  never reads `service.Concurrency()`. `vfs.Default*` constants mirror `config`
  defaults (`TestVFSDefault…MatchesConfig`).
- Paths are cleaned by `listingKey` only.
- **Errors**: sentinels of `errors.go` are *added* to the original error (`kindError`),
  never substituted, so `errors.Is` still reaches API errors, auth sentinels and
  `ErrRateLimited` (which never gets a sentinel). `ErrNotExist` / `ErrExist` are the
  `os` ones; `cmd` flattens them for x/net/webdav (`webdavErr`).
- **Locking**: the API is never called under `FS.mu`; store reads/writes are (a
  generation check and its write are one step). Sealed nodes are decrypted outside the
  mutex. `Options.Logf` is never called under `FS.mu` (`FS.unlock`).
- `vfs` never writes to stderr: operator messages go to `Options.Logf`.
- Every cache change goes through `editLocked` / `invalidateLocked` /
  `invalidateSubtreeLocked`, which bump generations and drop name entries: a fetch or
  lookup that started before a mutation never stores its answer.
- `FS.Create` reads its `io.Reader` only once the upload is accepted (WebDAV relies on
  it). Uploads take a slot of `UploadConcurrency` across files.
- Test seams: `Options.List`, `Session`, `ListDatarooms`, `ReadChunk`, `ChunkSizeOf`,
  `ChunkSize`, `MaxChunkSize`; `SeedSession`, `SeedDatarooms`. Production sets none.

### metastore / Redis (`cache.store: redis`)

- `vfs` imports `metastore`, never the reverse; `cmd` (`newMetaStore`) is the only
  caller of `redisstore.New`. `metastore` imports the standard library only.
- The Redis URL carries the password: never in an error, log, span or metric
  (`Store.fail` strips it).
- An absent key always means "invalid" (eviction-safe): values carry the tokens of
  their ancestors; a write is refused when its generation moved or is absent.
- Writes are Lua scripts (`lua/*.lua`), every key passed through `KEYS[]`, run with
  `EVALSHA`→`EVAL` (nothing loaded at startup). The dataroom list never goes to Redis.
- Wire format (`wire.go`): fields are only added at the end of their block; anything
  else is a new `wireVersion`. Malformed input reads as absent, never panics
  (`FuzzDecodeNode`). Update `describe.go` with any format change.
- High confidentiality stores the API's ciphertexts; nothing is encrypted for the store.
- Tests need `REDISSTORE_TEST_URL` (`scripts/start-redis.sh`); skipped without it,
  **failed when `CI` is set**. Each test uses a random prefix, never `FLUSHDB`.

## WebDAV (`retyc fs webdav serve`)

`cmd/webdav*.go` parses WebDAV, calls `vfs`, maps errors to statuses. Only the command
path carries `fs`: keys stay `webdav.*` / `cache.*`, env `RETYC_WEBDAV_*`. Tests build
handlers with `newWebdavHandler`, never a bare `webdav.Handler`. Symlinks are hidden
(`HideSymlinks`). `COPY`, `LOCK` mirroring and the executable property are custom
(`webdav_copy.go`, `webdav_locks.go`, `webdav_chmod.go`).

## FUSE driver (`retyc fs mount`, `internal/retycfs`)

Linux only: every file but `doc.go` has `//go:build linux`; `cmd/mount_other.go`
answers "Linux only". Imports `vfs`, go-fuse, and `api` / `auth` for sentinels only.
User doc: `doc/retycfs.md`. Rules:

- **State lives in `inodeTable`, never in the object a `Lookup` returns** (go-fuse
  keeps the first object of an inode). Inode numbers are never reused.
- **Paths never come from go-fuse's tree**: use `inodeState.at` via `dirNode.path()` /
  `withPath`.
- **Notifications are sent from the `notifier` goroutine**, never from a handler
  (deadlock), `contentNow` excepted.
- **Every handler starts with `defer c.end(&errno)`** (recover + access log + metrics)
  and **guards its context** (`call.guard`): only the kill of the caller or the end of
  the drain interrupts an operation.
- `toErrno` (`errno.go`) is the only error mapping; never `ENOSYS`.
- One `vfs.Spool` per inode while written; writes go through `Spool.Flush` on the flush
  of handles that send. No writeback cache. The tree is built with `MaxStale` zero.
- Access log, spans and logs carry identifiers only, never a name or path.
- Tests mount against `fakeAPI`; `requireFUSE` skips without `/dev/fuse` /
  `fusermount3` and **fails when `CI` is set**.

## Observability

`retyc fs mount` only: no other command (WebDAV, MCP, one-shot) exposes metrics,
probes or traces. Shared code (`vfs`, `service`, `api`) still observes and opens
spans: unregistered collectors and the no-op tracer cost nothing elsewhere.

- Metrics (`internal/metrics`): one prefix, `retycfs_`. Declare in `metrics.go`, add
  to `all`, observe at the event, document in `doc/retycfs.md`. Labels stay bounded
  (routes through `metrics.NormalizeRoute`, never an ID or path). Registered only by
  the observability listener of the mount (`--metrics-addr`, `cmd/observability.go`).
- Tracing (`internal/telemetry`): `telemetry.Init` is called by `runMount` only; off
  unless an OTLP endpoint is set. Attribute keys live in `attrs.go`, never spelled at
  call sites. One root span per FUSE operation that reaches the API
  (`StartUsedRoot`).
- **Privacy rule** (`cmd/tracing_privacy_test.go`, `telemetrytest.AssertNoLeak`): no
  span name, attribute, event, status or resource carries a path, file or folder name,
  dataroom title, command argument, HTTP body or header, error message or e-mail.
  Errors are `error.type` only. No `otelhttp` on the server, no
  `resource.WithProcess()`.

## CI

`main.yml` → `_ci.yml` (vet, race tests with `fuse3` installed and a `redis:8.10.2`
service, dev + prod builds) → `_docker.yml`. `release.yml` on `v*` tags: goreleaser,
MCPB bundle, GitHub release. See `doc/ci-cd.md`.
