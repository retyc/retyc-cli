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
  fs.go                        # fs group (filesystem access to datarooms); parent of `webdav` and `mount`
  mount.go                     # fs mount: the command, parseMountArgs, the mount.* flags (addMountFlags,
                               #   resolveMountFlags), mountSettings, checkSpoolDir (all platforms)
  mount_linux.go               # runMount: fail-fast checks, vfs.New, retycfs.Mount, serveMount (lifecycle)
  metastore.go                 # newMetaStore: cache.store → nil (vfs's memstore) or a redisstore.Store,
                               #   shared by webdav serve and fs mount
  serve_common.go              # shared by webdav serve and fs mount: serveStartupCheck,
                               #   servePassphraseReader, tokenKeepalive / authWatch (401 → check now)
  mount_other.go               # runMount on the other platforms: "Linux only"
  webdav_ratelimit.go          # webdav serve: api.ErrRateLimited -> 429 + Retry-After (rateLimitStatus)
  observability.go             # observability listener shared by webdav serve and fs mount: /metrics
                               #   (Prometheus, dedicated registry), /healthz, /readyz, serveHealth state,
                               #   metricsSettings + startObservability, sessionsCachedGauge
  webdav_metrics.go            # webdav serve: binding of webdav.metrics.* (resolveMetrics*),
                               #   instrumentWebdav middleware
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
    retry.go                    # retryTransport + throttleGate: replay on 429, RateLimitError, WithRetry
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
    envfile.go                  # --env-file / RETYC_ENV_FILE: parse, permission check, apply to the environment
    paths_dev.go                # configDir() + defaultAPIBaseURL for dev
    paths_prod.go               # configDir() + defaultAPIBaseURL for prod
  crypto/age.go                 # AGE encrypt/decrypt helpers (PQ-only, see below)
  metrics/                      # Prometheus metric declarations (retyc_cli_* / retyc_cli_vfs_* / retyc_cli_webdav_*),
                                #   Register(reg), NormalizeRoute, RoundTripper (API client wrapper)
  telemetry/                    # OpenTelemetry tracing: env.go (only OTEL_*/TRACEPARENT reads), Init/Shutdown,
                                #   RoundTripper (API spans), privacy helpers, used.go (UsedSpan: a root span
                                #   exported only if it got children); telemetrytest/ for tests
  retycfs/                      # FUSE driver, linux build tag (see "FUSE driver"): mount.go (Mount, Server,
                                #   Options), driver.go (driver, call = access log + recover, notifier), inodes.go
                                #   (inodeTable, inodeState), node.go (base, dirNode, linkNode, child, reconcile,
                                #   Setattr, Create / Mkdir / Unlink / Rmdir / Rename), dir.go (dirHandle:
                                #   READDIRPLUS from the listing), file.go (fileNode: open, read, write, flush,
                                #   release), spool.go (openSpool: the one vfs.Spool of an inode, spoolRegistry),
                                #   root.go (allRoot), attr.go, xattr.go, errno.go (toErrno),
                                #   accesslog.go + control.go (.retycfs/accesslog)
  vfs/                          # Service layer shared by WebDAV and the FUSE driver (see "internal/vfs"):
                                #   vfs.go (Options), fs.go (FS, New, sessions), node.go (Node, SplitPath,
                                #   listingKey), errors.go (sentinels), datarooms.go (DataroomCache: titles →
                                #   IDs), listings.go (listing cache: SWR, single-flight, generations, refresh
                                #   slots, ETag), resolve.go (Lookup: listing, Entry, name hash), mutate.go
                                #   (Mkdir, Remove, Rename, Copy), attrs.go (Chmod, SetExecutable,
                                #   SetModTime), quota.go (Quota), locks.go (LockManager), edit.go (the cache
                                #   edits behind them), reader.go (Open, File: positioned reads by
                                #   chunk, two-chunk window), chunksize.go (per-version chunk size memo),
                                #   writer.go (Create, OpenSpool, Spool: uploads,
                                #   spool file, lazy hydration), trace.go (cache.refresh span helpers),
                                #   deps_test.go (dependency rule)
    metastore/                  # MetaStore interface (listings, entries, dataroom list) + Node, Listing, Entry,
                                #   Codec / Binder, …; memstore/ is the in-memory implementation (the default),
                                #   redisstore/ the one shared between instances (see "Redis metadata store")
  keyring/keyring.go            # Linux kernel session keyring cache (TTL-based)
mcpb/icon.png                   # MCPB bundle icon (512×512)
scripts/build-mcpb.sh           # Builds dist/retyc-<version>.mcpb from goreleaser dist/ (jq+zip, no Node)
scripts/webdav-bench.sh         # Benchmark small-file writes through `retyc fs webdav serve`
scripts/start-jaeger.sh         # Local Jaeger (OTLP 4318/4317, UI 16686) for manual tracing checks
scripts/redis-cache-dump/       # package main, diagnostic: prints a Redis metadata cache as JSON (redisstore.Describe),
                                #   read-only, not released (see "Redis metadata store")
scripts/redis-cache-dump.sh     # go run ./scripts/redis-cache-dump "$@" from the repository root
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
- Copies only: binary, CA certs, `/etc/passwd`, `/home/retyc` (with `.config/retyc/` pre-created),
  and an empty `/tmp` (mode 1777, copied as the content of `/image-root`: `COPY --chmod` on a
  directory does not set the directory's own mode): `fs mount` spools the files being written there
- `fs mount` in the image needs `--user 0 --device /dev/fuse --cap-add SYS_ADMIN` (no `fusermount3`
  in scratch: root mounts with `mount(2)`); the default user stays 1000 (`doc/retycfs.md`, Containers)
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

- Rate limit: `api.retry.max_wait` (30s, between 1s and `config.MaxRetryMaxWait`
  = 10m, with a unit) and `api.retry.max_attempts` (10, between 1 and
  `config.MaxRetryAttempts`; 1 = the request is not replayed, the client still
  observes the pause), no flag. Passed to every `api.New` through `apiRetry(cfg)` (`api.WithRetry`), next to
  `apiTransport()`. See "API rate limit (429)".

## Persistent flags (root)

| Flag | Short | Default | Description |
|---|---|---|---|
| `--insecure` | `-k` | false | Skip TLS verification (self-signed certs). **Dev builds only** — `cmd/insecure_prod.go` defines it as a `const false` |
| `--debug` | `-d` | false | Print all HTTP requests + raw responses to stderr |
| `--config` | | auto | Override config file path |
| `--env-file` | | `$RETYC_ENV_FILE` | File of `RETYC_*` variables applied to the environment before viper (see "Environment file") |
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
  `RETYC_CONFIG_DIR` (read before viper is initialised), `RETYC_ENV_FILE`
  (read first of all, see "Environment file" below). Never
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
  viper, because only the variable sees `-k`. A prod build has no `insecure`
  key at all: no default (`setBuildDefaults`, `paths_prod.go`), `config show`
  leaves it out even when a config file carries it (`hiddenConfigKey`), and a
  requested `insecure` is ignored silently.
- A config file that exists but fails to load (unreadable `--config` path, YAML
  error) is still skipped — defaults and env apply — but no longer silently:
  `initConfig` keeps the error in `configFileErr`, printed by `config path`
  (`config_file_error` in JSON) and under `--debug`. A missing file in the
  search path (`viper.ConfigFileNotFoundError`) is the normal case, not an error.

### Environment file (`--env-file` / `RETYC_ENV_FILE`)

The source of secrets for a non-interactive start (boot mount, systemd, CSI).
`internal/config/envfile.go`: `config.LoadEnvFile(flagPath)` (flag, else
`RETYC_ENV_FILE`) parses the file and `os.Setenv`s its variables, so the
accessors of `env.go` and viper's `AutomaticEnv` see them with no change of
their own. Rules:

- **Order**: `cobra.OnInitialize(loadEnvFile, initConfig)` (`cmd/root.go`): the
  file is applied after flag parsing and before viper and any `RETYC_` read,
  `RETYC_CONFIG_DIR` included. Only the `--config` help hint, built in
  `init()`, reads the config dir earlier.
- **Precedence**: real environment > file > `config.yaml` > default. A
  variable already present, even empty (`os.LookupEnv`), is kept
  (`EnvFile.Kept`); the others are `EnvFile.Applied`. Last assignment of a
  name in the file wins.
- **Format** (`parseEnvFile`): `NAME=value`, optional `export `, `#` comment
  lines, blank lines, CRLF and a BOM tolerated; value = rest of the line
  trimmed, or the content of single / double quotes (`\"` and `\\` in double
  quotes only, a comment allowed after the closing quote); no expansion, no
  inline comment on an unquoted value. Only `RETYC_*` names: any other, and
  `RETYC_ENV_FILE` itself, is an error (the file must not set a proxy, a CA
  bundle or `LD_PRELOAD`). A malformed file applies nothing.
- **Errors never quote a line**, key included (a line without `=` may be the
  secret): file path + line number + a fixed message. All wrap
  `config.ErrEnvFile` → `exitConfig` (78).
- **Permissions**: checked on the open file (`f.Stat`), mode & 0077 ≠ 0 is
  refused with `chmod 600 <path>`; not on Windows (`runtime.GOOS`). The owner
  is not checked.
- `loadEnvFile` cannot return an error (`OnInitialize`): it keeps it in
  `envFileErr`, which `PersistentPreRunE` returns first thing — except for
  `annotationOffline` commands, which run and print `warning: …` on stderr
  (`config path` reports it as `env_file_error`).
- `config path` prints `env file` (`env_file`, `env_file_variables`: names
  only); `config show` names the file on stderr and keeps its stdout shape.
  `--debug` prints the path and the names applied / kept, never a value. The
  path goes to no span and no metric.
- `LoadEnvFile` first takes back what the previous load set
  (`config.UnloadEnvFile`), so `run()` can be called several times in one
  process; `isolateConfig` calls `UnloadEnvFile` and resets `envFileFlag`,
  `envFileLoaded`, `envFileErr` — the injected variables are not registered
  with `t.Setenv`.

Adding a config key: `viper.SetDefault` in `SetDefaults()`, a field in the
`Config` struct, a row in `doc/configuration.md`. Nothing else.

The `SetDefault` is **mandatory, even for a zero value**: `viper.AllKeys()` only
reports keys that carry a default, so a key without one is invisible to
`retyc config show` and to `TestEnvVarsDocumented` — it would silently escape
the documentation check. This is why `insecure` has a `SetDefault(false)`, in
`setBuildDefaults` of `paths_dev.go` only: a key that exists in one build mode
gets its default there, not in `SetDefaults()`.

## JSON output (`--json`)

Convention: **stdout = results only, stderr = everything else** (prompts, spinners,
progress bars, service warnings, device-flow instructions). `cmd/output.go` holds
`jsonOutput`, `printJSON`, `printError` (used by `Execute()`; with `--json` the
object of `cmd/errorjson.go`: `error` and `kind` always, `status` / `code` / `detail` for an
`api.HTTPError` (`code` = the API's `X-Error-Code`, absent when it sent none); `errorKind` classifies, first match wins, in `exitCode`'s order;
a kind is never renamed, the table is in `doc/commands.md`), `confirm(prompt, yes)`
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
  Commands annotated `annotationOffline` (`version`, `mcp manifest`,
  `config path`, `config show`) skip it — they open no connection, and the
  release CI runs `retyc mcp manifest`.
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

## API rate limit (429)

The ingress refuses requests above 100/s per source IP with a 429 and
`Retry-After: 1`, before they reach the API: replaying is safe whatever the
method. `internal/api/retry.go` handles it for every command; the OIDC client
(`newHTTPClient`) is not concerned.

- `api.ErrRateLimited` matches any 429 (`HTTPError.Is`); `HTTPError.RetryAfter`
  holds the parsed header (seconds or HTTP date, 0 otherwise);
  `api.RetryAfter(err)` reads it from a chain.
- `retryTransport` is the **outermost** RoundTripper of `api.New`, outside
  the `WrapTransport` wrappers: retry → telemetry → metrics → User-Agent →
  oauth2 → `BaseTransport`, so each attempt is one counted request and one
  CLIENT span. It replays on 429 only, when the request has no body or a
  `GetBody`: build request bodies from `bytes.Reader` / `bytes.Buffer` /
  `strings.Reader` (what `http.NewRequest` can rebuild), never from a stream,
  or the 429 goes back to the caller unretried.
- Pause: `Retry-After` (seconds capped at 24 h, or an HTTP date read against
  the gate's clock, as `Client.responseError` does), else 200 ms × 2ⁿ capped
  at 5 s with full jitter. A request is given up after
  `api.retry.max_attempts` sends, or as soon as it would be held back for
  more than `api.retry.max_wait` **in total**, gate included: the check runs
  after each 429 and again at each gate deadline (`throttleGate.wait` gets the
  remaining budget), so a gate pushed by another request's refusal never
  holds a request past its budget. The caller gets a `*api.RateLimitError`
  ("API rate limit, gave up after 30s (10 attempts): ...", or "... without
  sending the request" for a request that never left the gate; it wraps the
  last `HTTPError`, the gate's when the request has none of its own;
  `Client.do` / `GetBytes` strip the `*url.Error` around it). A context done
  during the wait returns the context's error, not a rate limit. Exit code 1.
- `throttleGate`, one per `api.Client` (`Client.retry.gate`): the first 429
  closes it, every request of the client, new or replayed, waits at it; a 429
  received while it is closed pushes it to now + pause at most, and it never
  closes for longer than `max_wait`. A request given up leaves it closed, and
  so does `max_attempts: 1`: the request is not replayed but the next ones
  wait for the pause. An episode (first 429 → gate open again for good) is
  **one** stderr line, `API rate limit: throttled from <start> to <notBefore>
  (<notBefore - start>), N refusal(s), M request(s) held back` (M counts
  requests, once each), printed by the first answer that is not a 429 once
  the gate has reopened (`settle`; an answer received while it is closed
  ends nothing). A one-shot command whose last request is given up therefore
  logs no episode: its error message carries it. Under `--debug` each refused
  attempt also prints `< 429 Too Many Requests, ...`.
- Tests never sleep: replace `gate.now`, `gate.sleepUntil`, `gate.logf` and
  `retry.jitter` (`fakeClock` in `internal/api/retry_test.go`); outside the
  package, `api.WithRetry(time.Millisecond, 1)` gives up at once and caps the
  gate at 1 ms.
- Metrics: `retyc_cli_api_throttle_episodes_total`,
  `retyc_cli_api_throttle_wait_seconds`, `retyc_cli_api_rate_limited_total{method}`.
  Trace: the wait is an `api.throttle` event on the caller's span
  (`telemetry.ThrottleEvent`: `retyc.retry.attempt`, `retyc.retry.wait_ms`).
- `webdav serve` answers 429 + `Retry-After` (`cmd/webdav_ratelimit.go`).
  x/net/webdav picks its status from the FileSystem error with no hook (404,
  405, 409 or 500) and only then calls `Handler.Logger`, so
  `newWebdavHandler` wraps the handler in `rateLimitStatus`: error responses
  (status ≥ 400), and the whole response of a `PROPFIND` with `Depth: 1` (its
  207 is written before the children are listed), are held back until the
  handler returns, and replaced when the logged error is
  `api.ErrRateLimited`. Everything else is streamed as before, `Depth:
  infinity` / no `Depth` included (a whole subtree, never buffered). It only
  works while FileSystem errors keep the API error wrapped (`%w`); `vfs`
  gives a rate limit no sentinel and no `CopyError`, it crosses as it is. Tests
  build their handler with `newWebdavHandler` too, never a bare
  `webdav.Handler`. `handleCopy` does the same by itself. Not covered: a
  `GET` whose chunk download is refused after the headers left (cut short,
  like any failed download), a `Depth: infinity` listing refused past its
  first entry (truncated 207, as any failed listing), and `lockMirror`, which
  logs a failed server lock and grants the WebDAV one.

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
| Metadata (`name_enc`, `type_enc` / `mime_name_enc`, `message_enc`, key fields) | **Armored AGE** | `EncryptStringForKeys(value, []pubKeys)` |
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
- **Server-side copy** (`retyc:// → retyc://`, same dataroom, one file):
  `service.CopyDataroomNode` → `POST /dataroom/node/{id}/copy` (202, chunks duplicated by
  the storage, MIME / mode / `client_mtime` kept), then `waitForVersion` polls
  `GET /dataroom/node/version/{id}` (after 50 ms, doubled up to one second) until `chunk_count` reaches
  `chunk_count_expected` (`api.DataroomNodeVersion.Complete`); 404 while polling →
  `ErrCopyDiscarded`, 410 → `ErrCopyTargetDeleted`. Folders are refused.
- **Upload** (`local → retyc://`): one or more local paths, last arg is remote dest folder.
  Directories are uploaded recursively (BFS). SIGINT or a failed upload discards what the
  upload created (`service.DiscardFailedUpload`): the node if it was new, otherwise only the
  new version (`DeleteDataroomNodeVersion`) — best-effort, deleting needs `can_delete`.
- A small file (≤ `service.SmallUploadMaxSize`, **one chunk**, 8 MiB of plaintext, empty included) goes through
  `service.UploadSmallFile` → `POST /dataroom/{id}/node/file` (operationId
  `createDataroomFileNode`, via `api.Client.CreateDataroomFileNode`, multipart): node + version + the single encrypted chunk in one request, `overwrite=true`
  so an existing file gets a new version, 410 `NAME_HOLDER_DELETED` (any 410 from an API
  without codes) → `ErrNameBeingDeleted`, 409 `CONCURRENT_UPDATE` sent once more. The server drops a
  failed request: no `DiscardFailedUpload`. In production that route sits behind the
  Traefik `maxRequestBodyBytes` of the chunk route, 32 MiB on the whole body (encrypted
  chunk + multipart envelope; it was 1 MiB, and the threshold 768 KiB, until October
  2026); the API itself refuses more than `dataroom_single_upload_max_size` (64 MiB).
  `TestSmallUploadMaxSize` checks a chunk at the limit leaves room for the envelope. A
  file above it (more than one chunk) goes through version + chunks. Should a proxy
  still answer **413** (a text body; an older limit), `uploadSmallFile` sends the same
  content once through version + chunks (`uploadSmallFileChunked`, which discards what it
  created on failure). `dataroom cp`, WebDAV and the spool (`vfs.FS.Create`, see
  "internal/vfs": writes) all go through it.
- Refusals of a write: **403** for a viewer or a dataroom over its plan (`Create not allowed
  here`, `Add version not allowed`; only the author of a version may send its chunks);
  **400** `STORAGE_EXCEEDED` (from an API without codes: a `detail` containing `exceeds
  maximum allowed storage size`, `api.IsStorageExceeded`) for lack of storage, on the single-request route, on version creation (for the size announced), on
  **each chunk** (for its encrypted size: an upload can pass the creation and fail at chunk
  N) and on the server-side copy. Other 400s are not storage (`Maximum number of versions
  reached (n)`, `mime_types_limit`, the missing name salt). When version creation is
  refused for storage and the node had **no version yet**, the API deletes the node:
  `DiscardFailedUpload` treats a 404 on the node as done.
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
- The local file's mtime is sent as `client_mtime` (version creation and single-request
  route); a download gives the file the `client_mtime` of its version when there is one
  (`service.downloadVersion`, `os.Chtimes`).

Flags: `--yes`/`-y`

### Node types, MIME table, name-hash lookup (API `evol/dataroom_node_types`)

The API answers **426** to a CLI older than its minimum version (`User-Agent`
`retyc-cli/<version>`); a `dev` build is refused, build with `-ldflags` to test.

- A node is a folder when `node.type == "folder"`; `api.DataroomNode.IsFolder()` is the
  **only** test, it falls back to `type_enc == nil` for an API without the type field.
  Never test `TypeEnc` directly: on the new API a migrated file has `type_enc: null`.
  A node is a **symlink** when `node.type == "symlink"` (`IsSymlink()`): no version, no
  MIME, its target in `target_enc` (session key). `IsFile()` is the kind that carries
  versions; `!IsFolder()` is **not** "file". `service.DataroomNodeInfo` reports
  `Type: "symlink"`, `Size` = target length (lstat), `Target()` the decrypted target,
  `ModTime()` the node's `created_at`; `dataroom ls` prints `LINK name -> target`.
  After a 409, `findNodeByName` returns the holder: an upload refuses a folder or a
  symlink holder, `mkdir` reuses a folder holder only. `download` and the server-side copy
  refuse a symlink source. **WebDAV hides symlinks**: `nodesToFileInfos` leaves them out and
  `vfs.FS.Lookup` does not match them (`vfs.Options.HideSymlinks`, set by `newWebdavFS`), so `Stat` answers `ErrNotExist` and a `PUT` on the
  name ends in the 409 path. The CLI does not create symlinks (`POST /dataroom/{id}/node/symlink`
  is for the FUSE driver).
- MIME types live in a per-dataroom table (`GET /dataroom/{id}/mime-types`: `id`, `hash`
  = SHA-256(nameSalt + type), `name_enc` encrypted for the session key); a file node
  references a row by `mime_type_id`, a file not migrated yet still carries `type_enc`.
  `service.mimeCache` (`internal/service/mime.go`), held by `dataroomSession`, loads the
  table on first use and resolves rows (one decryption per row, not per node; reload once
  for an unknown row). All MIME reads go through `sess.mimeTypeOf`.
- Writes go through `sess.withMIME`: `mime_hash` alone for a type the table knows,
  `mime_hash` + `mime_name_enc` otherwise; 422 `MIME_TYPE_UNKNOWN` → resend with the
  ciphertext; 400 `MIME_TYPES_LIMIT` (256 types per dataroom) → legacy `type_enc`
  (`mimeRefusal`: the code, or the `detail` `mime_type_unknown` / `mime_types_limit` of an
  API without codes). The
  legacy ciphertext is also what a dataroom **without name salt** gets (the API refuses an
  unsalted MIME hash) and what the **legacy API** gets.
- **Probe**: the first `GET /mime-types` of a session tells the API apart. 404 without `X-Error-Code` → legacy API
  (`type_enc`, no name-hash lookup, the session is marked for good); a 404 with a code
  (`DATAROOM_NOT_FOUND`) is the new API's refusal, returned and not cached; any other failure →
  legacy for that call only, not cached. This matters because the API in production may
  predate the branch: the new CLI must keep working against it, and pydantic ignores
  unknown fields, so a file sent with `mime_hash` and no `type_enc` would become a folder
  there.
- `internal/vfs` resolves by name hash too, one component at a time and
  through its cache: `service.LookupNodeByName(ctx, client, dataroomID,
  parentID, name, sess)` is the primitive (`ErrNoNameLookup` on a legacy API
  or a failed probe), `FS.Lookup` the cache around it (see "internal/vfs":
  resolution). It refuses (not found) a node whose `parent_id` is not the
  folder asked: the root is asked by leaving `parent_id` out.
- `resolvePathWithSession` / `resolvePathItemWithSession` look each path component up
  with `GET /dataroom/{id}/nodes?parent_id=&name_hash=` (`api.Client.FindDataroomNodeByHash`)
  on a non-legacy API: O(depth) requests, nothing decrypted. Glob paths still list.
  `findNodeAndTypeByName` (after a 409) does the same. The identity-only `resolvePath` /
  `resolvePathItem` remain the listing fallback.
- `PUT /dataroom/node/{id}` is `exclude_unset`: `api.NodeUpdate` sends only the set fields,
  `SetParent` + nil `ParentID` is the explicit null that means "move to the root".
  `RenameDataroomNode` (rename + move), `SetDataroomNodeAccessMode` (chmod, no version),
  `SetDataroomVersionClientMtime` (`PATCH /dataroom/node/version/{id}`, no version;
  `vfs.FS.SetModTime` is its only caller, no command or WebDAV method reaches it yet).
  `NodeUpdate.Replace` sends `"replace": true` (never `false`: the route refuses a field it
  does not know): a live **file** holding the target name is deleted and the node renamed in
  one transaction; a folder holding it answers 409 `Cannot replace a folder`, a file the
  user may not delete 403 `Replace not allowed`. `service.ReplaceDataroomNodeByID` sends it
  on a non-legacy API only (`supportsNodeTypes`), `service.ErrReplaceUnsupported` otherwise:
  an older API would ignore the field and rename without replacing. Only
  `vfs.FS.Rename(replace=true)` uses it, for the FUSE driver to come; WebDAV never replaces
  on rename (x/net/webdav deletes the destination of a `MOVE` itself).
- `access_mode` ("0644", octal string) is parsed by `api.ParseAccessMode` into
  `DataroomNodeInfo.Mode()`, its presence in `HasMode()`: **`"0000"` is a mode, not an
  absence**, and the defaults (0644 / 0755, FUSE `file_mode` / `dir_mode`) apply only when the
  API stores none. A creation with an explicit mode 0 sends `"0000"` (`accessModeField`
  takes a `*os.FileMode`, nil = none). WebDAV presents it (`webdavFileInfo.Mode`,
  setuid/setgid/sticky stripped), 0644 / 0755 when absent. `webdav serve` writes it on a `PROPPATCH` of the
  Apache `executable` property, the only part of a mode WebDAV carries
  (`cmd/webdav_chmod.go`, the PROPPATCH part only): x/net/webdav opens the target of a
  PROPPATCH for writing, so `writeFileHandle.Patch` is where it lands. It calls
  `vfs.FS.SetExecutable` (`internal/vfs/attrs.go`: `WithExecutable` →
  `SetDataroomNodeAccessMode`, cached listing updated in place, no request for an unchanged
  mode) and turns its error into a propstat (`vfs.ErrIsDir` → 403 on the property,
  `api.ErrLocked` → 423, `vfs.ErrForbidden` → 403, `vfs.ErrNotExist` → `os.ErrNotExist`);
  `readFileHandle.DeadProps` reports the property on PROPFIND. Files only. The cache keeps the mode it holds when an upload path
  does not learn it (`keepKnown`, `internal/vfs/edit.go`).
- `DataroomNodeInfo.ModTime()`: a file's `client_mtime` else the version's `created_at`; a
  folder's `created_at` (zero on an older API).
- Decoded and shown only: `versioning_enabled` (`api.Dataroom`, `dataroom info`),
  `storage_capacity` / `storage_used` / `storage_free` (`api.DataroomStats`, `dataroom info`
  and the WebDAV quota; `storage_used` is a pointer, nil on an API without the counters).
  `chunk_count_expected` (`api.DataroomNodeVersion.Complete()`) follows a copy. Decoded and
  unused: `allowed_storage_size`, `copied_from_version_id`, and the dataroom's `storage_*`.
- Listing ETag: `api.Client.ListDataroomNodesIfChanged` sends `If-None-Match` and answers
  `api.ErrNotModified` on a 304 (`HTTPError.Is`); `service.ListNodesByIDIfChanged` makes
  only the first page conditional and returns its ETag. The ETag is the dataroom's
  revision, not the folder's. Only the WebDAV listing cache uses it (see WebDAV server
  flags); `GET /mime-types` is not conditional.
- **WebDAV** (`cmd/webdav_copy.go`, `cmd/webdav_locks.go`: HTTP only, the work is in
  `internal/vfs`): `COPY` of a file goes to
  `handleCopy` from the mux (x/net/webdav's `copyFiles` would move every byte through the
  server), RFC 4918 statuses (201 / 204 replaced / 412 `Overwrite: F` / 409 missing folder /
  501 folder / 507 storage). `copyNode` parses `Destination` and `Overwrite`, checks the
  locks, then calls `vfs.FS.Copy(…, replace)`, which updates the cached listing of the
  destination in place. The API only copies into a new node, so a replaced destination is
  deleted first, and the copy is tried again while the API still holds the name of the
  deleted node (409 until its purge has run, on an API without codes; with codes the name
  is freed by the `DELETE` itself: `NAME_TAKEN` stops at once, `CONCURRENT_UPDATE` retries;
  `copyNameHeld`; `vfs.Options.CopyReplaceRetry` /
  `CopyReplaceWait`, 500 ms / 15 s, which `newWebdavFS` fills from the `copyReplaceRetry` /
  `copyReplaceWait` variables of `cmd` that tests shorten). A 404 / 410 on the copy route
  is told apart by its code (`copyGone`): `NODE_NOT_FOUND` / `NODE_DELETED` is the source
  (`CopySource`, only its folder's listing dropped), `PARENT_NOT_FOUND` / `PARENT_DELETED`
  the destination folder (`CopyDestinationFolder`, 409); without a code it is
  `CopyTransfer` (404) and both listings go. It is never the name. A failed copy is a `*vfs.CopyError{Step, Err}`:
  WebDAV's status depends on **which** resource failed, so `copyStatus` reads the step
  (`CopySource` → 404, or 501 for a folder; `CopyDestinationFolder` → 409; `CopySession` →
  500; `CopyDestination` → 403 same node / 412 exists / 409 folder; `CopyReplace` → 500;
  `CopyTransfer` → `copyErrorStatus`), where a front end mapping to errno reads the
  sentinels only. Bypassing the handler also bypasses its lock
  check: `confirmCopyLocks` redoes it on the destination against `webdavFS.locks` (own
  `parseIfHeader`, x/net/webdav exports neither), and a destination that resolves to the
  source node is refused before anything is deleted (the `Destination` header is not
  normalized; `vfs.ErrSameNode`).
  Every dataroom folder handle implements `webdav.DeadPropsHolder` with the RFC 4331
  quota properties from `GET /dataroom/{id}/stats`, cached per dataroom for the listing
  TTL (`vfs.FS.Quota`, `internal/vfs/quota.go`; `quotaOnce` / `quotaProps` stay in `cmd`).
  `lockMirror` wraps the WebDAV handler and keeps the HTTP side: a `LOCK` on a listed file
  (buffered response, `Lock-Token` header, or the `If` header on a refresh) has an
  exclusive API lock taken (`vfs.LockManager.Take`: `POST /dataroom/node/{id}/lock`, lease
  `api.LockTimeoutMax`),
  423 from the API undoes the local lock (`LockSystem.Unlock`) and answers 423; `UNLOCK`
  releases it (`Release`). The API locks live in `vfs.LockManager` (`vfs.FS.Locks()`,
  `internal/vfs/locks.go`), keyed by the WebDAV lock token: `Run` (started by
  `webdav serve` through `lockMirror.run`) renews every lock every 2 min and releases them
  all on shutdown. A lock records when its WebDAV lock lapses (the timeout of the LOCK
  response, `lockExpiry`, given to `Take` / `Refresh`): `RefreshAll` releases a lapsed one
  instead of renewing it, and
  the periodic renewal never takes a lock for a token unlocked meanwhile. The server holds
  one lock per **token**, not per user (a second exclusive LOCK by the same user answers
  423): before taking a server lock for a new WebDAV lock, `Take` (`releaseStale`) drops the
  server locks still held for that node, since MemLS only grants the new lock once the
  previous one lapsed or was unlocked; without it the mirror would refuse itself. The temporary locks x/net/webdav takes around writes without an `If` header
  (`confirmLocks`) never reach the API. `statfs` has no WebDAV equivalent beyond quota.
  The locks are driven by WebDAV `LOCK` / `UNLOCK` only: nothing takes one when a file is
  opened for writing.
- `api.HTTPError{Status, Body, Code}` is every non-2xx error; `errors.Is` keeps matching
  `ErrConflict` / `ErrNotFound` / `ErrGone`. **Branch on the code**: `api.ErrorCode(err)`
  is the `X-Error-Code` header (`api.ErrorCodeHeader`, constants `api.Code*` in
  `internal/api/errorcodes.go`; the full list per route is in the API's OpenAPI), stable,
  one status per code. `detail` (`api.ErrorDetail`) is a message for humans: it is read
  only for a refusal **without** a code (an API that predates them), as the fallback,
  never when a code is there. No code also means the answer did not come from the
  dataroom code (pydantic 422, authentication, unknown route, proxy 413).

### `dataroom mv retyc://id/src retyc://id/dst`
Rename or move within the same dataroom. Resolves both paths, re-encrypts the name with the
session public key, calls `PUT /dataroom/node/{id}`.

### `dataroom rm retyc://id[/path] [-y]`
- **`retyc://id`** (path = `/`): deletes the entire dataroom. No crypto needed — calls `DELETE /dataroom/{id}` directly.
- **`retyc://id/path`**: deletes a single node.
- **Glob** (`retyc://id/*.log`): lists matching nodes (type + name) before confirmation, then deletes each.

### `dataroom mkdir retyc://id/path`
Creates directory node. Parent path must exist.

### `dataroom create --title <title> [--versioning=false] [--storage-capacity SIZE]`
1. `GET /user/me/key/active` → user's public key
2. Generate session keypair
3. `EncryptStringForKeys(sessionPrivKey, [userPublicKey])` → `session_private_key_enc`
4. `POST /dataroom` with title, session_private_key_enc, session_public_key, and
   `versioning_enabled` / `storage_capacity` only when their flag is set (`api.DataroomOptions`)

### `dataroom set <id|retyc://id> [--title T] [--versioning=true|false] [--storage-capacity SIZE] [-y]`
`PATCH /dataroom/{id}` (`updateDataroom`, `api.DataroomUpdate`): only the flags set are
sent, none → "nothing to update". `--versioning`/`--storage-capacity` are shared with
`create` (`addDataroomOptionFlags` / `dataroomOptionsFromFlags`). Sizes go through
`ui.ParseSize`: binary units only (`50G` = `50GiB` = 50×1024³), `GB`/`KB` refused.
`--versioning=false` asks for confirmation (`confirm`, `-y`). The API refuses to shrink a
capacity; the CLI does not pre-check. `session_private_key_enc` is not exposed (rekey is
`dataroom user add/rm`). No crypto, no MCP tool.

### `dataroom info <id>`
Parallel fetch of `GET /dataroom/{id}`, `GET /dataroom/{id}/stats`,
`GET /dataroom/{id}/users`. Displays metadata, versioning (when the API reports it), file
count, encrypted size, storage (reserved capacity and free space, or usage on the owner's
plan), and users with roles.

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
MIME table row = {hash: SHA-256(nameSalt + mimeType),                  ← one row per type and dataroom
                  name_enc: EncryptStringForKeys(mimeType, [sessionPublicKey])}
node mime_type_id → row of the table (files); legacy files carry type_enc (same ciphertext, per node)
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

The command is `retyc fs webdav serve` (`cmd/fs.go` holds the `fs` group, the
filesystem accesses to datarooms); the rest of this document shortens it to
`webdav serve`. Only the command path carries `fs`: config keys (`webdav.*`),
`RETYC_WEBDAV_*`, metric names and Go identifiers do not. The `fs` group must
not get a `PersistentPreRun(E)` (see TLS, proxy and custom CAs).

`webdav serve` binds `--addr host:port` (`webdav.addr`, `RETYC_WEBDAV_ADDR`,
default `127.0.0.1:8888`); there is no separate port flag. Like the
`--metrics-*` flags, it is bound to its viper key in `resolveWebdavAddr`,
called from `RunE`, never in `init()`. `isLoopbackAddr` takes the same
`host:port` form.

Caches: the common `cache:` section, shared with `fs mount` (`cache.ttl`,
default 1m; `cache.max_stale`, default 5m, WebDAV only; `cache.negative_ttl`,
default 1s; `cache.store`, `memory` or `redis`, with `cache.redis.url` and
`cache.redis.high_confidentiality`, see "Redis metadata store";
`config.CacheConfig`, `Config.Cache`). Flags `--cache-ttl`,
`--cache-max-stale`, `--cache-negative-ttl`, `--cache-store`,
`--cache-redis-url`, `--cache-redis-high-confidentiality` (`addCacheFlags` in
`cmd/fs.go`; `fs mount` has no `--cache-max-stale`), bound by `resolveCacheFlags`, called
from `RunE` before `config.Load`, which validates them. The former
`webdav.cache.ttl` / `webdav.cache.max_stale` are **removed without alias**:
`config.Load` refuses a config file or an environment that carries one
(`removedKeys`, `viper.IsSet`: "webdav.cache.ttl was replaced by cache.ttl"),
for every command. Cached:
folder listings (`vfs.FS.ReadDir`, `internal/vfs/listings.go`) and the dataroom
list (`vfs.DataroomCache`, `internal/vfs/datarooms.go`)
are served fresh under the TTL, then served expired for `max_stale` more while
one background refresh replaces them (stale-while-revalidate), then waited for.
Background listing refreshes queue on `FS.slots` (`vfs.Options.ListConcurrency`,
which `webdav serve` fills from `api.concurrency.list`); a
request missing a folder whose refresh is queued promotes it (`listingFetch.promote`)
so it never waits behind the queue; the refresh reads the listing's generation
(`FS.gen`) when it starts, not when it is queued, and keeps it
(`listingFetch.gen` / `started`): `fetchLocked` joins a fetch in flight only
while it is still queued or its generation is the listing's current one.
Otherwise the folder changed through the FS while the API was answering, and a
new fetch replaces it in `FS.inflight` (the old one still answers whoever
waited for it before the change, removes the entry only if it is still its
own, and is not stored): `rm f; stat f` never reads the answer that predates
the `rm`. Name lookups (`Stat`,
the mutations of `internal/vfs/mutate.go`, the uploads) go through `FS.Lookup`: a name missing from an expired
listing waits for the refresh instead of answering 404. A name whose folder has
no listing in cache is looked up on its own, by name hash, and the answer kept
as an `Entry` (see "internal/vfs": resolution): the folder is not listed for a
`Stat`, a `PROPFIND Depth: 0` or a `GET`. A name found missing is answered
missing for `vfs.Options.NegativeTTL` (`cache.negative_ttl`, 1 s by default,
0 = no negative cache, passed by `webdav serve` and `fs mount`;
`vfs.DefaultNegativeTTL` is the same value for an FS built outside a command). The overwrite shortcut of an upload (`cachedFileID`)
trusts fresh listings, and fresh positive entries, only. A zero `vfs.Options.MaxStale` (every FS a test builds
without setting it) never serves an expired listing.
A listing is cached with the ETag the API answered (`Listing.ETag`) and
refreshed with it: on a 304 `fetchNodes` returns the held nodes and the listing
is renewed for a TTL, one round trip and nothing decrypted. A listing edited in
place (`FS.editLocked`) loses its ETag, so its next refresh is a full
listing. `vfs.Options.List` (tests) bypasses the ETag.

## internal/vfs

Service layer shared by the front ends that present datarooms as a file tree:
`webdav serve` and the FUSE driver (`internal/retycfs`, read-only so far). It is being extracted from
`cmd/webdav.go` slice by slice. So far it holds:

- the dataroom list, in the `FS`: `FS.Datarooms(ctx)` (`[]DataroomInfo{ID, Title,
  DisplayName}`, sorted by display name) and `FS.DataroomByName(ctx, displayName)`
  (tags the span with `retyc.dataroom.id`). `vfs.DataroomCache` still does the
  work (single-flight, stale-while-revalidate, display names deduplicated by ID
  order: unchanged) but the list itself is data and lives in the `MetaStore`
  (`GetDatarooms` / `PutDatarooms`, display names included); the cache keeps the
  fetch in flight and an index of the stored list, rebuilt when its `FetchedAt`
  changes. `webdavFS` has no cache field of its own any more. The list comes
  from `service.ListDatarooms` unless `Options.ListDatarooms` replaces it;
  `FS.SeedDatarooms` is the test seam (`SeedSession`'s twin);
- `vfs.FS` (`vfs.New(client, vfs.Options)`, `webdavFS.tree`): the folder listing
  cache, the dataroom sessions (`Session`; `SessionsCached` for the gauge,
  `SeedSession` for tests; `service.SessionCache`, resolved from
  `Options.Identity`) and path resolution (`ReadDir`,
  `Lookup(dataroomID, parentPath, name)`, `FindNode`; see "Resolution"
  below);
- the mutations of the tree, addressed by dataroom ID and path
  (`mutate.go`, `attrs.go`): `Mkdir`, `Remove(…, recursive)`,
  `Rename(…, replace)`, `Copy(…, replace)`, `Chmod` / `SetExecutable`,
  `SetModTime`. Each resolves its paths through the cached listings, calls the
  API, and records the outcome in the cache itself (`edit.go`: `upsert`,
  `forget`, `move`, `addFolder`, or an invalidation when the listing cannot be
  edited). The retries on a stale listing moved with them, unchanged:
  `mkdirAfterConflict`, `staleRename`, the second attempt of `Remove` after a
  404, the wait for the purge in `Copy`;
- `Quota` (`quota.go`) and the API locks (`LockManager`, `locks.go`, reached
  through `FS.Locks()`);
- positioned reads (`internal/vfs/reader.go`, see below): `FS.Open(ctx,
  dataroomID, node)` → `vfs.File`.

- writes (`internal/vfs/writer.go`, see "Writes" below): `FS.Create` (size
  known, content streamed from an `io.Reader`) and `FS.OpenSpool` →
  `vfs.Spool` (size unknown: a local file, flushed as a version).

- for the FUSE driver in write mode, used by no front end yet
  (`mutate.go`, `access.go`):
  - `FS.Symlink(ctx, dataroomID, path, target) (Node, error)`:
    `service.SymlinkDataroomInto` → `api.Client.CreateDataroomSymlink`
    (`POST /dataroom/{id}/node/symlink`, 201 + the node; body `name_enc`,
    `name_hash`, `target_enc` — armored AGE for the session key, 16 KiB at
    most —, `parent_id` null for the root; no `type`, `access_mode` left to
    the server, 0777). Errors as `Mkdir` (`ErrNotExist`, `ErrNotDir`,
    `ErrExist` + `nameTaken`, `ErrForbidden`, the stale parent of a 409 through
    `parentAfterConflict`, shared with `mkdirAfterConflict`), and
    `ErrSymlinkUnsupported` (which **is** `service.ErrSymlinkUnsupported`) on a
    legacy API — not asked — or a 405 on the route; a failed probe is returned
    as it is. The node is `upsert`ed (`TypeSymlink`, `Target`, `Size` = target
    length); `Options.HideSymlinks` then hides it from `Lookup` like any other.
  - `FS.Access(ctx, dataroomID) (Access, error)`, `Access{Role, Writable,
    ReadOnly}`: the role comes from the **list** (`GET /dataroom`, `role`;
    `DataroomInfo.Role`, from the cached list), `writable` (the owner's plan)
    from the **detail** (`GET /dataroom/{id}`, asked every call, no cache);
    neither route carries the other field. `ReadOnly = Role == "viewer" ||
    !Writable`. What the API does not tell is allowed: `api.Dataroom.Writable`
    is a pointer (`CanWrite()`), an empty or unlisted role is not a viewer.
  - `Rename(replace=true)` of a **folder** looks its destination up first
    (`folderReplaces`): a file or symlink holding the name is `ErrNotDir` and
    nothing is sent, the API would replace the file by the folder. Free when
    the destination's folder is listed or an `Entry` holds the name, one
    lookup by name otherwise. A file source, and any rename without replace,
    look nothing up (the API answers `Cannot replace a folder` itself). A
    folder onto a folder is still the API's 409 → `ErrIsDir`, empty or not.

`webdavFS.Mkdir` / `RemoveAll` / `Rename`, `copyNode`, `writeFileHandle.Patch`,
`lockMirror` and the write handles (`createHandle`, `writeFileHandle`) are
adapters: they parse the WebDAV path or the HTTP request, call the method
above, and map its error. What is still in `cmd`: the WebDAV read handle (an
adapter over the stream and `vfs.File`; its streamed download is the last
thing that reads `webdavFS.client`, and its `onDownloadError` the only caller
of `FS.InvalidateListing` outside the package, which is why that one is still
exported). `upsert`, `resolveFolderID`, `cachedFileID`, `invalidateSubtree`,
`forget`, `move` and `addFolder` have no caller outside the package. `cmd`
holds no cache structure and never reaches the store.

New with the mutations, used by no front end yet (they are what a FUSE driver
needs, WebDAV keeps calling the forms that reproduce what it did):
`Remove(recursive=false)` lists a folder first and answers `ErrNotEmpty` when
it has children (the API would delete the tree; the check and the `DELETE` are
two requests). That listing is **always asked of the API** (`readDirFetched`),
never read from the cache, even fresh: a child created elsewhere since would
go with the folder. One request per `rmdir` is the price of `ErrNotEmpty`;
`Rename(replace=true)` is one `PUT` with `"replace": true`
(`vfs.ErrReplaceUnsupported`, which still matches
`service.ErrReplaceUnsupported`, on a legacy API, no three-request fallback).
With codes: `REPLACE_TARGET_IS_FOLDER` is `ErrIsDir`, `CONCURRENT_UPDATE` is tried once
more (`renameRetries`; `Mkdir` too), `NAME_TAKEN` is `ErrExist` at once, and a coded 409
skips `staleRename`, and `parentAfterConflict` for `Mkdir` / `Symlink` (a deleted folder
is a 404 `PARENT_NOT_FOUND` there). Without code: a
409 on a replace that does not carry the detail `Cannot replace a folder` is
the race of two concurrent replaces: it is tried once more before `ErrExist`;
one that carries it (`isReplaceFolder`) is `ErrIsDir` at once, without `staleRename` (a re-listing
that failed used to replace it). The probe behind "legacy" is
`dataroomSession.nodeTypesSupport`, `(supported, err)`: a 404 on
`GET /mime-types` is a legacy API, any other failure is **returned as it is**
(a 429 stays `api.ErrRateLimited`) and no rename is sent. `supportsNodeTypes`,
its boolean form, is for the callers that have a path both APIs accept
(listing instead of a lookup, `type_enc` instead of a MIME hash);
`Chmod` stores a whole mode; `SetModTime` patches the `client_mtime` of the
current version and edits the listing in place.

Paths are absolute, `/` being the dataroom root, and cleaned on the way in:
`listingKey` (`node.go`, `path.Clean("/" + p)`) is the only place a
`ListingKey` is built from a caller's path, so `/a`, `/a/`, `/a//`, `//a` and
`a` read, edit and drop one listing. The paths `parseWebdavPath` hands over
were already clean; this changes nothing for WebDAV.

Resolution (`resolve.go`). `FS.Lookup(dataroomID, parentPath, name)` answers
from the first of:

1. the listing of the parent, when cached and still served (younger than
   TTL + max stale): a name it holds is answered at once; a name missing from a
   fresh listing is `ErrNotExist`; a name missing from an expired one waits for
   its refresh. A listing cached but **no longer served**, for less than
   `listingRefreshWindow` (10 × TTL) past TTL + max stale, is refreshed and
   answers (`readDirRefreshed`, one conditional listing shared by a sweep of
   the folder's names in place of one lookup by name each; a failed refresh is
   the error returned) — after a fresh `Entry` of step 2, which keeps
   priority, and on an API with the lookup only. Past the window: step 3;
2. the `Entry` cached for `(parent, name)`: a node found is trusted for
   `Options.TTL`, a name found missing for `Options.NegativeTTL` (zero is a
   value here, unlike `TTL`: no negative cache);
3. on an API with the lookup: `service.LookupNodeByName` (one
   `GET /dataroom/{id}/nodes?parent_id=&name_hash=`, only the node found is
   decrypted, no cache logic in `service`), whose answer, found or not, is
   stored as an `Entry`. The parent's ID comes from `resolveFolderID`, i.e. from
   `Lookup` one level up: a path four folders deep that nothing cached costs
   four light requests and no listing; listing the folder afterwards costs its
   own listing only;
4. on a legacy API (`DataroomSession.SupportsNameLookup` false), or when its
   probe failed for this call, or with `Options.List` set (tests): the listing
   of the parent, fetched and cached, as before (`lookupListed`).

- Lookups of one name that reach the API share one request (`FS.lookups`,
  `entryLookup`), detached from the caller like a listing fetch.
- **Entries are dropped** (`dropEntriesLocked`) by everything that changes a
  folder through the FS, in the three primitives every mutation goes through:
  `editLocked` (`upsert`, `forget`, `move`, `addFolder`: so `Mkdir`, `Remove`,
  both sides of `Rename`, `Copy`, `Chmod`, `SetModTime` and the uploads),
  `invalidateLocked` (`InvalidateListing`) and
  `invalidateSubtreeLocked` (`DeleteEntriesBelow`: the folder and everything
  below). They are also dropped when a listing of the folder is put in the
  cache: it says all they say, and is the one consulted. The entry that names
  a folder belongs to its parent.
- **`upsert` under a folder that is not listed** (no listing in cache, or one
  too old for `Lookup` to serve) has nothing to edit: it keeps the node as the
  **positive `Entry`** of its name, written after the drop above so it
  survives it (`upsertLocked`). Without it a file just written there would be
  looked up at the API, and a late or early answer could keep "missing" for
  `NegativeTTL`. `cachedFileID` reads that `Entry` too, so an overwrite under
  an unlisted folder adds its version directly instead of going through node
  creation → 409 → lookup of the holder. `upsert` returns the node as the
  cache holds it (what `keepKnown` kept included), which is what the uploads
  return.
- A lookup in flight is covered by the generation of the parent's listing
  (`FS.gen`, bumped by the same three primitives; `invalidateSubtreeLocked`
  bumps it for the lookups in flight below): its answer is stored only if the
  generation did not move, and a lookup started after a mutation never joins
  one started before. A name created through the FS is never answered missing
  from an older `Entry`.
- A refusal of the API is evidence too. A genuine 409 on `Mkdir`, `Rename` or
  `Copy` says the name exists: `nameTaken` (`mutate.go`) drops the entries of
  the folder, and its listing unless it already names the node. A 404 that
  survives the retry of `Remove` / `Rename`, or answers `Copy`, invalidates
  the listing (and entries) the node was resolved from.
- A stale `Entry` behaves like a stale listing: the API answers 404 / 410 to
  what the caller does with the ID, the caller invalidates the folder (entries
  included) and resolves again. A lookup under a folder ID the API no longer
  has is made once more with the folder resolved afresh (`findByName`).
- `Options.HideSymlinks`: a symlink found by name is stored as an `Entry` and
  answered `ErrNotExist`, as when a listing holds it.
- A dataroom without name salt is looked up by the unsalted hash, the one its
  nodes were created with (`service` does the same everywhere).
- **Listing lookups never reach the network.** `ReadDir` returns complete
  nodes; a caller that lists a folder and answers for its entries one by one
  (FUSE `READDIRPLUS`: go-fuse calls `Lookup` once per entry, hot or cold) keeps
  the slice in its directory handle and uses `vfs.FindNode(nodes, name)`.
  `FS.Lookup` is the isolated lookup, for everything else.
- `cache.lookup` events carry `retyc.cache.name` `nodes` (a listing) or
  `entries`; a lookup that goes to the API adds `dataroom.resolve_path`
  (`retyc.dataroom.id`, `retyc.path.depth`). Both feed
  `retyc_cli_vfs_node_cache_lookups_total` (an `Entry` hit is a `hit`, a
  lookup by name a `miss`).
- Tests: `lookup_test.go` (`treeAPI`, a fake API holding a tree, counting
  lookups, listings and probes). A test whose fake API only answers listings
  seeds its session with `(&service.DataroomSession{…}).AssumeLegacyAPI()`,
  which marks the session legacy without the probe (`newCachedListingsFS` in
  `cmd` and in `vfs` do).

`Node` carries `ParentID` ("" for a child of the root) and `CreatedAt` (the
node's own `created_at`; `ModTime` is the version's for a file). Both come
from `service.DataroomNodeInfo.ParentID()` / `CreatedAt()` — unexported fields
behind accessors, the JSON shape of that struct being what the MCP server
emits (`TestDataroomNodeInfo_JSONShape`). Filled by listings, lookups by name,
`Copy` and the uploads (parent: the folder asked for; creation time: the one
`POST /node` or `POST /node/file` answered, `service.StreamUploadInit.NodeCreatedAt`),
`Rename` (the destination folder). `CreatedAt` is **unknown, left zero**,
after `Mkdir` (`MkdirDataroomInto` answers the ID only although the API
answers the whole node; `ModTime` is zero there too) and after a version
added to a node known by its ID alone (the overwrite shortcut: the version
route does not answer the node); `upsert` then keeps the one of the entry it
replaces, as it keeps the mode (`keepKnown`).

Errors (`errors.go`). The mutations return the sentinels of the package:
`ErrNotExist`, `ErrExist`, `ErrNotEmpty`, `ErrIsDir`, `ErrNotDir`,
`ErrSameNode`, `ErrStorageExceeded`, `ErrForbidden`, `ErrUnauthenticated`,
`ErrReplaceUnsupported`, and for the writes `ErrSpoolFull` and
`ErrNameBeingDeleted` (which **is** `service.ErrNameBeingDeleted`).
`ErrStorageExceeded` is `api.IsStorageExceeded` (code `STORAGE_EXCEEDED`, or a 400
whose `detail` contains `exceeds maximum allowed storage size` from an API without
codes), never "any 400": the copy route used to read it that way. `ErrReadOnly` is
**added next to** `ErrForbidden` for a 403 `DATAROOM_READ_ONLY` (the role allows the
write, the owner's plan is exceeded): WebDAV still answers 403, the FUSE driver `EROFS`.

- A sentinel is **added** to the error it is made from, never put in its place
  (`kindError`, `Unwrap() []error`): the message is the original one, and
  `errors.Is` / `errors.As` still reach `api.ErrNotFound`, `api.ErrConflict`,
  the `*api.HTTPError`, `auth.ErrNoToken`… The exit codes 77 / 78 and the 429
  handling of `cmd/webdav_ratelimit.go` rest on that.
- `ErrNotExist` and `ErrExist` **are** `os.ErrNotExist` / `os.ErrExist`: a bare
  one satisfies `os.IsNotExist`, which x/net/webdav uses to pick its statuses
  and which does not unwrap. One that carries the API's answer does not, hence
  `webdavErr` in `cmd`, which flattens any `vfs.ErrNotExist` to the bare
  `os.ErrNotExist` before the handler sees it (and `Mkdir` maps `ErrNotDir`
  there too: a parent that is a file is a 409, like a missing one).
- `classify` gives the error of an API **mutation** its status sentinel (401 or
  `auth.ErrNoToken` / `ErrNoRefreshToken` → `ErrUnauthenticated`, 403 →
  `ErrForbidden`). It is not applied to path resolution: an error met while
  listing or looking a name up reaches the caller as it is, so a WebDAV status
  that depended on the step that failed did not move. Extending it there was
  weighed and left: `writeFileHandle.Patch` and `copyErrorStatus` answer 403
  to `ErrForbidden`, so a 403 met while resolving a path would move a
  PROPPATCH from an error to a 207 / 403, and a COPY likewise.
- `Copy` takes a destination for free only when its lookup answers
  `ErrNotExist`; any other failure is a `CopyError` at `CopyDestination`
  carrying none of the three sentinels of that step (a 429 crosses bare), and
  nothing is copied. `copyStatus` answers it 500.
- `api.ErrRateLimited` is never given a sentinel, nor wrapped in a `CopyError`.
- Not produced yet, so not declared: `ErrCrossDataroom` (the methods take one
  dataroom ID; `webdavFS.Rename` and `copyNode` compare the two IDs themselves).
- No `net/http` in `vfs`: a status is read from `api.HTTPError.Status`
  (`httpStatus`), an API sentinel with `errors.Is`.

`vfs` never writes to stderr. What it has to tell the operator and no caller
(a store suspended after a failure, and its return; a quota that could not
be read; a lock the API did not renew, retake or release) goes to
`Options.Logf`, nil discarding it. `Options.Logf` is never called under
`FS.mu`: `wroteLocked` notes the report, `FS.unlock` (every release of the
mutex goes through it) makes the call once unlocked. `FS.Quota` caches the
absence of counters (a failed `GET /stats`, or an API without them) for the
TTL like the counters, so a failure is asked for and logged once per TTL and
per dataroom, not once per sub-folder of a listing; a fetch that failed because
the caller's context ended is neither cached nor logged. `newWebdavFS` plugs `webdavLogf`, which
prefixes `webdav: ` and escapes the arguments (`ui.Escape` for a string,
`ui.EscapeLines` for an error): the messages are those `cmd` printed before.
`webdav serve` closes the tree (`FS.Close`: the store, and the base context of
the open `vfs.File` handles) when it returns, and
returns only once the server is done for good: `serveUntilDrained`
(`cmd/webdav.go`) calls the shutdown path after `srv.Serve` (which returns as
soon as `Shutdown` closes the listener, requests still in flight) and waits
for it, then for the lock loop (`LockManager.Run` → `ReleaseAll`).
`newWebdavShutdown` is that single path (SIGINT/SIGTERM, auth expiry, a server
that stopped on its own), run once, every caller returning when the run is
over; the drain is bounded by `webdavDrainTimeout` (15 s).

Coordination and storage are separate (`internal/vfs/metastore`):

- coordination lives in `FS`, in memory, under `FS.mu`: the generation of each
  listing as this process changed it (`gen`), the fetches in flight
  (`inflight`), the refresh slots, the sessions. `gen` is read and bumped
  through `genLocked` / `bumpGenLocked` only (+1 per bump, which
  `listingFetch.currentLocked` counts on), and pruned when it has doubled
  since the last prune (`pruneGensLocked`, `minGenSweep` 1024, amortized
  O(1)): it keeps the folders with a fetch in `inflight` or a lookup in
  `lookups`, drops the rest, and raises `genFloor` (what an absent key reads)
  above every value held, so a superseded fetch or lookup never finds its
  value again;
- the data lives behind `metastore.MetaStore` (context and error everywhere;
  `Options.Store`, nil → a `memstore`; `redisstore` is the other
  implementation, see "Redis metadata store"): the listings (`GetListing`,
  `ListingMeta` — `FetchedAt` and `ETag` without the nodes —, `GetNode` — one
  child of a held listing —, `GetNamed` — `GetNode` and the `GetEntry` of the
  same folder and name in one read, what `Lookup` and `cachedFileID` ask
  (`FS.namedLocked`) —, `PutListing`, `PutListingIf`, `RenewListingIf(key,
  etag, fetchedAt, gen)` — the fetch time and ETag of a held listing, nodes
  untouched, generation compared and bumped like `PutListingIf`; false and
  nothing written when the generation moved or the listing is gone —,
  `UpsertNode`, `RemoveNode`, `DeleteListing`, `DeleteSubtree`; `EditListing` is gone, the
  two edits in place are `UpsertNode` / `RemoveNode`, which keep the fetch
  time and empty the ETag), keyed by `ListingKey{DataroomID, Path}`
  (clean absolute path, `/` for the root). Every write to a listing is atomic
  and bumps a **generation the store holds** (`Generation(key)`), which is
  what a store shared by several processes coordinates on: a fetch reads it
  when it starts (`listingFetch.storeGen`) and stores its answer with
  `PutListingIf(…, gen)`, refused when another writer went by, so an answer
  of the API never overwrites a newer edit of another instance. A 304
  (`listingFetch.unchanged`, the ETag still set: no edit replayed, no node
  hidden) is stored by `RenewListingIf` instead, and by `PutListingIf` with
  the nodes held when that answers false (`storeFetchedLocked`). The entries (`GetEntry`,
  `PutEntry`, `DeleteEntries(dataroomID, parentPath)`,
  `DeleteEntriesBelow(dataroomID, path)`), keyed by
  `EntryKey{DataroomID, ParentPath, Name}`, an `Entry{Node *Node, FetchedAt}`
  with a nil node being negative; the dataroom list (`GetDatarooms`,
  `PutDatarooms`, `DataroomList{Items []DataroomInfo, FetchedAt}`). The entry
  operations are apart from the listing ones: `DeleteSubtree` drops no entry
  (`DeleteEntriesBelow` is the one method the study did not list). The store
  decides no TTL, for entries either. The store is read and written with
  `FS.mu` held, so a generation check and the write that depends on it are one
  step; the API is never called under it. A store that fails, a write
  or a read (`FS.wroteLocked`, `readLocked`; not a read whose context is
  over), is **suspended**: the FS goes on with an empty private memstore for
  `TTL + MaxStale`, then takes the configured store back (`FS.unlock`,
  `FS.resume`, clock `FS.now`), one `Options.Logf` line per change. The read
  itself stays a miss. `FS.storeEpoch` counts the changes: a fetch or a
  lookup whose store changed since it started does not store its answer
  (`storeGenLocked`). Only `FS.Close` closes the configured store.
  `ownDataroomStore` follows the same rule. Entries are stored under the
  store's generation of their folder (`PutEntryIf`: `lookupByName`,
  `upsertLocked`, through `putEntryLocked`), and what is read from the store
  goes through the hidden-node filter (`heldLocked`, `heldNodeLocked`,
  `namedLocked`). A fetch that resolves the dataroom's session itself reads
  the store's generation again once it is resolved, before asking the API. A store may drop what is too old to be served (Redis gives
  its keys a lifetime) but never serves a value as younger than it is.
  **The memstore an FS builds** (`newMemStore`, for `Options.Store` nil and
  for a suspension) has the Redis lifetimes (`memstore.NewWithOptions`,
  `memstore.Options`): `ListingLife` = `ListingRetention(TTL, MaxStale)` from
  `FetchedAt` (the put time when zero; `UpsertNode` / `RemoveNode` keep it,
  `RenewListingIf` restarts it), `EntryLife` = TTL, `NegativeEntryLife` =
  `NegativeTTL` (TTL when zero), `GenerationLife` = 2 × `fetchTimeout()`,
  clock `FS.now`. Past its lifetime a value reads absent on every path
  (`GetListing`, `ListingMeta`, `GetNode`, `GetNamed`, `GetEntry`; a renewal
  or an edit sees no listing), and a sweep removes it: run by the first call
  once due, every quarter of the longest lifetime, O(what it holds) under its
  mutex, no goroutine. A generation is dropped once its listing is gone and
  `GenerationLife` passed since it last moved **or its listing left**
  (expired or deleted: `dropListingLocked` dates it then, so a fetch started
  while the listing was held is not refused). A listing without a generation
  reads the **floor** (`Store.floor`, 0 until a drop, then above every
  generation dropped), in `Generation` and every conditional write alike, and
  its first write moves it to floor + 1 (what `editedLocked` expects). The
  generations of a listing never go down and move with every write, so a
  value read before a drop, an old floor included, is never answered again
  once the listing changed. So a folder deleted or renamed elsewhere
  leaves the memory with its sub-listings. `memstore.New()` (lifetimes zero)
  keeps everything for ever, generations included: what tests build.
  `Store.Held()` counts listings, entries, generations (tests).
  `memstore.GetListing` returns a copy
  of the listing's header (`FetchedAt`, `ETag`) over the stored `Nodes` slice,
  which is shared and never written through.
- `metastore.Node` is the serializable value a listing holds (no pointer, no
  unexported field; `Type` file / dir / symlink, `Mode` + `ModeSet`: a mode
  is stored when `HasMode()` (`ModeSet || Mode != 0`), so an explicit 0 is one,
  and a nonzero `Mode` counts as stored whatever the flag). The data types are defined in `metastore` and aliased in `vfs`
  (`vfs.Node`, `vfs.Listing`, `vfs.ListingKey`, `vfs.NodeType`): `vfs` imports
  `metastore`, never the reverse, and a front end imports `vfs` only.
  `vfs.NodeFromInfo` converts a `service.DataroomNodeInfo`. `metastore` imports
  the standard library only.
- `Node.Sealed` (`metastore.Sealed`: `Name`, `Target`, `MIMETypeID`,
  `MIMEType`) is the encrypted fields of a node as the API answered them,
  filled only with `vfs.Options.KeepSealed` (about 2.5 KiB per node, useless
  to a memstore), for a store that keeps them in place of the decrypted ones.
  A node written through a route that does not answer its encrypted form has
  none. `metastore.Codec` (`Hash(dataroomID, s)`: the dataroom's name hash;
  `Open(ctx, dataroomID, *Node)`: decrypts `Sealed` into the node) is what
  such a store needs; `vfs.New` hands its own (`internal/vfs/codec.go`, from
  the sessions the FS holds, never resolving one: no session → no hash, a
  miss) to a store that implements `metastore.Binder`.
  `vfs.ListingRetention(ttl, maxStale)` is how long a listing can still be of
  use to an FS (TTL + max stale + the refresh window): the lifetime a store
  gives it.

### Redis metadata store (`internal/vfs/metastore/redisstore`)

`cache.store: redis` (`memory` by default), `cache.redis.url`
(`redis://` / `rediss://`, **password included**: in `secretKeys` of
`cmd/config.go`, never in an error, a `--debug` line, a span or a metric;
`config.Load` refuses `redis` without a URL or with another scheme, without
quoting it), `cache.redis.high_confidentiality`. Flags `--cache-store`,
`--cache-redis-url`, `--cache-redis-high-confidentiality` on both front ends
(`addCacheFlags`). `cmd.newMetaStore(ctx, cfg, maxStale)` (`cmd/metastore.go`)
is the only caller of `redisstore.New`: `ListingLife =
vfs.ListingRetention(cache.ttl, maxStale)` (`maxStale` is 0 for `fs mount`,
`cache.max_stale` for `webdav serve`), `EntryLife = cache.ttl`,
`NegativeEntryLife = cache.negative_ttl`; called after `serveStartupCheck`,
before `vfs.New`, so a Redis that does not answer or is older than 7.4
(`HPEXPIRE`) fails the start. `vfs.Options.KeepSealed` is set with high
confidentiality on a Redis store only. `cmd` imports `redisstore`, `vfs`
never does (its tests may).

- Keys: `<prefix>:v2:{<dataroom ID>}:<kind>:<h>`, prefix `retyc`, `h` =
  `Codec.Hash(dataroomID, path)`: no name in a key; the braces are a hash tag
  (one slot per dataroom). `ls:<h>` hash = the listing (one field `n:` +
  `Hash(name)` per child, the node as below, the field `m` = `<wire version>:<lifetime
  ms>`, the field `t` = the listing tokens it was written under, and the
  field `etag`, apart so a script empties it with an `HDEL`; `PEXPIRE` on the
  key); `e:<h>` hash = the entries of the folder (field `Hash(name)`, a
  lifetime per field, `HPEXPIRE`, and the field `t` = the entry tokens, which
  lives as long as its longest entry and is only written to a new hash, HSET
  clearing a field's lifetime); `tl:<h>` / `te:<h>` string = the listing /
  entry **token** of the folder (128 random bits, drawn in Go with
  `crypto/rand` and passed in `ARGV`); `g:<h>` string = the generation (a
  random number below 2^51 when created, `INCR` by every write that bumps
  it, kept 24 h). `v1` keys (subtree index `sub:`, counters from 1) are
  never read.
- **Eviction** (`maxmemory-policy allkeys-lru`): an absent key always means
  "invalid", never "unchanged"; an eviction may cost a miss, never a stale
  value nor a write that should have been refused. A value records, in its
  `t` field, the tokens of every folder from the root down to its own
  (joined by `,`, root first), `SET NX`ed by its write; reads `MGET` the
  tokens in the same `MULTI` and treat a differing or absent one as no value
  (`sameTokens`). `DeleteSubtree(p)` is one `SET` of a new `tl:<h(p)>`,
  `DeleteEntriesBelow(p)` one `SET` of `te:<h(p)>`: no walk, the listings
  (resp. entries) at and below `p` are stale, the two families stay apart.
  A write of an entry into a hash recorded under other tokens empties it
  first (`put_entry.lua`). The generation given to `vfs` is the stored
  number + a 52-bit fingerprint (first 13 hex digits of `redis.sha1hex`) of
  the listing tokens of the folder and its ancestors (`lua/lib.lua`,
  `current`): it moves with every write (+1, which `vfs.editedLocked`
  relies on), with a `DeleteSubtree` above (a fetch in flight is refused, as
  the `sub:` registration did), and with the eviction of the generation or
  of a token. The sum stays below 2^53, exact in a Lua number; a stored
  number outside `[1, 2^52)` is a script error. `Generation()` never
  answers 0 (it creates an absent generation with a random start and
  settles the tokens); a conditional write whose generation is absent is
  refused. Tokens and generations are only ever lengthened (`PEXPIRE … NX`
  then `… GT`, `extend` in `lib.lua`), tokens to `tokenLife` (longest value
  lifetime + 1 min): instances with other `cache.*` durations share them
  (`TestScripts_TokenLifetimeOnlyGrows`); their expiry only invalidates.
  `evict_test.go` simulates evictions with `UNLINK` (targeted cases and
  `TestEviction_Random`, a model of the API's truth with two instances and
  random evictions: nothing served differs from the truth).
  A clear node without a name is not written (`appendNode`), as a sealed one
  without its payload is not: the read refuses it and would drop the listing.
- Redis is the only clock: a value is stored with the lifetime left to it
  and read back with what remains, so `FetchedAt` is computed on the reader's
  clock. Reads are one `MULTI` (value + TTL + tokens: never the TTL or the
  tokens of a newer value; one `MGET` more than before); `GetNamed` is one
  too (`HMGET` + `PTTL` of the listing, `HMGET` + `HPTTL` of the entry, one
  `MGET` of both token families): resolving a name is one round trip per
  path component, not two. `RenewListingIf` is `lua/renew_listing.lua`:
  under the expected generation and only for a listing this wire version
  holds **under the tokens of now** (one written before a `DeleteSubtree`
  is never renewed back to life), the field `m`, the `etag` field,
  `PEXPIRE` with what is left of a full lifetime, the bump, as
  `put_listing.lua` does without the nodes. Writes are Lua scripts
  (`lua/*.lua`, `go:embed`, one per operation, each prefixed by
  `lua/lib.lua` in `newScript`; `scripts.go`): one round trip, the
  generation compared and bumped in the same step, no retry. They are run
  through `redis.Script.Run` (`EVALSHA`, then `EVAL` on `NOSCRIPT`): nothing
  is loaded at startup and nothing is to reload after a restart or a
  `SCRIPT FLUSH` (`TestScripts_SurviveScriptFlush`). Each binary carries its
  own scripts. Every key goes through `KEYS[]`, named in Go (`Store.folder`:
  `tl` / `te`, root first): no script builds a key, so with the hash tag the
  store is fit for Redis Cluster, which is not wired (a standalone Redis or a
  primary with replicas today).
  A listing above `maxListingBytes` (64 MiB of fields) is not stored.
- `HighConfidentiality` decides what is **written** (sealed nodes: the API's
  ciphertexts, nothing encrypted here; a node without sealed form drops the
  listing rather than leaving the name out), the value alone what is read: a
  hash may hold both forms, and a sealed node costs one AGE decryption per
  read (`Codec.Open`), once per process: `vfs` remembers what a payload
  decrypts to (`sealedMemo`, `internal/vfs/codec.go`, the field `FS.sealed`:
  SHA-256 of dataroom ID + payload → plaintext, for `Sealed.Name` and
  `Sealed.Target`; `sealedMemoMax` = 100,000 entries, the oldest recorded
  leaving first; its own mutex, never `FS.mu`; a failure is not recorded;
  emptied by `FS.Close`, never written anywhere). The MIME type is resolved
  by the session's table at each read (`DataroomSession.SealedMIMEType`); a
  legacy `type_enc` is still decrypted each time. A value of another wire
  version is read as absent.
- **Decryption happens outside `FS.mu`**: the Redis round trip and the binary
  decoding stay under it, `Codec.Open` (and the memo's SHA-256) do not. `vfs`
  reads the store with a context made by `metastore.LeaveSealed`
  (`FS.leaveSealed`, set only for a store bound to the codec, `FS.openLater`:
  a memstore pays nothing); the store then returns a sealed node **unopened**
  (`Node.Unopened()`: `Name` empty, `Sealed` filled; `hasher.open` /
  `openAll` skip the codec) and `vfs` opens it once the mutex is let go:
  `FS.openNode`, `FS.openListing` (a copy, GOMAXPROCS at a time, sorted by
  name + ID as the store sorts an opened listing). Same semantics as before:
  a node that does not open makes its listing a miss (`readDirStale`,
  `readDirRefreshed`: the mutex is taken again and the listing fetched; the
  fetch's `held` is dropped), and its `GetNamed` half absent (`Lookup` →
  `lookupUnlisted`, the Entry opened there too). Reads under the mutex whose
  nodes never leave it and need no decrypted field (ID, type, version, mode,
  dates) use `sealedStoreCtx` and open nothing: `upsertLocked` (+ its
  `GetEntry`), `nameTaken`, `forgetVersionless`, `dropListingUnless`,
  `cachedFileID`, the first read of `forgetIDLocked`. Two still open under
  the mutex, with `storeCtx()`, because they need the plaintext: `move` (the
  node goes back to the store with its target and MIME type, and a store
  may hold both forms) and the full-listing fallback of `forgetIDLocked`
  (the name of a node renamed elsewhere): one node, or a rare path, the memo
  most often answering. `FS.openHook` is the test seam
  (`TestSharedRedis_SealedNodesAreOpenedOutsideTheMutex`).
  Every decryption of the process takes one of `decryptSlots` (half of
  GOMAXPROCS, 1 at least; `codec.go`): unbounded, parallel walks took
  every CPU and the goroutine holding `FS.mu` for its Redis read waited for
  one (measured: 24 CPUs, ≈ 500 ms without the bound, 210 ms with it, 280 ms
  when decryption was under the mutex). On one CPU the walk costs the same
  CPU either way (≈ 170 µs per name); what changes is that the mutex is no
  longer held for the decryption of a whole listing.
- Values of nodes and entries (`wire.go`, `wireVersion` 1) are **binary**,
  written by hand with `encoding/binary`, one form only (the JSON it replaced is not
  read: about a third of its size, and several times faster to decode). A
  value is a frame: the version byte, a uvarint `L`, `L` bytes of fields,
  nothing after. Fields of a node, in this order: type byte (0 none, 1 file,
  2 dir, 3 symlink), flags byte (1 sealed, 2 mtime, 4 ctime, 8 mode stored:
  `flagModeSet`, so an explicit 0 survives; an older reader ignores it and shows the
  default, as before, and an older writer that puts the node back drops it until the
  next full listing: rolling upgrades only), ID, parent ID,
  version ID (idents), chunk count, size, mode (uvarints), mtime and ctime
  when flagged (varint Unix seconds + uvarint nanoseconds, read back in UTC:
  the nanosecond `vfs` holds; a zero time has no flag), then name, target,
  MIME type (strings) for a clear node, or the MIME type ID (ident) and the
  AGE payloads of name, target, MIME type (strings holding the **binary**
  payload) for a sealed one. Fields of an entry: kind byte (0 negative, 1
  positive), lifetime in ms (uvarint), and for a positive one a uvarint `Ln`
  + the `Ln` bytes of its node's fields. A string is a uvarint length + its
  bytes; an ident is `0x00` + 16 bytes for a canonical UUID (36 characters,
  lower case), otherwise uvarint(length + 1) + the string as it is (`n1`, an
  upper-case UUID: any string comes back unchanged). The listing's `m` and
  `etag` fields are untouched (the Lua scripts read them).
  **Rule of evolution**: a field is added **at the end of its block of
  fields** (node or entry), optionally announced by a flag bit free today; a
  reader stops after the last field it knows, ignores the rest of the `L` /
  `Ln` bytes and the flag bits it does not know — which is why every block
  carries its length. Only for a field an older reader may miss (it writes
  the node back without it). Anything else (field removed, reordered, a new
  type byte) is another `wireVersion`, read as absent by this one. Absent
  too, never an error nor a panic: a value cut short, a length beyond what
  is left (`reader.take` compares before slicing, nothing is allocated from
  a length), a varint that does not end, an unknown type or entry kind,
  nanoseconds ≥ 1e9, bytes after the frame, a node without a name. A node of
  a type the format has no byte for is not stored (`typeByte`).
  `FuzzDecodeNode` (`wire_test.go`): no panic, and a value read is written
  back as one that reads the same.
  The API sends the payloads armored (2,360 bytes for a name, 1,691 without
  the armor): `appendNode` takes the armor off at the write (`unarmor`,
  `filippo.io/age/armor`, base64 decoding only: **the AGE bytes are the
  API's, nothing is ever encrypted, nor decrypted, for the store**), a
  payload that is not armored being binary already (a node read from Redis
  and written again) and stored as it is. A name or a target whose armor
  does not decode is no sealed form (the listing is dropped, the entry not
  stored); a `type_enc` whose armor does not decode is left out. Reads return
  `Sealed.Name` / `Target` / `MIMEType` in binary, never armored again:
  `metastore.Sealed` holds either form and `Codec.Open` takes both
  (`crypto.DecryptPayloadToString`, told apart by `crypto.IsArmored`, behind
  `DataroomSession.OpenSealedName` / `OpenSealedTarget` / `SealedMIMEType`).
  `sealedMemo` digests the payload as it comes, so one name seen armored
  (from the API) and binary (from Redis) is two entries, on purpose:
  normalizing would decode an armor at every read.
- Reading a cache by hand: `redis-cli` shows the values as escaped bytes.
  `redisstore.Describe(kind, field, value)` (`describe.go`) decodes one with
  the store's own decoder and no codec (`*NodeDescription`,
  `*EntryDescription`, `*MetaDescription`, `*TokensDescription` for a field
  `t`, the ETag, the generation, a token; a
  sealed name is `<AGE payload, N bytes>`, never opened; an unreadable value
  is an error wrapping `ErrUnreadable` that tells its size and first byte,
  never its content), with `ParseKey`, `KeyPattern` and the `Kind*`
  constants. `scripts/redis-cache-dump` (`package main`, `go run
  ./scripts/redis-cache-dump -url … [-prefix] [-dataroom] [-kind ls|e|g|tl|te]`,
  or `scripts/redis-cache-dump.sh`; URL from `-url` or `REDIS_URL`, never a
  `RETYC_*` variable, never printed) prints every key as JSON with it: TTL,
  meta, ETag and children of a listing, entries with the TTL of their field,
  tokens of a listing or an entries hash, generation, token. Read-only (SCAN,
  PTTL, HGETALL, HPTTL, GET). Not in the release: `.goreleaser.yaml` builds `main: .`
  only. A change of the format changes `Describe` with it, nothing else.
- The dataroom list is never written to Redis (it is one user's): it stays
  in the `Store`'s memory. Before `Bind`, or for a dataroom whose session is
  not resolved, the store reads and writes nothing.
- Errors go through `Store.fail`, which takes the URL and the password out
  of the message. Every call is bounded by 2 s (`ioTimeout`): the FS holds
  `FS.mu` across it.
- WebDAV on a store over the network: x/net/webdav lists a folder, then
  opens each child by path for its properties (three lookups by name per
  child). `requestListings` (`cmd/webdav.go`, put in the context of a
  `PROPFIND` by `markReadRequests`) keeps the listings that request read, and
  `webdavFS.Stat` answers a child from them: one `GetListing` per folder, no
  `GetNode` per child (`TestPropfind_ChildrenAreAnsweredFromTheListing`).
- Observability (`observe.go`): each method wraps its round trip, and only
  that, in `begin(ctx, op, dataroomID)` … `operation.end(err)`. `end` always
  observes `retyc_cli_vfs_store_op_duration_seconds{op,result}`; the span
  `redis <op>` exists only when `trace.SpanContextFromContext(ctx).IsValid()`,
  so a write made with `storeCtx()` (`context.Background()`) is measured and
  never a root trace. `PutListingIf` / `PutEntryIf` are `put_listing` /
  `put_entry`, `GetNamed` is `get_named` (one span where `get_node` +
  `get_entry` were two), `RenewListingIf` is `renew_listing`; `UpsertNode` that drops the listing is still `upsert_node`. A
  call that returns before Redis (keys that cannot be named, `GetDatarooms`,
  `PutDatarooms`) measures nothing; `redis.Nil` on `GetEntry` is `ok`. The
  span holds no key, field, hash, value, path nor URL; an error is its type
  (`telemetry.RecordError` on the client's error, not on the `storeError`
  around it). Decryption of sealed nodes happens after `end` and is not under
  the span. In `vfs`, the writes that follow a fetch carry its trace
  (`context.WithoutCancel`: `storeFetchedLocked`, the `DeleteListing` of a
  listing answered 404, the `putEntryLocked` of `lookupByName`); the edits and
  invalidations (`edit.go`, `invalidateLocked`, `invalidateSubtreeLocked`,
  `dropEntriesLocked`, `nameTaken`, `cachedFileID`, …) still use `storeCtx()`
  and have no span. `observe_test.go` holds the tests, privacy rule included.
- Tests need a real Redis: `REDISSTORE_TEST_URL` (e.g.
  `redis://localhost:6379/15`; `scripts/start-redis.sh`), skipped without it
  and **failed when `CI` is set**; each works under a random prefix it
  removes, never `FLUSHDB`. `redisstore_test.go` for the store,
  `internal/vfs/redis_shared_test.go` for two `vfs.FS` over one Redis.
  `_ci.yml` runs a `redis:8.10.2` service.

Writes (`internal/vfs/writer.go`). Two entry points over one upload
(`FS.upload`): session, then the folder through the cache
(`resolveFolderID`), then a slot of `FS.uploadSlots`, then the route the size
calls for.

- **Uploads are bounded across files**: `vfs.Options.UploadConcurrency`
  (`api.concurrency.upload`, filled by `webdav serve` and `fs mount`; zero →
  `vfs.DefaultUploadConcurrency`, 4, kept equal to `config.DefaultConcurrency`
  by `TestVFSDefaultUploadConcurrencyMatchesConfig`) uploads send at once,
  whatever the number of files; the chunks of one file are bounded apart by
  `service.UploadChunks`. The slot is taken after the session and the folder
  are resolved and before the content is read, and waited for with the
  caller's context (`TestCreate_UploadsAreBoundedAcrossFiles`,
  `TestCreate_WaitingForASlotEndsWithTheContext`). Without it a mount
  flushing thousands of spools at once (20,000 `touch`, then the unmount's
  `closeSpools`) sent up to the HTTP/2 stream limit at once and stalled the
  API: it holds a database connection per upload (pool of 60) and a thread
  per synchronous step (40), and the two waited for each other until their
  30 s timeouts.

- `FS.Create(ctx, dataroomID, path, size, mtime, r io.Reader) (Node, error)`:
  size known, content streamed, no temporary file. ≤
  `service.SmallUploadMaxSize` → read in memory, one request
  (`UploadSmallFileWithMtime`); above → `initUpload` (the overwrite shortcut
  moved from `cmd`: a node found by `cachedFileID`, or given by the spool,
  takes its version directly, 404 / 410 → the listing is dropped and the full
  path recreates the node) then `service.UploadChunks`, and
  `DiscardFailedUpload` on failure, its outcome sent to `Options.Logf` (the
  `webdav: cleaned up orphaned node: …` lines). A zero `mtime` declares no
  `client_mtime` (WebDAV), otherwise it is the version's.
  **`r` is first read once the upload is accepted** (session, folder, and for
  a streamed file node + version): a contract, tested
  (`TestCreate_ReadsNothingBeforeTheUploadIsAccepted`), that the WebDAV
  adapter relies on to tell an `OpenFile` failure from a `Close` one.
- `FS.OpenSpool(ctx, dataroomID, path, existing *Node, truncate bool) (Spool, error)`:
  size unknown. One file of mode 0600 per spool in `Options.SpoolDir`
  (`os.TempDir()` when empty; `os.CreateTemp`, a name that says nothing of the
  file), created at open, removed by `Close`. No API request at open.
  `Spool` is `io.ReaderAt` + `io.WriterAt` + `Truncate`, `Size`, `ModTime`,
  `SetModTime(ctx, t)`, `Node() (Node, exists)`, `Dirty`, `SetPath`,
  `SetMode(mode)`, `CopyFrom(ctx, srcPath) (Node, error)`,
  `Flush(ctx) (Node, error)`, `Unlinked()`, `Close`.
  - `SetMode`: the mode a **pending** spool's first `Flush` declares with the
    creation of the node (`content.mode` → `access_mode` of `POST /node/file`
    or `POST /node`), no request of its own; ignored once the file exists
    (`FS.Chmod` is the way then).
  - `CopyFrom`: a pending spool with no content becomes the server-side copy
    of `srcPath` (`FS.Copy`, never replacing), clean on the copied node, its
    content hydrated lazily; it holds `flushing` and `content` for the copy.
    `ErrSpoolNotEmpty` otherwise, nothing sent. Unlinked meanwhile: the copy
    is deleted (`undoUpload`) and a zero `Node` returned, as for a `Flush`.
  - States: **pending** (`existing == nil`: nothing at the API until the first
    `Flush` that succeeds, `Node()` says `exists == false`, dirty from the
    start so a `touch` flushes an empty file; "nothing at the API" is strict
    for the single-request route only, ≤ 8 MiB, which the server stores or
    drops whole: above it the node and the version are created before the
    chunks and a failed `Flush` deletes them best effort, so a node without a
    complete version can outlive a `Flush` whose cleanup failed too), **clean** (content = the
    version of `Node()`), **dirty**. `existing` + `truncate` starts empty and
    dirty.
  - **Lazy hydration**: opened on an existing file without `truncate`, the
    spool downloads nothing until the first `ReadAt` or `WriteAt`, then copies
    the whole version in through `FS.Open` (any chunk size). Exceptions that
    download nothing: `Truncate(0)` first; a `WriteAt` from offset 0 covering
    the whole content. That write lets the version (`src`) go only once it
    is stored in full (`covered`): cut short (`ENOSPC`), it answers
    `ErrSpoolFull` with the `n` bytes stored, and `[n, srcSize)` is brought in
    behind them at once (`srcFrom`), or, when that copy fails too, by the next
    read, write or `Flush`, which answer the copy's error until there is room;
    the spool never reads a hole where the version had bytes. A `Truncate`
    before the copy only bounds it (`srcSize`); a `Flush` of a spool left dirty by a truncation hydrates
    first. No partial (per-range) hydration.
  - `Flush`: nothing when clean; otherwise the current size goes through
    `upload` (single request ≤ 8 MiB, empty included; version + chunks read
    from the spool file above), `client_mtime` = `ModTime()`: the time given to
    `SetModTime`, else **the time of the last write or truncation** (not the
    time of the flush: what `getattr` served while the file was open is what
    the version is dated). Success → clean, listing edited, node returned.
    Failure (a context that ends included) → what was created is discarded,
    the spool stays dirty and intact, `Flush` can be called again. A write
    after a `Flush` makes it dirty again: the next one is another version.
  - `SetModTime` on a dirty spool is kept for the `Flush`, on a clean one it
    is `FS.SetModTime` (a `PATCH`, no version). `FS.SetModTime` knows nothing
    of spools: the front end routes.
  - `SetPath`: the front end tells a spool its file was renamed, since the
    single-request route goes by parent and name.
  - `Rename(ctx, newPath, rename func(exists bool) error)`: the rename of
    the file serialized with `Flush` (under `flushing`): waits for the flush
    in flight, calls `rename` with whether the API holds the file at that
    instant, records `newPath` when it succeeds; `ErrNotExist` unlinked,
    `ErrClosed` closed, the context's error while waiting, `rename` not
    called. `SetPath` is for a path that changed without the file being
    renamed (a folder above it moved).
  - `Unlinked()`: the front end tells a spool its file was removed (unlink of
    an open file), for good. From then on it is a local file: `Node()`
    answers `exists == false`, `Dirty` false, `Flush` returns a zero `Node`
    and no error at no request, `SetModTime` only dates the local content,
    reads, writes and truncations go on until `Close` (a version not hydrated
    yet is still downloaded by the first of them). It cancels a `Flush` in
    flight and returns once it is over; an upload that completed all the same
    is undone (`undoUpload`: the node it created, or the version added to a
    node other than the one unlinked, deleted best effort; listing dropped).
  - Locks, in order: `flushing` (a channel: `Flush` and `SetModTime`, the only
    one waited for with a context), `content` (RWMutex on the bytes: shared by
    reads **and by the upload of a `Flush`**, exclusive for writes,
    truncations, hydration, `Close`), `mu` (fields). So two `Flush` send one
    version, a write issued during a `Flush` **waits** for it (the version
    sent is one state of the file) and then makes the spool dirty, and
    `Close` during a `Flush` cancels it (`ErrClosed`), waits, removes the
    file. After `Close`: `ErrClosed`; a second `Close` does nothing.
  - `spoolError`: `ENOSPC` / `EDQUOT` on the spool file → `ErrSpoolFull`,
    still matching the errno. `FS.newSpoolFile` is the test seam.
- Errors of both (`uploadFailed`, `uploadError`): a 404 on node or version
  creation is the parent deleted elsewhere → the listings that named it are
  dropped, `ErrNotExist`; storage → `ErrStorageExceeded`, and the listing
  forgets a node it shows **without a version** (the API just deleted it,
  `forgetVersionless`); 403 → `ErrForbidden`; 410 on the single request →
  `ErrNameBeingDeleted`; parent is a file → `ErrNotDir`; the root → `ErrIsDir`;
  `api.ErrRateLimited` untouched. Chunks refused on a node that **existed**
  (overwrite shortcut or holder of the name), the caller's context not being
  over, drop the parent's listing and entries (`uploadChunked`): the failure
  may be the node deleted or replaced elsewhere. `unsafe_write` is the API client's setting,
  `vfs` does nothing about it.
- WebDAV on top (`cmd/webdav.go`), statuses unchanged: a PUT with a
  `Content-Length` is `createHandle`, a pipe into `FS.Create` running in a
  goroutine since `OpenFile`, which returns at the first read of the pipe
  (`startReader`) or with the error of `Create` when it fails before; the
  upload lives on the request context (`context.AfterFunc`) until the whole
  body is received: the `Write` that brings the bytes written to the
  `Content-Length` detaches it (`keepComplete`, also called by `Close` for an
  empty body), whatever the size, so a client that leaves after its last byte
  loses neither the single request nor the last chunks; a body still short
  fails at `Close` and what was created is discarded. A PUT without one (chunked), a LOCK placeholder and
  the target of a PROPPATCH are `writeFileHandle`: an `OpenSpool` used as the
  buffer, then **`FS.Create` from the spool on `Close`, not `Spool.Flush`** —
  a flush declares a `client_mtime` and a WebDAV upload declares none. An
  empty non-PUT handle uploads nothing (lock-null resource).
- A FUSE driver does itself: route `truncate` / `utimens` / `getattr` by
  inode to the open spool (`Truncate`, `SetModTime`, `Size` + `ModTime`),
  pass `O_TRUNC` as `truncate` (`CAP_ATOMIC_O_TRUNC`), show a pending spool in
  its parent's `readdir`, call `Flush` on the `flush` of the handles that
  write (idempotent; the handles that only read the spool must not send it),
  give the mode of a creation to `SetMode` before the first `Flush`, answer
  `copy_file_range` of a whole file into a new one with `CopyFrom`,
  call `SetPath` after a rename, `Unlinked` after the unlink of an open file
  (once the node is removed; at once for a pending spool), `Close` on the
  last `release`.

Positioned reads (`internal/vfs/reader.go`). A version is stored in chunks,
each encrypted on its own: `vfs.File` (`io.ReaderAt`, `ReadAtContext`,
`io.Closer`, `Node()`) reads at any offset by downloading the chunks the read
enters, through `service.ReadDataroomChunkBounded(ctx, client, versionID,
index, sess, maxPlain)` — one chunk downloaded and decrypted, same
`crypto.decrypt` span, metric and 404 retry as `StreamDownloadChunks` (they
share `decryptChunk`), nothing kept. A `File` reads the version it was opened
on, even if the file is replaced, renamed or deleted afterwards.

- **The chunk size is a property of the version, not a constant.** The client
  that uploads chooses it: 8 MiB for this CLI (`service.UploadChunkSize`),
  `NUXT_PUBLIC_UPLOAD_CHUNK_SIZE` for the web app (8 MiB in production, 16 MiB
  in preprod), the cut of its source for a copied file. The cut is uniform (all
  chunks equal, the last one shorter or equal) and the listing does not expose
  the size, only `chunk_count` and the plaintext size. Never write
  `offset / service.UploadChunkSize` on the read side. Each handle settles it
  from `Node.ChunkCount` and `Node.Size`, **at its first read** (`Open` asks
  nothing: an `Open` followed by a `Close` costs no request), by the first of
  these that applies (`file.assumeLayout`, `recallLayout`, `decideLocked`):
  1. one chunk: it is the file, nothing to work out;
  2. the `FS` remembers the size of that version (memo, below);
  3. several chunks and `ceil(Size / default) == ChunkCount`: the default
     (`Options.ChunkSize`, zero → 8 MiB) is **assumed**, no request;
  4. the first read is in chunk 0 whatever the size (offset 0, or an offset
     below `ceil(Size / ChunkCount)`): chunk 0 is downloaded, its length is the
     size, and it was needed anyway;
  5. **one `HEAD`** on chunk 0 (`api.Client.DataroomChunkEncryptedSize`,
     `HEAD /dataroom/node/version/{id}/chunk/{n}`, `Content-Length` = encrypted
     size; `service.DataroomChunkPlainSize` turns it into the plaintext size).
     With a known count the answer must give `ChunkCount` chunks, else
     `ErrChunkLayout` with nothing downloaded, and is an assumption like the
     default; with an unknown count it stands for the length of chunk 0;
  6. the API does not tell and the count is known: `c = ceil(Size /
     ChunkCount)` is assumed; when `ceil(Size / c) != ChunkCount` no uniform
     cut exists and the version is refused at once, without a download;
  7. the count is unknown and the API does not tell: chunk 0 is downloaded
     first for its length.
  Every chunk downloaded is checked against `min(size, Size − i·size)`. One
  that contradicts an assumption corrects it (its own length, or for the last
  chunk `(Size − length) / (ChunkCount − 1)`), is kept, and the read locates
  its offset again (`chunkAt`); one that contradicts a size already measured
  is an error. The comment on `file` proves that once the count matches and
  the lengths are checked no byte comes from a wrong offset, **for any
  assumed size that gives the count**; it rests on the cut being uniform and
  on `ChunkCount` being true, which the reader can only disprove on the
  chunks it reads.
- **Encrypted → plaintext size** (`internal/service/chunks.go`): AGE STREAM,
  `encrypted = H + 16 + plain + 16 × max(1, ceil(plain / 65536))` (an empty
  plaintext still makes one segment). `H`, the AGE header, depends on the
  recipient alone (1627 bytes for a session's hybrid key) and is **measured,
  never written down**: `dataroomSession.chunkEnvelope` encrypts nothing once
  per session. `plainChunkSize` inverts the formula and refuses a size no
  plaintext makes (then `api.ErrNoChunkSize`);
  `TestChunkSizeArithmeticMatchesTheEncryption` checks both against real
  encryption.
- **Memo per version** (`chunkSizes`, `internal/vfs/chunksize.go`, the field
  `FS.chunkSizes`): `versionID → chunk size`, `chunkSizeMemoMax` (4096)
  entries, the oldest recorded leaving first, no expiry (a version is
  immutable), emptied by `FS.Close`, never written to the store. Filled by the
  `HEAD` and by every size a chunk actually read proved; read at `Open`. The
  `HEAD` costs the API a `HeadObject` and counts in the rate limit: **one per
  version at most** per `FS`, and none for a version cut at the default size.
- **An API without the route** is recorded in the same structure for the life
  of the `FS` (`sizeRouteAbsent`), so the route is probed once, not per file.
  A 405 / 501 says it outright (`api.ErrNoChunkSize`). A 404 or 410 **with a code**
  (`CHUNK_NOT_FOUND`, `VERSION_NOT_FOUND`…) comes from the route: present, the read fails
  like any other `HEAD` failure. A 404 without code is ambiguous —
  the route answers it for a chunk the store does not hold — and is settled
  by what follows: the handle goes on with step 6, and if a chunk of that
  version then **downloads**, the version exists and the 404 was the route
  (`routeMissed`); a route that answered a size once (`sizeRoutePresent`) is
  never taken for missing. Any other failure of the `HEAD` (429 once the
  client's retries are spent, 410, 403, 5xx, network) fails the read that
  needed it, wrapped, and the next read asks again. The `HEAD` is not retried
  on 404 the way a chunk download is.
- **`vfs.ErrChunkLayout`** is what cannot be read at an offset: a cut that is
  not uniform, `ChunkCount` / `Size` / lengths that do not agree (more chunks
  than bytes, an empty chunk, a chunk longer than the file, a size told by the
  API that does not make the count), or a chunk beyond `vfs.MaxChunkSize`
  (**32 MiB**, `Options.MaxChunkSize` in tests: the ingress refuses a chunk
  upload request of more than 32 MiB, encryption and multipart included, so no
  larger chunk exists). It is final for the handle: later reads return it
  without a download. Such a version is still readable from start to end
  (`StreamDownloadChunks`, unchanged, concatenates whatever the cut).
- **No chunk beyond the limit is held in memory**: the limit is checked on
  `ChunkCount` at `Open`, on the size the `HEAD` tells, and otherwise by the
  download itself — `api.Client.DownloadDataroomChunkLimit` refuses a response
  whose `Content-Length` exceeds what a chunk of the limit makes once
  encrypted (`encryptedChunkSize`) without reading its body, and reads at most
  that many bytes when no length is announced (`api.ErrChunkTooLarge`, mapped
  to `ErrChunkLayout`). Only the positioned reader passes a limit; the stream
  (`StreamDownloadChunks`, `dataroom cp`, admin download) is unchanged and
  still reads a chunk whole.
- **Window, not a cache**: two decrypted chunks at most per handle
  (`windowSize`), of the size the version was cut at — 16 MiB for an 8 MiB
  cut, 64 MiB at the limit — nothing shared between handles, nothing on
  disk, all released by `Close`. A read pins the chunk it waits for or copies
  from, one at a time; an unpinned chunk is evicted least recently used first,
  and a read that finds both slots pinned waits for one, so the bound holds
  whatever the number of concurrent readers. Readers of one chunk share its
  download, and readers waiting for the chunk size share its `HEAD`
  (`sizeProbe`).
- **Fetch ahead**: a reader is sequential once its run covers `readAheadAfter`
  bytes — an eighth of a chunk, 1 MiB at most (so 1 MiB for 8 MiB chunks). The
  run is the span `[runStart, lastEnd)` its recent reads cover: a read that
  starts in it or at its end continues it (`lastEnd = max(lastEnd, off + n)`),
  and so does one that lands within `readAheadSlack` of either end (the length
  of the read, `readAheadAfter` at least), the run growing to hold it; any
  other read starts a new run. **Reads need not arrive in order**: a kernel
  reading ahead is served by several goroutines (FUSE), and offsets 4, 0, 12,
  8… are one sequential reader; requiring each read to start where the last
  ended never established the run. The price: a seek back into the span
  already read continues the run. From then on, entering a chunk starts the
  download of the next one **at once**, not when the chunk entered has
  arrived: an established sequential read has two downloads in flight, never
  more (two slots). Below the threshold nothing is fetched ahead, so a short
  `Range` read in several 32 KiB `Read` calls (media players, previews) costs
  the chunks it covers and no other; above it the waste is one chunk at most.
  A chunk whose download failed is not fetched ahead again (`file.failed`),
  only on demand; a failed download is never kept in the window.
- **Contexts**: the context given to `Open` bounds the opening only (the
  session resolution; `service.SessionCache` shares a resolution and does not
  let one caller interrupt it, so only an open that *joins* one leaves early).
  The handle lives until `File.Close` or `FS.Close` (`FS.ctx`, the base context
  of every handle; reads then fail with `vfs.ErrClosed`). `ReadAt` reads for as
  long as the handle is open. `ReadAtContext(ctx, …)` bounds one read:
  cancelling it fails that read only, the download or the `HEAD` goes on for
  the others (it carries the trace values of the read that started it, not its
  cancellation), and a read whose context is already over starts nothing.
  `Close` cancels the downloads and waits for them. A FUSE driver opens with
  the context of the `open` and reads with the context of each `read`.
- **Errors**: those of the API pass through wrapped (`api.ErrChunkMissing`,
  `api.ErrRateLimited`, `api.ErrGone`, a cancellation: `errors.Is` /
  `errors.As` hold); `Open` answers `vfs.ErrIsDir` / `vfs.ErrNotFile` and
  resolves the dataroom session. `Open` trusts the node it is given and asks
  the API nothing.
- **A version being uploaded or copied is never read**: in listings and
  lookups `node_version` is the last **complete** version of the file, and a
  file whose only version is in progress comes back with `node_version: null`.
  `service` then reports no version and no size, and `Open` returns a file
  that reads as empty, at no request (`ErrNotFile` is for a size without a
  version). `chunk_count_expected` matters to `waitForVersion` only.
- **WebDAV** (`readFileHandle`, `cmd/webdav.go`): `markReadRequests` wraps the
  handler and records in the request context what a `webdav.File` cannot see
  (`readHint`): a `Range` header that asks for a part of the file (`ranged`,
  `isPartialRange`), a `HEAD` (`noBody`).
  - A `GET` without `Range`, or with `Range: bytes=0-` (the whole file: the
    first request of a browser's `<video>`, download managers), keeps the
    parallel stream (`service.StreamDownloadChunks`, `api.concurrency.download`
    chunks in flight, a pipe), started by the first `Read` at offset 0.
  - A request with any other `Range` reads through `vfs.File` from its first
    byte, offset 0 included (`bytes=0-1` costs chunk 0, not a burst of the
    stream). The header is taken as it is: when `If-Range` does not match, the
    whole file is answered 200 through the positioned reader, two chunks in
    flight in place of `api.concurrency.download`.
  - Without the hint, the first `Seek` that leaves the stream ends it
    (`endStream` cancels its context: the downloads in flight stop, the
    goroutine returns, `streamDone`) and switches the handle to `vfs.File` for
    good. The `Seek(0, End)` / `Seek(0, Start)` of `http.ServeContent` only
    move the position.
  - A `HEAD` downloads nothing and asks no chunk size, `Range` or not.
  - Reads go through `ReadAtContext` with the request context, and the handle
    is closed at the end of the request: a client that leaves fails the read
    at once and `Close` stops the download.
  - What fails before the headers: the first `Seek` to the inside of the file
    downloads the chunk at its target (`warm`), so a missing chunk there is a
    416 from `ServeContent` and drops the parent listing (`onDownloadError`).
    Nothing more is promised: a later chunk of the range, a range starting at
    offset 0, the second range of a multi-range request fail while the body is
    sent (206 cut short), like any chunk of a full `GET`.
  - `vfs.ErrClosed` (the server shutting down closed the `FS` under the
    handle) and a client that left are not download failures
    (`isReadAbandonedErr`): no line in the journal, no listing dropped.
  - On `vfs.ErrChunkLayout` the handle falls back for good
    (`leavePositioned`, `sequentialOnly`) to the stream read from the start and
    discarded up to the offset (`streamTo`; restarted for a backward `Seek`),
    which works for any cut, and does **not** call `onDownloadError`: the
    version exists, dropping the listing would repair nothing. The `Read` that
    gets the error **drops the bytes that call had copied** and reads them
    from the stream: they were placed by a chunk size the version had just
    disproved (14 bytes cut `[2][4][4][4]` and read as chunks of 4: chunks 1
    and 2 have the expected length two bytes off). So the fallback is right
    when the cut is found out before the handle returned a byte read through
    the `vfs.File`; a cut that is not uniform yet agrees in length with a
    uniform one on every chunk read so far is undetectable, bytes already
    returned by an earlier `Read` included — a known limit, no client makes
    such a version. Nothing is written to a temporary file on the read path.
- Test seams: `Options.ReadChunk` replaces download and decryption,
  `Options.ChunkSizeOf` the `HEAD` (an `FS` given `ReadChunk` alone has no
  size request to make), `Options.ChunkSize` the chunk size assumed,
  `Options.MaxChunkSize` the limit; production sets none.

Dependency rule, enforced by `TestDependencyRule` (`internal/vfs/deps_test.go`),
for `internal/vfs` and its sub-packages: no direct import of `net/http`,
`golang.org/x/net/webdav`, go-fuse, `cobra`, `viper`, `internal/config` nor
`cmd`. Transitively (`go list -deps ./...`, dev and prod builds), the front
ends stay banned (`x/net/webdav`, go-fuse, `cobra`, `cmd`); `internal/config`
and `viper` are tolerated there, since `internal/api` and `internal/service`
import them, and `net/http` comes with `internal/metrics` and
`internal/telemetry`. Settings arrive through `vfs.Options` as plain values
(`TTL`, `MaxStale`, `NegativeTTL`, `FetchTimeout`, `ListConcurrency`, `Store`, `Identity`,
`HideSymlinks`, `CopyReplaceRetry` / `CopyReplaceWait`, `Logf`; `List`,
`Session`, `ListDatarooms`, `ReadChunk`, `ChunkSizeOf`, `ChunkSize` and `MaxChunkSize` are the test
seams), filled by `cmd`:
`vfs` never reads `service.Concurrency()`. `vfs.DefaultCacheTTL` and
`vfs.DefaultListConcurrency` copy `config.DefaultCacheTTL` and
`config.DefaultConcurrency`, `vfs.DefaultNegativeTTL` copies
`config.DefaultCacheNegativeTTL` (`TestVFSDefault…MatchesConfig` in `cmd` keep them
equal).

Span names did not move with the code; the two metrics `vfs` observes did
(`retyc_cli_vfs_dataroom_cache_refreshes_total{result}`, `ok` / `error`, and
`retyc_cli_vfs_node_cache_lookups_total{result}`, both `retyc_cli_webdav_*`
before, no duplicate under the old name); the mutations tag the request
span with `retyc.node.id` where `cmd` did (`listedNode`: the node removed or
renamed), a UUID, never a name. Tests of the cache internals, of the
mutations and of the writes live in `internal/vfs` (fake `Options.List`, or `fakeAPI`, an
`httptest` server that records each request with its JSON body, or `storeAPI`
in `writer_test.go`, which keeps what is uploaded so a test reads it back
through `FS.Open`); tests that go
through `webdavFS` or the server stay in `cmd`, where `newTestFS` builds a `webdavFS` on a memstore
the test helpers seed and read (`setNodeCache`, `cachedNodes`).
`telemetrytest.AssertNoLeak` is the span walker both packages use for the
privacy rule.

## FUSE driver (`retyc fs mount`, `internal/retycfs`)

Linux only, `github.com/hanwen/go-fuse/v2` v2.12.0 (`fs` API), pure Go. A thin
adapter over `vfs.FS`; **read-write** (`--read-only` keeps the read-only mount,
see "Writes" below). Every file of
`internal/retycfs` but `doc.go` carries `//go:build linux`, so the package is
empty elsewhere; `cmd/mount.go` is built everywhere and `runMount` answers
"Linux only" off Linux (`cmd/mount_other.go`): goreleaser builds darwin and
windows. The package imports `vfs` and go-fuse, `internal/api` and
`internal/auth` for their error sentinels only (`errno.go`), never
`internal/service`.

Command: `retyc fs mount retyc://<dataroom-id> <mountpoint>` (the dataroom is
the root) or `retyc fs mount --all <mountpoint>` (one folder per dataroom,
named by `FS.Datarooms`; `folderName` turns a `/` of a title into `_`).
Besides `--all` (an argument, no key) and the two cache flags, every flag has
its `mount.*` key (`mountFlags` in `cmd/mount.go`, bound by
`resolveMountFlags` from `runMount`; `TestMountFlags_OnePerKey` fails on a key
without a flag): `entry_ttl` / `attr_ttl` (0 → `cache.ttl`,
`Config.KernelTTLs`), `kernel_cache` (false → no `FOPEN_KEEP_CACHE`,
`Options.NoKernelCache`), `spool_dir` (`checkSpoolDir`: exists and takes a
file, checked before the token is asked for; → `vfs.Options.SpoolDir`),
`allow_other`, `uid` / `gid` (-1 → the process; `Options.UID` / `GID` are
pointers, 0 being an owner), `file_mode` / `dir_mode` (octal **strings**:
`config.Load` refuses a YAML number, since `0644` unquoted is read 420;
`attrSource.fileMode` / `dirMode`), `read_only`, `drain_timeout` (0 → no
drain, which `mountDrain` turns into the negative `Options.DrainTimeout`).
`mirror_locks` (`Options.MirrorLocks`, never on a read-only mount; see
"API locks" below), `metrics.addr` / `metrics.runtime` / `metrics.labels` (the
observability listener, see "Metrics"; `config.MetricsConfig` is the type of
both `webdav.metrics` and `mount.metrics`), `local_files` (`--local-file`,
repeatable; `Options.LocalFiles`, see "Local files" below),
`background_delete` (`--background-delete`, see "Background delete" below). `mount.open_cache` of the study
does not exist. The
tree is built with `cache.ttl`, `cache.negative_ttl` and
**`MaxStale` zero whatever `cache.max_stale` says** (see "open" below). `annotationLongRunning`; span
`retyc fs mount init`, ended once the mount is in place. `runMount`
(`cmd/mount_linux.go`): `checkMountpoint` (exists, a directory, empty),
`checkFUSE` (`/dev/fuse` opens; `fusermount3` unless root), passphrase, token,
`api.New` like `webdav serve`, `serveStartupCheck` (shared, in
`cmd/serve_common.go`), `vfs.New`, `mountDataroomCheck` (session resolves, and
`SupportsNameLookup`: a legacy API is refused, `retycfs.ErrLegacyAPI`; at
startup for one dataroom, on first entry of each one with `--all`, where it
answers `ENOTSUP`), `retycfs.Mount`, `authWatch.run`, then `serveMount`:
signal, expired login (wrapped `%w`: exit code 77) or the filesystem
unmounted from outside (`Server.Done`, exit 0), and `Server.Shutdown(ctx)`,
whose context a second signal ends.

Login (`cmd/serve_common.go`). `authWatch` is `tokenKeepalive` (what `webdav
serve` still calls, unchanged: a check every 60 s) plus `checkNow`: the mount
builds its client with `apiTransportWatching(watch)` (the wrappers of
`apiTransport()` around `authWatch.roundTripper`, outside the oauth2
transport), so a 401 answered to any request of the mount, or a request the
token source could not sign (`auth.ErrNoToken` / `ErrNoRefreshToken`), asks
for a check at once. A check asked for first calls
`auth.RefreshingTokenSource.Expire` (once per `authRefreshInterval`, 30 s):
the source would otherwise answer from an access token it takes for valid, and
a login revoked on the server would go unnoticed until that token ran out. A
failed check ends `run`, `serveMount` unmounts and returns the error wrapped
(77). FUSE operations meanwhile answer `EACCES` (`toErrno`).

Shutdown (`Server.Shutdown`, `mount.go`; `Unmount` is `Shutdown` with a
context that never ends). The drain (`Options.DrainTimeout`, 5 min, started
once by `startDrain`: by `Shutdown`, or by `finish` when the filesystem was
unmounted from outside) is `driver.stopped`, a context `driver.abort(cause)`
ends: at the timeout (`errDrainTimeout`), when the context of `Shutdown` ends
(`errDrainCut`), or with nil once everything is sent. Order: access log
closed, `fuse.Server.Unmount` retried for `UnmountGrace` (5 s, cut by the end
of the drain), detach when still busy, then `finish`. `unmountOnce`:
`fuse.Server.Unmount`, once the kernel let the mount point go, waits for the
FUSE connection to close, which a bind mount of the filesystem in another
namespace (a CSI pod) keeps open while a file is open through it, and so does
a request in progress: the mount point gone from `/proc/self/mountinfo` is
then the unmount done, logged, the connection serving the rest meanwhile
(`TestShutdown_MountedElsewhereStillFinishes`). The end of the drain gives the
unmount 500 ms more before it is taken for busy (`TestShutdown_NoDrainUnmountsCleanly`).
`finish`: `uploads.wait` (the
flushes that follow a last close, which run on `driver.detached(ctx)`: the
values of the request, cancelled only with `stopped`), `closeSpools` (every
spool still open flushed **as it is**, on `stopped`, the uploads taking
the slots of `vfs.Options.UploadConcurrency`). `startDrain` logs what is still
to send (`driver.pending`: dirty spools but local files, background deletes),
the drain timeout and that a second signal abandons it, and `finish` how long
it took and what was not sent; nothing when nothing was pending
(`TestShutdown_*` assert both lines). Past the
drain the uploads are cancelled; `openSpool.close` reports each dirty spool
(`its changes are lost: dataroom, node, inode: not sent before the end of the
shutdown drain`, never a name) after one line saying why. `Shutdown` runs the
unmount in a goroutine and gives up `abortGrace` (5 s) after the end of the
drain, with an error: `fuse.Server.Unmount` waits for the handlers in
progress, and one the drain does not cancel (a download) must not hold the
process. **New writes are not refused during the drain** (the study asks for
none): they are sent, or lost with the rest.

Mount options (`mount.go`): `default_permissions` (no `Access` handler), `ro`
with `Options.ReadOnly`, `MaxWrite` 1 MiB, `CAP_HANDLE_KILLPRIV_V2`,
`CAP_ATOMIC_O_TRUNC` (go-fuse does not ask for it: `O_TRUNC` then arrives in
the OPEN, not as a SETATTR to 0 before it), `CAP_DIRECT_IO_ALLOW_MMAP`, `FsName`
`retyc://<id>`, type `fuse.retycfs` (`retycfs.FSType`), `DirectMount` when
root (euid 0: `mount(2)`, which the scratch image needs; go-fuse falls back on
`fusermount3`), `allow_other` with `Options.AllowOther`, `NullPermissions` (go-fuse
would turn a permission 0 into 0644: `chmod 000` must show `----------`; every inode gets
its permissions from `attrSource.fill` / `controlAttr`), **`SyncRead`** (one read per
handle at a time, in offset order: the parallel, unordered reads of the
kernel's read-ahead made a late read ask again for a chunk the two-chunk
window of `vfs.File` had let go, downloaded twice, and broke the sequential
detection that starts the fetch ahead), `MountOptions.Logger` → `Options.Logf`.
**No writeback cache** (the kernel
would stop asking for size and mtime: a file extended elsewhere would read
truncated). `MountOptions.Debug` is never set: its output holds file names.
`Server.Unmount` closes the access log first (a reader blocked on it holds the
mount busy), retries a busy mount point for `Options.UnmountGrace` (5 s), then
detaches it (`MNT_DETACH`, or `fusermount3 -u -z`); it is a no-op when the
filesystem is gone (`isMounted` reads `/proc/self/mountinfo`).

- **Inodes** (`inodes.go`). `inodeTable.ino(key)`: node ID → inode number
  (1 root, 2 `.retycfs`, 3 its `accesslog`, the rest counted up, **never
  reused**; `dataroomKey` for the synthetic folder of a dataroom, kept for
  the life of the mount). Each number has an `inodeRecord` (its keys: a node
  ID, and the `pending:<n>` key it was `alias`ed from, swept together; the
  objects handed to go-fuse with it). Every object is made through
  `inodeTable.lend` / `lent` (`driver.child`, `Create`): `lend` takes the
  number of the key **at that instant** (not the one of an older listing) and
  returns the object go-fuse holds for it when there is one, which `child`
  returns instead of a new one. `inodeTable.sweep` (run when an assignment
  doubles the table since the last sweep, `sweepMin` 1,024 at least, and
  `forgetSweepDelay` after a FORGET: `forget` schedules one through
  `time.AfterFunc`, one at a time, another once it ran if FORGETs came
  meanwhile, stopped by `inodeTable.close` in `Server.finish`; without it a
  mass of FORGETs, which grows nothing, released nothing) drops a
  record and its keys when no object of it is held (`held`: `!Forgotten()`,
  the one deprecated call, on purpose), none is being made, none was handed
  out within `handoutGrace` (1 min: covers a LOOKUP racing the FORGET of the
  node, whose object reads as not held until go-fuse registers it), its state
  is not `busy` and the spool registry does not pin it (`spoolRegistry.folders`:
  the folder of a named spool, which `sameDir` compares by number). The node
  then gets a new number at its next lookup; the reasoning is on `sweep`.
  `forget`, `lent` and `sweep` also let go of the objects of a record that
  are dead past the grace (`pruneLocked`): a forgotten object still holds
  what go-fuse hung on it (≈ 1 KiB).
  `inodeTable.state(ino, seed)`: the `inodeState` of an inode the kernel
  holds, dropped on FORGET (`base.OnForget`) unless handles are open.
  **State lives in the table, never in the object a `Lookup` returns**:
  go-fuse keeps the object of the first lookup of an inode and discards the
  later ones, so an object (`base`: `fs.Inode` + `ident{drv, ino, dataroomID,
  seed}`) holds its identity only, and `seed` is merely what the table starts
  from when it holds nothing.
- **Paths**: `vfs` is addressed by path, and the path is **never** read from
  go-fuse's tree (`Inode.Parent()` is the parent of the last lookup, and a
  lookup answered from a listing older than a remote move puts the old place
  first). `inodeState.at` is the `location{parent *fs.Inode, name}` vfs last
  found the node at, recorded by `observe` (`driver.child`, `dirNode.list`,
  `revalidate`); `was` the one before. `dirNode.path()` walks the `at` up to
  the folder marked `dataroomRoot` (a moved folder takes its children along);
  no known place is `errStale` → `ESTALE` (`pathErrno`). Every question to vfs
  goes through `dirNode.withPath`: on `ENOENT` it checks the folder itself
  (`revive`: `Lookup(parent path, name)` up the tree, free while cached, falls
  back on `was` via `inodeState.relocate` and drops the dead entry from the
  kernel) and asks once more when the path changed. `fileNode.revalidate` tries
  `at` then `was` the same way. The path never leaves the process.
- **Observations are dated** (`driver.stamp`, a counter taken before asking
  vfs, carried by `dirEntry.seen`): `observe` ignores one older than the last
  it recorded, so an old `dirHandle` replaying its listing (READDIRPLUS)
  neither brings a version back nor moves the node; `child` then answers with
  the attributes the table holds.
- **Lookup vs listing.** `dirNode.Lookup` is the isolated lookup
  (`vfs.FS.Lookup`). `OpendirHandle` reads the listing once
  (`vfs.FS.ReadDir`) into a `dirHandle`, which implements `FileReaddirenter`,
  `FileLookuper` and `FileSeekdirer`: the per-entry lookups of READDIRPLUS are
  answered from the listing in hand (`dirHandle.Lookup`, last entry returned
  first), never through `dirNode.Lookup`. `ls -l` of a folder is one listing
  and no lookup. Names the kernel cannot take (`presentable`) are left out,
  and so is a node called `.retycfs` at the root.
- **`driver.child`** is where every node goes by, lookup or listing: it
  records the node (`inodeState.observe`) and builds the object. `dirNode.list`
  also observes the nodes whose inode has a state, and `driver.reconcile`
  compares the listing with `Inode.Children()`: a name gone, or naming another
  node, is dropped from the kernel (`NotifyEntry`).
- **Version change.** `observe` seeing another `VersionID` for a file: size
  and mtime follow the node, the handles open become *stale* (they keep
  reading their version, `vfs.File`), `pagesOf` is reset and the live inode
  (set by the first open) gets `NotifyContent`. `Open` passes
  `FOPEN_KEEP_CACHE` only when the pages the kernel may hold are of the
  version opened and no stale handle lives (`inodeState.opened`); the release
  of a stale handle purges again (`released`). The page cache is per inode,
  not per handle: a handle opened while a stale one lives, or on a version
  that is not current any more, is opened `FOPEN_DIRECT_IO` (`opened` returns
  `direct`) and reads through its `vfs.File` only. Left: the stale handle
  reads through the cache under the new version's size (cut there when it is
  shorter); `doc/retycfs.md` says so.
- **Notifications are sent from a goroutine** (`notifier`), never from a
  handler: the kernel takes for `NotifyEntry` / `NotifyContent` the lock a
  request on that folder or inode already holds. The queue is bounded
  (dropped when full: the kernel's own timeout then applies) and a
  notification still waiting is not queued twice (`notifier.once`, keyed by
  `notification{inode, name, entry}`). One exception, `notifier.contentNow`:
  `revalidate` finding a new version sends `NotifyContent` and waits for it
  (2 s at most) before the OPEN is answered, or the kernel bounds the reads by
  the size it knew. Safe from an OPEN for reading only (no inode or page lock
  held; the invalidation waits for reads other goroutines answer).
- **open** (`fileNode.Open`): close-to-open consistency. The version opened is
  the one `vfs.FS.Lookup(parent path, name)` answers then, not the one the
  table remembers: free when the listing or the `Entry` is fresh, one request
  otherwise. Because `Lookup` answers a name an *expired* listing holds from
  that listing without telling, the tree is built with `MaxStale` zero: what
  `Lookup` returns is then never older than the TTL. A name that is gone:
  `ENOENT` + `NotifyEntry`; a name that now holds another node: `ESTALE` +
  `NotifyEntry` (the kernel resolves the path again). An open for writing, or
  of a file being written: see "Writes".
- **read** (`fileNode.Read`): `vfs.File.ReadAtContext` with the guarded
  context of the request (see "Interruptions": only the kill of the reader
  ends it); a failed read returns no
  byte, since the page cache takes a short read for the end of the file.
- **Attributes** (`attr.go`, `attrSource.fill`): size, mtime = ctime = atime =
  `Node.ModTime` (mount time when unknown), mode with `file_mode` / `dir_mode` only when
  the node stores none (`HasMode()`; an explicit 0000 is shown 0000) and 0777 for a link, nlink 1 / 2, owner = the process,
  blocks = ⌈size / 512⌉. `Getattr` answers from the table, never the API.
  `EntryTimeout` / `AttrTimeout` default to `vfs.DefaultCacheTTL`,
  `NegativeTimeout` to `vfs.DefaultNegativeTTL` (`retycfs.Options`; a
  negative value is "no cache", sent as 1 ns because go-fuse reads 0 as "use
  the default"). `runMount` passes `cache.ttl` for the first two and
  `cache.negative_ttl` for the third (`kernelNegativeTimeout`: a zero key is
  sent as −1, "no cache").
- **Statfs**: `vfs.FS.Quota` of the dataroom (cached for the TTL); a 1 PiB
  constant without counters and at the root of `--all` (no request per
  dataroom). **xattr** (`xattr.go`): `user.retyc.node_id`, `version_id`,
  `dataroom_id`, `mime`, read-only; `Setxattr` / `Removexattr` are `ENOTSUP`
  (go-fuse's default is `ENODATA`). **Symlinks are shown** (`linkNode`,
  `Readlink` from `Node.Target`), unlike WebDAV: the tree is built without
  `HideSymlinks`.
- **Writes** (`spool.go`, `file.go`, `node.go`). `driver.readOnly(dataroomID)`
  is `Options.ReadOnly` (the mount, `ro`) or what `Options.Access` (a hook of
  the shape of `vfs.FS.Access`, which `cmd` plugs) said of that dataroom: every
  write handler then answers `EROFS`. At the root of `--all` they answer
  `EPERM` for good.
  - **Read-only by role** (`driver.learnAccess`, `dataroomRights`,
    `cmd.mountRights`). One dataroom: `mountRights` asks `FS.Access` at mount
    time (the cached dataroom list + one `GET /dataroom/{id}`); `ReadOnly`
    (a viewer, or a plan that refuses writes) mounts `ro` and the mount
    message says why (`Access.Reason()`); writable passes no hook, nothing is
    asked again. `--all`: the driver asks when a dataroom is first entered
    (`checkDataroom`, after the legacy check: lookup, listing, mkdir,
    symlink), one request per dataroom for the life of the mount, and logs
    the read-only ones. **Until the question is answered the dataroom is
    read-only for the writes (`EROFS`) and open to the reads**: a failure
    (at mount time for one dataroom, in the driver otherwise) is logged once,
    never makes a dataroom writable, never fails a lookup, and the next
    access to the dataroom asks again (one more request per access while it
    fails). The answer is not refreshed: a role changed since needs a
    remount. `Options.Access` nil (the tests, a writable single dataroom)
    refuses nothing; the API still decides each write (403 → `EACCES`).
  - **One `vfs.Spool` per inode**: `openSpool` (`inodeState.spool`), counted by
    reference (`refs`, under `st.mu`). The first open for writing creates it
    (`fileNode.openSpool`: `revalidate`, then `FS.OpenSpool(…, &node,
    truncate)`, no request; `inodeState.attach` settles two opens that race);
    every handle opened while it lives is a `spoolHandle` on it, **those opened
    for reading included** (`inodeState.join`). While it lives it answers for
    the inode: `inodeState.view()` (the node with `Spool.Size()` /
    `ModTime()`, two short mutexes, never an upload) feeds `Getattr`, `Lookup`
    and listings (`driver.fillAttr`); `Read` of a `spoolHandle` is
    `Spool.ReadAt`; `Setattr` goes to it; `observe` records nothing. A
    `fileHandle` opened before keeps its `vfs.File`, becomes *stale*
    (`attach` does what a version change does), and its `Flush` / `Fsync` send
    nothing. A `spoolHandle` **sends** (`spoolHandle.sends`, counted in
    `openSpool.writers`) when it was opened for writing or with `O_TRUNC`,
    `Create` included; one opened for reading only reads the spool.
  - **`FOPEN_DIRECT_IO` on every `spoolHandle`**: the page cache is per inode
    and may hold the version a stale handle reads. Writes come one WRITE per
    `write(2)` (no writeback cache), at the offset asked; a handle opened with
    `O_APPEND` writes at `Spool.Size()` under `openSpool.appending`, whatever
    offset the kernel computed.
  - **Pending files.** `Create` makes no request: `FS.OpenSpool(…, nil,
    false)`, an inode keyed `pending:<n>` in the table (`spoolRegistry.pendingKey`),
    a synthetic node (name, mode). `spoolRegistry` (`driver.spools`) holds
    every open spool, and by `location` those whose file has a name:
    `dirNode.Lookup` asks it **before vfs**, `dirNode.list` lists the folder's
    spools as their spools know them (`openSpool.entry`, `dirEntry.local`:
    `child` does not `observe` it) and adds the pending ones, `Unlink`,
    `Rename` and `Rmdir` (a folder holding a pending file is `ENOTEMPTY`)
    look there first. The first flush that succeeds gives the node ID the
    inode number the file already has (`inodeTable.alias`) and the table the
    node (`inodeState.adopt`). A pending file whose last handle closes without
    a successful flush is gone: `NotifyEntry` (queued).
  - **`Create` on a name that exists** (the kernel's negative entry is older
    than a file created elsewhere; `Create` asks `vfs.Lookup`, free right after
    the kernel's own lookup): `ESTALE`, on which the kernel resolves the name
    again (`LOOKUP_REVAL`) and opens what it finds; `EEXIST` with `O_EXCL`.
    Never go-fuse's `Create` path with an existing inode: it registers the
    child as new (`O_EXCL` to `registerNew`). **An `O_EXCL` creation asks the
    API** (`dirNode.lookupRemote` → `vfs.FS.LookupRemote`): the cache may say
    a name is free (a fresh listing, a negative `Entry`) that a file created
    elsewhere holds, and the first flush would give that file a new version.
    One lookup by name hash per exclusive creation (`cp` of a new file makes
    one: coreutils creates its destination with `O_EXCL`), none for a plain
    creation, none on a legacy API (`authoritative` false: the cache decides).
    `LookupRemote` keeps the answer as an `Entry` and drops a cached listing
    of the folder that says otherwise. Not closed: a file created elsewhere
    between that answer and the flush (the API has no exclusive creation).
  - **flush** (`fileNode.Flush`, `Fsync`, both `sync` → `openSpool.flush` →
    `Spool.Flush`), on the `flush` of a `spoolHandle` **that sends** only: the
    `close` or the `fsync` of a reader of a file being written sends nothing
    (it used to store a version of a half-written file). With the guarded
    context of the request (see "Interruptions": a signal the program handles
    interrupts nothing, `close` never answers `EINTR`; the kill of the program
    cancels the upload, the spool stays dirty and the release sends it). Its error is the errno of `close(2)`.
  - **Mode at creation**: `Create` (and a `chmod` of a file still pending)
    gives the mode to the spool (`Spool.SetMode`), and the first flush
    declares it as `access_mode` in the request that creates the node
    (`service.UploadSmallFileWithAttrs` → `POST /node/file`,
    `InitStreamUploadIntoWithAttrs` → `POST /node`; `StreamUploadInit.NodeMode`
    is the mode that creation answered): no request of its own.
    `openSpool.stored` still sends one `FS.Chmod` when the node answered
    carries another mode than the one wanted (an API that ignores the field,
    a server-side copy whose source has another mode).
  - **release** (`openSpool.release(ctx, sends)`): the last handle *that sends*
    flushes with `context.WithoutCancel` even while readers keep the spool
    open; the last handle of all flushes once more (a failed flush gets a
    second chance) and closes the spool. `openSpool.close` reports a loss to
    `Options.Logf` (dataroom, node ID, inode, errno name: no file name, not
    the error) **from the state of the spool, not from the error of one
    flush**: once, when the spool it closes is still dirty (`Spool.Dirty()`),
    with `openSpool.flushErr`, the error of the last flush that failed (reset
    by one that succeeds). A flush that failed and was followed by one that
    succeeded reports nothing; two last releases that overlap report once,
    whichever closes. `closing` counts last releases still flushing, so a handle
    opened meanwhile keeps the spool and the one that ends last closes it.
    `driver.uploads` (`inflight`) is what `Server.finish` waits for, before
    `driver.closeSpools` flushes and closes what is still open (a mount
    detached while busy). What it sends is a complete version of a file its
    writer had not finished: each spool sent there while handles were open is
    logged (`a file was sent as it was at shutdown, the file was still open`,
    IDs only), each one that could not be sent is logged lost by `close`.
  - **`openSpool.hold` / `letGo`**: `Rename` (source and destination) and
    `Unlink` find a spool by its place and keep it across a request, while the
    release of its last handle, which follows `close(2)`, may come. They take
    a reference for the call: that release then leaves the spool open and
    `letGo` closes it. `spoolRegistry.move` ignores a spool that was dropped
    all the same: a closed spool put back under a name answers for it for
    good (frozen attributes, `Rmdir` of the parent `ENOTEMPTY`, `Create`
    `ESTALE`). Any new handler that keeps a spool found by `find` across a
    request holds it.
  - **Setattr** (`base.Setattr`): size → `Spool.Truncate` when the inode has a
    spool (flushed before the call returns when no handle that sends is open:
    no close would send it), otherwise a spool opened for the call, truncated and flushed before
    it returns (`truncate` to 0: `truncate=true`, one request; a size equal to
    the current one: nothing); mtime → `Spool.SetModTime` with a spool, else
    `FS.SetModTime`; mode → `FS.Chmod` (kept in the table only for a pending
    or unlinked file); uid, gid, atime ignored without error; a folder ignores
    mode and times too (`cp -p`, `tar`, `rsync` set them), size is `EISDIR`.
  - **Mutations** (`dirNode.Mkdir`, `Rmdir`, `Unlink`, `Rename`): vfs by path
    (`joinPath(path, name)` inside `withPath`), then the table:
    `inodeState.place` (new `at`, `was` cleared, name), `inodeState.remove`
    (`unlinked`: `nlink` 0, no more `observe`). Each takes a `stamp` so an old
    listing replayed teaches nothing. go-fuse does `RmChild` / `MvChild`
    itself once the handler returns and the kernel updates its own entries:
    no notification. `Rmdir` is `FS.Remove(recursive=false)`; `Rename` is
    `FS.Rename(replace=!RENAME_NOREPLACE)`, any other flag `EINVAL`, another
    dataroom or the root of `--all` `EXDEV`, a folder over a folder
    `ENOTEMPTY`. **The rename of a file with a spool goes through
    `vfs.Spool.Rename(ctx, newPath, rename func(exists bool) error)`**, which
    takes the spool's `flushing` lock (it waits for the flush in flight, with
    the request's context), tells the callback whether the API holds the file
    at that instant, and records the new path when the callback succeeds: the
    callback is `FS.Rename` for a file the API holds, `renamePending` for one
    it does not. Reading `pending()` before the request was the bug: during
    the first flush it is still true, the rename asked nothing, and the flush,
    which read its path when it started, created the node under the old name.
    A rename therefore blocks for as long as an upload of that file runs. A
    spool open on the
    destination replaced gets `Unlinked`; after a folder moved, every named
    spool is given its path again (`SetPath`, not serialized with a flush in
    flight). **A pending source is renamed without a
    request** (`renamePending` only looks the destination up: a folder there
    is `EISDIR`): the new path + the table. Over a file the API holds, that file
    keeps its node and gets the pending file's content as a version at the
    first flush (the single-request route overwrites).
  - **Unlink of an open file**: `FS.Remove`, then `Spool.Unlinked()` and the
    spool leaves the registry by name; a pending one is unlinked at no request.
  - **Symlink** (`dirNode.Symlink`): `FS.Symlink`, one request, the target
    kept as given (relative, absolute, dangling); the node goes through
    `child` like a `Mkdir`, so `readlink`, `ls -l`, `rm` (`FS.Remove`) and
    `mv` (`FS.Rename`) work at once. A name held by a pending file is
    `EEXIST`; `vfs.ErrSymlinkUnsupported` (an API without symlinks) is
    `EPERM`, what symlink(2) documents. `Link` and `Mknod` stay `EPERM`
    (`dirNode.unsupported`).
  - **`CopyFileRange` → server-side copy** (`fileNode.CopyFileRange`,
    `copyInto`, `vfs.Spool.CopyFrom`) when the call is the copy of a whole
    file into a new one, which is what `cp` does (coreutils ≥ 9): same
    dataroom, writable; `offIn == offOut == 0` and `len ≥` the size of the
    source (the kernel clamps `len` to the size it knows, and to 4 GiB: a
    larger file falls back); the source handle reads the current version
    (`revalidate`) and the source has no dirty spool; the destination is a
    **pending** spool of size 0. Then `Spool.CopyFrom(ctx, srcPath)`:
    `FS.Copy(…, replace=false)` under the spool's `flushing` and `content`
    locks (no write or flush in between), one `POST /dataroom/node/{id}/copy`
    (plus the polling of a copy that is not complete at once), and the spool
    is **clean on the copied node**, its content brought in lazily like a
    spool opened on an existing file: the `flush` and `release` that follow
    send nothing. `openSpool.stored` records the node (inode alias, table,
    mode). Everything else answers `EXDEV`, on which the kernel copies through
    reads and writes itself (`ENOSYS` would disable the operation for the
    mount); `ENOSPC` / `EACCES` / `EINTR` / a rate limit (`EIO`) of the copy
    are returned as they are, the bytes would meet them too. **A destination
    that exists (`cp` over a file, `O_TRUNC`) is not copied server-side**:
    `FS.Copy(replace=true)` deletes the node, so its versions would be lost,
    it is not restored when the copy fails, and the copy waits up to 15 s for
    the purge of the name with the inode locked; it falls back and gets a
    version. The copy keeps the `client_mtime` of its source (like `cp -p`),
    no `PATCH` is sent to date it now. `Spool.CopyFrom` on a spool that is not
    pending and empty is `vfs.ErrSpoolNotEmpty`, nothing sent; `Unlinked` /
    `Close` cancel it like a `Flush`.
- **Errors** (`errno.go`, `toErrno`, the only mapping): `ErrNotExist` / 404 /
  410 → `ENOENT`; 401 / 403 / `ErrForbidden` / `ErrUnauthenticated` / no token
  → `EACCES`; `api.ErrRateLimited` → `EIO` (after the client's own wait, never
  `EAGAIN`); `context.Canceled` → `EINTR` (a caller being killed or the end of
  the drain, nothing else: see "Interruptions"); `api.ErrChunkMissing` (checked
  before `ErrNotFound`, which it also matches), `vfs.ErrChunkLayout` → `EIO`;
  `ErrLegacyAPI` → `ENOTSUP`; `vfs.ErrReadOnly` → `EROFS` (before the `EACCES` case);
  `ErrStorageExceeded` / `ErrSpoolFull` →
  `ENOSPC`; `ErrNameBeingDeleted` (before the 410 it also is) / `api.ErrLocked`
  → `EBUSY`; `ErrSymlinkUnsupported` → `EPERM`; `ErrNotEmpty` → `ENOTEMPTY`; `ErrExist` / 409 → `EEXIST`;
  anything else → `EIO`. Never `ENOSYS`. An errno wrapped in an error is never
  passed on (it is the HTTP client's).
- **Interruptions** (`interrupt.go`). The kernel sends `FUSE_INTERRUPT` as
  soon as the thread waiting for a request receives **any** signal (the
  `SIGURG` of Go's preemption, `SIGCHLD`, `SIGALRM`, `SIGPROF`, a handled
  `SIGUSR1`), once per request, and go-fuse ends the request's context.
  Answering `EINTR` to those failed `close(2)` with `EINTR` and page-cache
  reads with `EIO` in any program that receives signals (≈0.5 % of
  `TestWrite_Rename` runs). The driver honours an interruption **only when
  the caller is being killed**, and lets the others go to their end (libfuse's
  default).
  - **No handler passes go-fuse's context on.** `call.guard(ctx)` (one line
    after `defer c.end(&errno)`; `driver.guard` + `defer release()` in the two
    handlers without a call, `dirHandle.Seekdir` and `accessLogNode.Read`)
    returns an `opContext`: the request's values (caller, trace), `Done` /
    `Err` of its own. It ends when (a) the request is interrupted **and**
    `callerDying`, (b) `driver.stopped` ends (drain of a shutdown over). A new
    handler that uses its context must guard it.
  - **`callerDying(pid, read)`**: `fuse.Caller.Pid` is the **thread ID** of the
    caller in the PID namespace of the mount (`task_pid(current)`; checked by
    `TestInterrupt_HarmlessSignalsDoNotFailReads`), 0 when the caller is not
    visible in it. `/proc/<tid>/status` (exists for every thread), bit 9
    (`0x100`) of `SigPnd` or `ShdPnd`: the kernel makes SIGKILL pending on
    every thread of a group that dies of a fatal signal (`kill -9`, `-TERM`,
    Ctrl-C without handler, `exit_group`, `execve` from another thread).
    ENOENT / ESRCH → dying. PID 0, an unreadable status, or a `/proc` that is
    absent or of another PID namespace (`procUsable`: `/proc/self` must name
    `os.Getpid()`) → **not** dying: every interruption is ignored there, and a
    killed process only goes when the operation ends (bounded by
    `api.retry.max_wait` for a throttled request, not for a slow transfer) or
    the filesystem is unmounted.
  - The kernel sends nothing for a kill that follows a harmless signal, so
    once interrupted the caller is looked at again every
    `interruptProbeInterval` (100 ms) for as long as the operation lasts.
  - **Cost**: one allocation per guarded operation; the goroutine that
    watches the request starts at the first `Done()` (something waits on the
    context: a request to the API, a wait on a fetch), not before, and ends
    with the handler (`call.end` → `release`). An operation answered from
    memory starts none. `Err()` alone starts it only once interrupted.
    `driver.detached` (the flush of a release) derives through
    `WithoutCancel` and is not concerned.
  - A read ended this way ends that read only; the download stops when the
    kernel releases the file of the dead process (`File.Close`).
  - Tests: `interrupt_test.go` (`TestCallerDying` with an injected reader,
    `Options.procStatus`; mounted: raw `read(2)` / `close(2)` on a locked
    thread bombarded with `SIGUSR1` + `SIGURG`, and the test binary started
    again as a reader (`TestMain`, `RETYCFS_TEST_HELPER_READ`) killed while
    the fake API holds its chunk: gone in a few ms). The tests run with
    signal preemption on: no `GODEBUG=asyncpreemptoff=1`.
- **Robustness**: every handler defers `call.end(&errno)` directly (`driver.go`),
  which recovers a panic into `EIO` + the stack through `Options.Logf`;
  `MountOptions.PanicHandler` (`driver.panicked`) covers go-fuse's own code.
- **`.retycfs/accesslog`** (`accesslog.go`, `control.go`): persistent inodes
  hung from the root in `OnAdd`, absent from the listing, reached by name.
  The log is a ring of `accessRecord` (4,096; numbers only: op, inode, offset
  and length of a read, duration, errno, **never a name or a path**), formatted
  when read. The file is a stream (`FOPEN_DIRECT_IO | FOPEN_NONSEEKABLE`): a
  read blocks for the next record, returns the end of the file once the log is
  closed, `EINTR` when its reader is killed (guarded context). `cat` works, plain `tail -f` does not. A
  reader that falls behind the ring is told how many records it lost. Logged:
  lookup, getattr, opendir, open, read, release, readlink, statfs, and the
  writes: create, write (offset and length), flush, fsync, setattr, mkdir,
  rmdir, unlink, rename, symlink, copy_file_range.
- **Traces**: `startSpan` opens a root `FUSE <op>` (`retyc.fuse.op`,
  `retyc.dataroom.id`, `retyc.node.id`, `retyc.version.id` on open and read)
  through `telemetry.StartUsedRoot`: the span is **exported only if it got a
  child** (an API round trip, a decryption), i.e. only for an operation that
  reached the API, and never ended otherwise. So a lookup, an open or a read
  served from memory leaves no span, and the API calls of the others are not
  orphan roots. With `cache.store: redis` a round trip to Redis is a child too
  (`redis <op>`, see "Redis metadata store"): an operation the store answered
  is exported, where the memstore leaves none. No new metric in this step.
- **Tests** (`internal/retycfs/*_test.go`): unit tests (`unit_test.go`) and
  mounted tests against `fakeAPI` (`fakeapi_test.go`: an `httptest` API with
  real encryption, counting listings, lookups, chunks; its write routes are in
  `fakeapi_write_test.go`: what is uploaded is decrypted and kept, each
  version cut as its uploader cut it, each kind of request counted, and
  `refuseUploads` answers the storage refusal). `write_test.go` holds the
  mounted write tests, which assert the requests of each case (`mounted.cost`,
  after `settle`: the RELEASE of a handle comes after its `close(2)` returned)
  and set the umask to 022 (another one costs a `Chmod` per creation).
  `mountFS` calls
  `t.TempDir()` before registering the unmount. `requireFUSE` skips without
  `/dev/fuse` or `fusermount3` and **fails when `CI` is set**; `_ci.yml`
  installs `fuse3`. The fake does not count the lookups a desktop session
  makes at the root of every new mount (`.Trash`, `.Trash-<uid>`…,
  `desktopProbe`). `trace_test.go` is the privacy rule for the driver.

Missing from `vfs` for the driver, worked around for now: a lookup that
revalidates an expired listing (hence `MaxStale` zero), a public
"supports lookup by name" (hence `Options.CheckDataroom`, filled by `cmd`),
and a mode at creation (`OpenSpool` / `Create` send no `access_mode`: hence
the `Chmod` after the first flush of a file created with another mode).
Known limits of the write path: every `close` of a file being written sends
it, a reader's included; `Spool.ReadAt` cannot be interrupted while it brings
a version in; a handle that reads a version while the file is written reads
it under the size the kernel now knows; a pending file renamed over a file
the API holds and never flushed leaves that file as it was.

Background delete (`--background-delete`, `mount.background_delete`,
`Options.BackgroundDelete`, off by default, never on a read-only mount).
`dirNode.Unlink` of a file or symlink the API holds goes to `unlinkLater`
(`internal/retycfs/deletes.go`): `vfs.FS.HideNode` (`internal/vfs/hidden.go`)
drops the node from the cached listing and tombstones its **ID**, so no
listing (`fetchLocked`) nor lookup by name (`findByNameOnce`) answered by the
API brings it back; the `deleteQueue` of the driver then sends
`vfs.FS.DeleteNode` (404 / 410 = deleted) from at most
`Options.DeleteConcurrency` goroutines (`service.Concurrency().Upload`), each
in a root span `FUSE background_delete` (identifiers only), and
`vfs.FS.RevealNode` records the outcome: deleted → the tombstone lasts one
more `Options.FetchTimeout` (a listing answered just before the delete), not
deleted → tombstone lifted, listing invalidated, one log line by identifiers,
`retyc_cli_fuse_background_deletes_total{result}`. A pending file, a local
file, a folder and `rmdir` keep the synchronous path. What needs the name
free at the API waits for the job of that name (`waitName` / `waitAt`, keyed
by dataroom, folder node ID and name): the first flush of a spool without a
node (`openSpool.flush`, so release and `closeSpools` too), `copyInto`,
`Mkdir`, `Symlink`, `Rename` (destination); `Rmdir` waits for the jobs of the
folder (`waitFolder`). `Server.finish` drains the queue after `closeSpools`;
a drain that is cut reports each job left and counts it in
`LostWritesError.Deletes` (exit code 75).

API locks (`--mirror-locks`, `Options.MirrorLocks`, off by default). The open
for writing of a file that has a node (`fileNode.openForWrite` →
`lockForWrite`, **before** the spool is created or truncated) takes an
exclusive API lock through `vfs.LockManager.Take`, with a zero `expires` (the
WebDAV notion of a front-end lock that lapses does not apply: it stands until
released) and a key of its own per lock (`fuse:<ino>:<n>`, `driver.lockKeys`).
**One lock per inode, not per handle** (the study said per handle; the API
holds one lock per token and would answer 423 to the second handle of one
process): `inodeState.lock` (`mirrorLock`: own mutex, held across the request;
`refs`; `key`, empty when none is held), counted by every `spoolHandle` with
`locked` set, released by `unlockWrite` from `Release` once `openSpool.release`
has flushed, when the last of them goes (context detached from the request,
`lockReleaseTimeout`). `api.ErrLocked` → `EBUSY` (`toErrno`), the request of a caller
being killed → `EINTR`; any other failure is reported through `Logf` and the file
opened without a lock, as `lockMirror` grants a LOCK it could not mirror, and
the next open for writing asks again. No lock for a pending file (no node),
nor when its first flush stores it: the next open for writing takes one. An
`O_RDONLY` open never locks; `truncate(2)` without a handle neither. `Mount`
starts `LockManager.Run` (renewal every 2 min) and `Server.finish` stops it
after `closeSpools`, which releases what is left (`ReleaseAll`, 10 s) before
`Unmount` returns. `LockManager` itself is unchanged but for its gauge
(`setLocked` / `dropLocked` are the only two places its map changes).

Metrics of the driver: `call.end` (where the access log is written) feeds
`retyc_cli_fuse_ops_total{op,result}` and `retyc_cli_fuse_op_duration_seconds{op}`;
`op` is the access log's name, `result` is `resultLabel(errno)`: `ok`, a name
of `errnoNames`, or `other` (never `errno=N`, which the access log prints).
`retyc_cli_fuse_bytes_total{direction}` in `Read` / `Write`,
`retyc_cli_fuse_open_handles{kind}` in `Open` / `Create` (`countHandle`) and
`Release` (`handleKind`: `write` for a `spoolHandle` that `sends`). The access
log file itself (`.retycfs`) is not an operation counted.

### Local files (`mount.local_files`, `Options.LocalFiles`)

Glob patterns (`path.Match`) on the base name, default
`config.DefaultMountLocalFiles()` (`.*.swp`, `.*.swx`, `*~`, `4913`: what vim
creates around an edit). `config.Load` reads them through `GetStringSlice`
(environment: space-separated) and `localFilePatterns`: empty items dropped,
the single item `none` (`config.MountLocalFilesNone`) is the empty list — the
way to empty it from the environment, where viper ignores an empty value —,
a malformed pattern or one with a `/` is an error. `retycfs.Mount` checks the
patterns again. Shared lock files (`.~lock.*#`, `~$*`) are left out on
purpose: they must reach the other clients.

A local file is an `openSpool` over a pending `vfs.Spool` with
`openSpool.local` set, nothing more:
- `dirNode.Create` on a name that matches (`driver.localName`) looks the name
  up in the **listing** of the folder (`dirNode.listed`: `vfs.FS.ReadDir` +
  `FindNode`, never `LookupRemote`, O_EXCL or not), then creates the spool.
  A node the listing holds is opened as today. `dirNode.lookup` does the same
  for every name that matches (Lookup, `renamePending`): no request by name.
- `openSpool.flush` does nothing, `release` neither sends nor closes: the
  spool stays `inodeState.spool` with zero references (so `inodeTable.forget`
  keeps the state), until its unlink (the last `release` after
  `inodeState.unlinked` closes it) or `closeSpools`. `retire` counts no loss
  and logs nothing for it. `CopyFileRange` into one is `EXDEV`.
- `Unlink` takes the existing "pending" path: no request. `Rmdir` already
  answers `ENOTEMPTY` for a folder with a named spool.
- `Rename`: the callback of `vfs.Spool.Rename` decides `kept` (new name
  matches and `renamePending` found no node). Otherwise `dirNode.publish`
  clears `local`: with a writer open the close sends it; without one it is
  flushed there, and a failure puts it back (local, old place, old path) and
  is the errno of the rename. Over a node: a new version of it, like any
  pending file. A node renamed to a matching name is an ordinary API rename.
  `local` is read in `release` under `inodeState.mu`, and `publish` clears it
  before counting the writers under that mutex: one of the two sends.
- The registry keys a spool by the `*fs.Inode` of its folder. A local file
  outlives its handles, so the kernel may forget that inode and get another
  for the same number: `spoolRegistry.find` falls back on the inode number
  (`sameDir`) for local files and re-keys them; `list` and `Rmdir` compare
  with `sameDir`.

## Metrics (`webdav serve --metrics-addr`, `fs mount --metrics-addr`)

`internal/metrics` declares every metric as a package-level collector, observed
where the event happens and registered into the dedicated registry only by
`cmd/observability.go:newObservabilityHandler`. Unregistered collectors still
accept observations, so the MCP server and one-shot commands pay nothing.
Prefixes: `retyc_cli_*` for what is not WebDAV-specific (API round trips via
`api.WrapTransport(metrics.RoundTripper)`, token keepalive, per-chunk
crypto), `retyc_cli_vfs_*` for what `internal/vfs` does for both front ends
(node cache lookups, dataroom list refreshes, `spool_bytes`, `uploads_total`,
`locks_held`), `retyc_cli_webdav_*` for the server (requests, bytes),
`retyc_cli_fuse_*` for the driver (see "FUSE driver").

Both commands share the listener (`cmd/observability.go`): `metricsSettings`
(addr, runtime, labels) → `startObservability(settings, health, tree)`, which
parses the labels, builds the handler with `sessionsCachedGauge(tree)` and
binds; nil when the address is empty. Each command only resolves its own
settings and flips its own `serveHealth`: `webdav serve` through
`resolveWebdavMetrics` (the three `resolveMetrics*`, keys `webdav.metrics.*`),
`fs mount` through `mountFlags` and `cfg.Mount.Metrics` (keys
`mount.metrics.*`). `/readyz` of the mount: ready once `retycfs.Mount`
returned, not ready as soon as `serveMount` leaves its wait (signal, login
lost, unmounted from outside), before `Shutdown` and so for the whole drain;
the listener is closed when `runMount` returns (`stopObservability`).

Observed in `internal/vfs`: `retyc_cli_vfs_spool_bytes` is what the spool
files hold (`spool.accountLocked`, called wherever `size`, `src` or `closed`
change: the size once the content is in the file, `srcFrom` while the version
is not brought in, 0 once closed), not the logical size of the open files: a
file opened for writing and never touched counts for nothing;
`retyc_cli_vfs_uploads_total{result}` is counted once per `FS.upload` (so a
`Create`, a dirty `Flush`; not a clean `Flush`, not a server-side copy);
`retyc_cli_vfs_locks_held` follows `LockManager.locks`. Observed in
`redisstore` (`operation.end`, `observe.go`):
`retyc_cli_vfs_store_op_duration_seconds{op,result}`, one observation per
round trip to Redis, span or not (`op`: the 13 `op…` constants; `result`:
`ok` / `error`; `storeBuckets`, 100 µs to 5 s); the memstore observes nothing.

Adding a metric: declare it in `internal/metrics/metrics.go`, add it to `all`,
observe it at the event, add a row to `doc/webdav.md` (or `doc/retycfs.md` for
the driver's). Labels must stay
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
`annotationOffline` commands (`version`, `mcp manifest`, `config path`,
`config show`) never initialise tracing, since `Init` runs in `PersistentPreRunE` after that early return.

Span model:
- one-shot command: span `retyc <command path>`, child of `TRACEPARENT`,
  attributes `retyc.command`, `retyc.cli.version`;
- the request or command span is tagged with `retyc.dataroom.id` when a
  dataroom title is resolved (`vfs.DataroomCache.IDForName`) and `retyc.node.id`
  when a path resolves to a node (`service.resolvePath`): UUIDs only, never
  the title or the name;
- `retyc:long-running` commands (`webdav serve`, `mcp serve`, `fs mount`) get no command
  span (`fs mount`: `retyc fs mount init`, then one root `FUSE <op>` per
  operation that reaches the API, see "FUSE driver"): `webdav serve` opens `retyc fs webdav serve init` (child of
  `TRACEPARENT`, ended once the port is bound) then one root `WEBDAV <method>`
  per request (`instrumentWebdav`, `WithNewRoot`, incoming `traceparent`
  ignored), and one root `cache.refresh` per background refresh of an expired
  listing or dataroom list (`startRefreshSpan` in `internal/vfs/trace.go`: `WithNewRoot` + a link to the
  request that triggered it, `retyc.cache.name`, `retyc.dataroom.id` for
  nodes), never a child of the request span it would outlive. A fetch the
  request starts itself stays in its trace; a request that waits for a
  background refresh it joined gets a link to it (`linkRefresh`);
  `mcp serve` opens one root `MCP <tool>` per call; `toolErr`
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
  `dataroom.resolve_path`);
- the Redis metadata store: one CLIENT span `redis <op>` per round trip
  (`get_listing`, `get_node`, `listing_meta`, `generation`, `put_listing`,
  `upsert_node`, `remove_node`, `delete_listing`, `delete_subtree`,
  `get_entry`, `put_entry`, `delete_entries`, `delete_entries_below`), child of
  the span the context carries and **not opened without one** (see "Redis
  metadata store"): `db.system.name` = `redis`, `db.operation.name` = the op,
  `retyc.dataroom.id`, `retyc.node.count` for a listing read or written.

Every attribute key lives in `internal/telemetry/attrs.go` under the
`retyc.` prefix, `error.type`, `db.system.name` and `db.operation.name`
excepted (OTel's own names) (`retyc.chunk.plaintext_bytes` on `crypto.encrypt`,
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
| `github.com/prometheus/client_golang` | `--metrics-addr` exposition of `webdav serve` and `fs mount` (`cmd/observability.go`) |
| `github.com/redis/go-redis/v9` | Shared metadata cache (`internal/vfs/metastore/redisstore`), `cache.store: redis` |
| `github.com/hanwen/go-fuse/v2` | FUSE driver (`internal/retycfs`, Linux only, pure Go); forbidden to `internal/vfs` (`deps_test.go`) |

## CI

- **`main.yml`**: orchestrator on push/PR → calls `_ci.yml` (vet, test with race, build dev + prod) then `_docker.yml`;
  `_ci.yml` installs `fuse3` before the tests, which mount (`internal/retycfs`), and runs a `redis:8.10.2`
  service for those of the shared metadata cache (`REDISSTORE_TEST_URL`)
- **`release.yml`**: on `v*` tags only → prod build with ldflags, goreleaser, MCPB bundle, `gh release create`

## Conventions

- All code comments in **English**
- No `vendor/` directory — dependencies fetched from module cache
- `.retyc/` in CWD is gitignored (dev token/config should not be committed)
- `SilenceUsage: true` + `SilenceErrors: true` on rootCmd — errors printed once by `RunE`, not by cobra
- Exit codes: `exitCode` (`cmd/root.go`) returns `exitAuthRequired` (77) when the error wraps
  `auth.ErrNoToken` / `auth.ErrNoRefreshToken`, `exitConfig` (78) for `config.ErrNoKeyPassphrase` /
  `service.ErrWrongKeyPassphrase`, `exitLostWrites` (75) for `fs mount` writes lost at the unmount
  (`lostWritesError`, which `serveMount` puts around a `*retycfs.LostWritesError`; 77 wins when
  the login was lost too), 1 otherwise. Supervisors (`retyc-k8s-csi`) rely on 77/78 to stop
  restarting `webdav serve`: keep those sentinels wrapped (`%w`) up to `RunE`
- No auto-commit
- Always perform linting with `make lint-fix` after editing code (uses `golangci-lint` with `--fix` to auto-apply simple fixes)
