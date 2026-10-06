# WebDAV Server

`retyc-cli` runs as a local **WebDAV server** that exposes your Retyc datarooms as a
mountable network drive. Browse, open, upload, rename and delete dataroom files from
Finder, Windows Explorer, your file manager, or any WebDAV client — with the same
end-to-end post-quantum encryption as the rest of the CLI.

Files are encrypted and decrypted **locally** by the CLI. The Retyc servers never see
plaintext; only your machine holds the decrypted data while the server is running.

## Quick start

```sh
# The key passphrase is required (never prompted in server mode)
read -rs RETYC_KEY_PASSPHRASE
export RETYC_KEY_PASSPHRASE

# Start the server on localhost:8888
retyc webdav serve
```

Then mount `http://localhost:8888` in your WebDAV client. Your datarooms appear under
the `/dataroom` folder.

## Requirements

- You must be authenticated first: `retyc auth login`.
- `RETYC_KEY_PASSPHRASE` **must** be set — the server never prompts interactively.
  It is used to unlock your AGE identity for decrypting/encrypting file contents.

## Command

```
retyc webdav serve [flags]
```

| Flag           | Short | Default     | Description                                                        |
|----------------|-------|-------------|--------------------------------------------------------------------|
| `--addr`       |       | `127.0.0.1:8888` | `host:port` to bind (`127.0.0.1` = local only; also `webdav.addr` / `RETYC_WEBDAV_ADDR`) |
| `--auth`       |       | `false`     | Require HTTP Basic authentication                                  |
| `--unsafe-write` |     | `false`     | Let the API acknowledge uploads before storing them (also `api.unsafe_write` / `RETYC_API_UNSAFE_WRITE`): faster, but a failed background store goes unreported, see [configuration](configuration.md#acknowledge-uploads-before-they-are-stored) |
| `--metrics-addr` |     | *(empty)*   | Expose Prometheus metrics and health probes on this address (see [below](#metrics-probes-and-traces)) |
| `--metrics-runtime` |  | `true`      | Include the Go runtime and process metrics on `/metrics` (`--metrics-runtime=false` to drop them) |
| `--metrics-label` |    | *(none)*    | Constant label `key=value` added to every series; repeatable |

### Environment variables

| Variable                | Required        | Description                                                        |
|-------------------------|-----------------|--------------------------------------------------------------------|
| `RETYC_KEY_PASSPHRASE`  | yes             | Passphrase that unlocks your AGE identity (no interactive prompt)  |
| `RETYC_WEBDAV_PASSWORD` | with `--auth`   | Basic-auth password. If unset while `--auth` is on, one is generated and printed at startup |

## Layout

The server exposes a virtual filesystem:

```
/
└── dataroom/
    ├── Project Alpha/        ← one folder per dataroom (its title)
    │   ├── report.pdf
    │   └── contracts/
    │       └── nda.pdf
    └── Release v2/
        └── dist/
            └── retyc
```

- Each dataroom appears as a folder named after its **title**.
- If two datarooms share the same title, the second gets a numeric suffix
  (`Project Alpha`, `Project Alpha (2)`, …). The mapping is stable across refreshes,
  so a bookmarked path always points to the same dataroom.
- The `/dataroom` prefix namespaces the tree; other element types may be added at the
  root in the future.

## Supported operations

| Action              | WebDAV method | Notes                                                     |
|---------------------|---------------|-----------------------------------------------------------|
| List / browse       | `PROPFIND`    | Names, sizes and MIME types are decrypted on the fly      |
| Read / download     | `GET`         | Streamed and decrypted locally; supports range requests   |
| Upload / overwrite  | `PUT`         | Encrypted locally, then chunked to the dataroom           |
| Create folder       | `MKCOL`       | `mkdir` inside a dataroom                                  |
| Delete              | `DELETE`      | Removes a node (or a folder and its contents)             |
| Rename / move       | `MOVE`        | Within the **same** dataroom only                         |
| Copy                | `COPY`        | **Not supported** — the dataroom API has no server-side copy (returns `501`) |

Notes and limitations:

- **Move is intra-dataroom only.** Moving a node from one dataroom to another is
  rejected. To relocate across datarooms, download then upload.
- **Copy is unavailable.** Many clients implement a drag-copy as `COPY`; if yours fails,
  download the file and re-upload it instead.
- **Uploading an existing name** creates a new **version** of that node rather than a
  duplicate.
- **Small files are one request.** A file that fits in one 8 MB chunk (an empty one
  included) is sent with its node and its version in a single API call
  (`POST /dataroom/{id}/node/file`), kept in memory until the PUT completes; a larger
  file is streamed chunk by chunk into a version created when the PUT starts.
- **File names containing `/`** cannot be represented as a single path component and are
  skipped from listings (a warning is printed to stderr).
- Folder listings and the dataroom list are cached (see [Caching](#caching));
  dataroom sessions (the decrypted session
  keypair) are resolved once per dataroom and kept for the life of the process, since
  a dataroom's keypair never changes and each resolution unlocks the user key with an
  scrypt costing ~256 MiB of working memory when no keyring caches it.
  Mutations made through the server update the cached listings in place (a new
  folder is added to its parent and cached as empty, a deleted node is removed, a
  moved one changes listing), so the request a client sends right after is
  answered without an API call. A dataroom name the expired list does not hold
  waits for the refresh, so a dataroom created elsewhere is found on first access.
  A read that fails because the cached listing pointed at a deleted node drops that
  listing straight away, so the following request sees the current state (`404`)
  rather than replaying the stale entry until the TTL expires. Likewise, listing a
  folder deleted elsewhere answers `404`/`410` and is retried against a fresh
  parent listing, so it is never shown empty or with the children of the deleted
  folder (this relies on the API answering `404`/`410` to a listing whose
  `parent_id` names a deleted folder; against an API that answers an empty page,
  such a folder shows empty until its parent listing expires), and a delete or
  move that hits a node deleted elsewhere is retried once against a fresh
  listing. Concurrent requests for the same folder share a single
  listing, and a listing that was in flight when a mutation landed is discarded
  rather than cached. A shared fetch (a folder listing, the dataroom list) is
  bounded to 2 minutes: if the API stalls mid-response, the waiting requests fail
  and the next one starts a fresh fetch, instead of all hanging on the stalled
  one. A folder whose listing genuinely takes longer than that cannot be listed.
- Files expose the version ID as their `ETag` and the version's creation time as
  `Last-Modified`, so clients can detect a new version even when the size is
  unchanged. Folders have no timestamp in the API and report none.

## Caching

Every WebDAV request needs the listing of its folder, and every listing is an API
round trip. Folder listings and the dataroom list are therefore cached:

| Age of the cached listing | Behaviour |
|---|---|
| under `webdav.cache.ttl` (default `1m`) | served from memory |
| up to `webdav.cache.max_stale` more (default `5m`) | served from memory **while one background refresh replaces it** |
| older | the request waits for a fresh listing |

The second row matters to clients that walk a whole tree after a pause: PrivateBin,
for instance, lists every folder of its store when it purges expired pastes, one
folder after the other. Without it, each folder of the walk waits for its own
API round trip; with it, the walk is answered from memory and the listings are
refreshed behind it. Background refreshes run at most `api.concurrency.list` at a
time; a request that needs a listing a refresh is still queued for starts it at
once. A failed refresh keeps the expired listing, except for a folder deleted
elsewhere, which is dropped so the next request answers `404`.

Mutations made through the server keep the cache exact. Changes made elsewhere
(web app, another client, another `webdav serve`) appear once the listing is
refreshed: after `webdav.cache.ttl` at best, after `ttl + max_stale` at worst, and
always one request late for an expired listing (that request still gets the
previous one: an old size, version or `ETag`, a node deleted since). A name the
expired listing does not hold is the exception: the request waits for the refresh
instead of answering `404`, so a file created elsewhere is found on first access.
Set `webdav.cache.max_stale` to `0` (`RETYC_WEBDAV_CACHE_MAX_STALE=0`) to never
serve an expired listing.

Both settings are durations and need a unit (`90s`, `2m`): a bare number in
`config.yaml` would be read as nanoseconds, so anything under a second is
rejected at startup.

```yaml
webdav:
  cache:
    ttl: 1m
    max_stale: 5m
```

## Authentication (`--auth`)

By default the server binds to `127.0.0.1` and serves **without** HTTP authentication —
appropriate for a local-only mount. Anyone able to reach the port can read your
decrypted dataroom contents, so if you bind to a non-loopback address you should enable
`--auth`. A warning is printed when you bind to a public interface without it.

```sh
# Generate a random password (printed once at startup)
retyc webdav serve --auth

# Or provide your own
RETYC_WEBDAV_PASSWORD='choose-a-strong-password' retyc webdav serve --auth
```

- Username is always `retyc`.
- Credentials are compared in constant time.
- Startup prints the credentials to stderr (either the generated password, or a note
  that the password came from `RETYC_WEBDAV_PASSWORD`).

## Mounting

### macOS (Finder)

Finder → **Go → Connect to Server…** (`⌘K`) → enter `http://localhost:8888` →
**Connect**. With `--auth`, use username `retyc` and your password.

### Windows (Explorer)

**This PC → Map network drive… → Folder:** `http://localhost:8888` → **Finish**.
> Windows may refuse Basic auth over plain HTTP by default. For a local mount, run
> without `--auth`, or place the server behind an HTTPS reverse proxy.

### Linux — GNOME Files (Nautilus)

**Other Locations → Connect to Server:** `dav://localhost:8888` → **Connect**.

### Linux — command line (`davfs2`)

```sh
sudo mount -t davfs http://localhost:8888 /mnt/retyc
```

### Generic clients

Any client (Cyberduck, rclone, `cadaver`, …) can connect to `http://localhost:8888`.

```sh
# rclone example
rclone config create retyc webdav url http://localhost:8888 vendor other
rclone ls retyc:/dataroom
```

## Metrics, probes and traces

`--metrics-addr` (or `webdav.metrics.addr` in `config.yaml`, or
`RETYC_WEBDAV_METRICS_ADDR`) starts a second, unauthenticated HTTP listener meant
for Prometheus and container orchestrators. It is off by default.

```sh
retyc webdav serve --auth --metrics-addr 127.0.0.1:9090
```

| Path       | Purpose   | Response                                                                 |
|------------|-----------|--------------------------------------------------------------------------|
| `/metrics` | Prometheus | Go runtime and process metrics (`go_*`, `process_*`) plus the CLI metrics below |
| `/healthz` | Liveness  | `200` as long as the process answers                                      |
| `/readyz`  | Readiness | `200` once the WebDAV port accepts connections, `503` before that and as soon as a shutdown starts (signal or expired login) |

The listener is separate from the WebDAV port on purpose: scrapers and probes
need neither the Basic auth password nor a path inside the WebDAV tree. Bind it
to a loopback or private address; the metrics carry no dataroom content but do
describe the process. A probe never calls the Retyc API, so probing at a high
frequency costs nothing on the backend.

### Metrics

`--metrics-runtime=false` (or `webdav.metrics.runtime: false`,
`RETYC_WEBDAV_METRICS_RUNTIME=false`) removes the `go_*` and `process_*`
families. Use it when a parent process aggregates the `/metrics` of several
instances and already exposes its own runtime metrics, such as the CSI driver:
the same families with different labels and help strings do not merge. The
setting only matters together with `--metrics-addr`.

`--metrics-label key=value` (repeatable; `webdav.metrics.labels` as a list, or
`RETYC_WEBDAV_METRICS_LABELS="identity=abc pod=x"` separated by spaces) adds
constant labels to every series, runtime metrics included, so the parent can
tell its instances apart. The first `=` separates key and value. A key that
collides with a metric label (`method`, `route`, `status`, ...) or an invalid
label name stops the server at startup.

```sh
retyc webdav serve --metrics-addr 127.0.0.1:9090 --metrics-runtime=false \
  --metrics-label identity=pvc-1234
```

Labels never carry identifiers or raw paths: API routes are normalized
(`/dataroom/{id}/nodes`, `/file/{id}/{n}`), WebDAV methods outside the RFC set
are folded into `OTHER`.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `retyc_cli_build_info` | gauge | `version`, `goos`, `goarch` | Constant 1, joins the version onto any series |
| `retyc_cli_webdav_requests_total` | counter | `method`, `status` | WebDAV requests served |
| `retyc_cli_webdav_request_duration_seconds` | histogram | `method` | WebDAV request latency |
| `retyc_cli_webdav_inflight_requests` | gauge | | Requests being served right now |
| `retyc_cli_webdav_bytes_total` | counter | `direction` (`upload`, `download`) | Plaintext bytes moved through the server |
| `retyc_cli_webdav_node_cache_lookups_total` | counter | `result` (`hit`, `stale`, `miss`) | Folder listing cache efficiency (`stale`: expired listing served while refreshed) |
| `retyc_cli_webdav_dataroom_cache_refreshes_total` | counter | | Refreshes of the dataroom list (one API call each) |
| `retyc_cli_api_requests_total` | counter | `method`, `route`, `status` | Calls to the Retyc API (`status="error"` = no response) |
| `retyc_cli_api_request_duration_seconds` | histogram | `method`, `route` | API round-trip latency, the dominant cost of every WebDAV operation |
| `retyc_cli_sessions_cached` | gauge | | Dataroom session keys held unlocked in memory |
| `retyc_cli_token_refreshes_total` | counter | `result` (`ok`, `error`) | Keepalive checks of the login token (every 60 s) |
| `retyc_cli_token_expiry_seconds` | gauge | | Seconds left on the access token, 0 when unknown |
| `retyc_cli_crypto_duration_seconds` | histogram | `op` (`encrypt`, `decrypt`) | Per-chunk AGE operation time |

Chunk counts are the `retyc_cli_api_requests_total` series of the chunk routes
(`/dataroom/node/version/{id}/chunk/{n}` for uploads,
`/dataroom/node/{id}/download/{n}` for downloads); files that fit in one chunk are
uploaded through `/dataroom/{id}/node/file` instead.

### Traces

With an OTLP endpoint in the environment (see
[Tracing](configuration.md#tracing-opentelemetry)), `webdav serve` exports one
startup span (`retyc webdav serve init`: login check, key unlock as a
`crypto.unlock_key` child span, bind),
parented to `TRACEPARENT` when set, then one new trace per request, named
`WEBDAV <method>`, with the API calls, the per-chunk `crypto.encrypt` /
`crypto.decrypt` spans and the cache events it caused (`cache.lookup`, with
`retyc.cache.stale=true` for an expired listing served while refreshed). The
background refresh of such a listing is not part of the request's trace: it
runs after the request has answered, as a trace of its own, `cache.refresh`
(`retyc.cache.name` `nodes` or `datarooms`, plus `retyc.dataroom.id` for a
folder listing), carrying the API calls and a span link back to the request
that triggered it. A listing the request fetches itself (nothing cached, or
past `max_stale`) stays in the request's trace; when a request has to wait for a
background refresh already running (a name missing from the expired listing),
its span gets a link to that `cache.refresh` trace instead. Upload calls carry
`retyc.upload.unsafe_write`, telling whether the API was asked to store the chunk
in the background; a chunk download retried on a 404 shows as successive calls of
the same route. Requests are
never parented to the startup span, so a caller's trace closes once the server
is up. WebDAV clients issue many `PROPFIND`s: set
`OTEL_TRACES_SAMPLER=parentbased_traceidratio` and `OTEL_TRACES_SAMPLER_ARG`
to keep the volume reasonable. Spans never contain a path, a file name or a
dataroom title.

## Lifecycle & auth expiry

- The server keeps your access token warm by refreshing it in the background.
- If the **refresh token expires**, the server shuts down gracefully (draining any
  in-flight uploads) and exits with a message. Run `retyc auth login` and restart it.
- A login that cannot recover, at startup or while serving (no stored token, refresh
  token expired or revoked), exits with code **77**; a missing or wrong key passphrase
  exits with **78**; any other failure exits with 1. A supervisor should stop restarting
  on 77 and 78: the same credentials will fail again.
- `Ctrl-C` (SIGINT) or SIGTERM triggers a graceful shutdown: in-flight uploads finish,
  temporary files are cleaned up, and a failed upload is discarded: the node it created,
  or only its new version when it overwrote an existing file (best-effort — deleting needs
  a privileged role, so a contributor's failed version is reported, not removed). A file
  sent in a single request leaves nothing to discard: the server drops a failed one.

## Security notes

- File **contents and metadata** (names, MIME types, sizes) are encrypted end-to-end;
  the server decrypts them only in memory / temporary files on your machine.
- The WebDAV protocol itself is **plaintext HTTP**. Keep the bind address on
  `127.0.0.1` for local use. If you must expose it on a network, put it behind an
  HTTPS-terminating reverse proxy **and** enable `--auth`.
- `RETYC_KEY_PASSPHRASE` and `RETYC_WEBDAV_PASSWORD` are read from the environment —
  prefer `read -rs` over inline assignment to keep them out of your shell history.

## Example session

```sh
read -rs RETYC_KEY_PASSPHRASE
export RETYC_KEY_PASSPHRASE

# Local, authenticated server on a custom port
RETYC_WEBDAV_PASSWORD='s3cret' retyc webdav serve --addr 127.0.0.1:9000 --auth
# → WebDAV server listening on http://127.0.0.1:9000
# → WebDAV auth enabled: user "retyc", password from RETYC_WEBDAV_PASSWORD

# In another terminal / your file manager:
#   mount http://localhost:9000  (user retyc / s3cret)
#   open  /dataroom/Project Alpha/report.pdf
```
