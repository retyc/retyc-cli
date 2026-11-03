# WebDAV Server

`retyc-cli` runs as a local **WebDAV server** that exposes your Retyc datarooms as a
mountable network drive. Browse, open, upload, rename and delete dataroom files from
Finder, Windows Explorer, your file manager, or any WebDAV client — with the same
end-to-end post-quantum encryption as the rest of the CLI.

Files are encrypted and decrypted **locally** by the CLI. The Retyc servers never see
plaintext; only your machine holds the decrypted data while the server is running.

## Quick start

```sh
# Start the server on localhost:8888 (asks for the key passphrase)
retyc fs webdav serve
```

Then mount `http://localhost:8888` in your WebDAV client. Your datarooms appear under
the `/dataroom` folder.

## Requirements

- You must be authenticated first: `retyc auth login`.
- The key passphrase unlocks your AGE identity for decrypting/encrypting file contents.
  It is asked for on the terminal at startup, unless the key is still in the
  [keyring cache](configuration.md#tune-the-key-cache-linux) or `RETYC_KEY_PASSPHRASE`
  is set. Without a terminal, `RETYC_KEY_PASSPHRASE` is required.
  A service reads it, with `RETYC_TOKEN` and `RETYC_WEBDAV_PASSWORD`, from an environment
  file of mode `0600`: `retyc --env-file /etc/retyc/env fs webdav serve`, or
  `RETYC_ENV_FILE`. See
  [Configuration](configuration.md#keep-the-secrets-in-an-environment-file-boot-mounts-systemd-csi).

## Command

```
retyc fs webdav serve [flags]
```

> **Breaking changes.** The command used to be `retyc webdav serve`, the cache
> settings lived under `webdav.cache`: see
> [Breaking changes](#breaking-changes) before upgrading a deployment.

| Flag           | Short | Default     | Description                                                        |
|----------------|-------|-------------|--------------------------------------------------------------------|
| `--addr`       |       | `127.0.0.1:8888` | `host:port` to bind (`127.0.0.1` = local only; also `webdav.addr` / `RETYC_WEBDAV_ADDR`) |
| `--auth`       |       | `false`     | Require HTTP Basic authentication                                  |
| `--cache-ttl`  |       | `1m`        | How long a listing is served from memory (also `cache.ttl` / `RETYC_CACHE_TTL`), see [Caching](#caching) |
| `--cache-max-stale` |  | `5m`        | How much longer an expired listing is served while refreshed, `0` to disable (also `cache.max_stale` / `RETYC_CACHE_MAX_STALE`) |
| `--cache-negative-ttl` | | `1s`      | How long a name found missing is answered missing, `0` to disable (also `cache.negative_ttl` / `RETYC_CACHE_NEGATIVE_TTL`) |
| `--cache-store` |      | `memory`    | `memory`, or `redis` to share the cache between instances (also `cache.store` / `RETYC_CACHE_STORE`), see [Caching](#caching) |
| `--cache-redis-url` |  | *(empty)*   | `redis://` or `rediss://` URL of that Redis, password included (also `cache.redis.url` / `RETYC_CACHE_REDIS_URL`, to be preferred to the flag) |
| `--cache-redis-high-confidentiality` | | `false` | Store in Redis the encrypted names the API sent, never the decrypted ones (also `cache.redis.high_confidentiality` / `RETYC_CACHE_REDIS_HIGH_CONFIDENTIALITY`) |
| `--unsafe-write` |     | `false`     | Let the API acknowledge uploads before storing them (also `api.unsafe_write` / `RETYC_API_UNSAFE_WRITE`): faster, but a failed background store goes unreported, see [configuration](configuration.md#acknowledge-uploads-before-they-are-stored) |

### Environment variables

| Variable                | Required        | Description                                                        |
|-------------------------|-----------------|--------------------------------------------------------------------|
| `RETYC_KEY_PASSPHRASE`  | without a TTY   | Passphrase that unlocks your AGE identity (prompted otherwise)     |
| `RETYC_WEBDAV_PASSWORD` | with `--auth`   | Basic-auth password. If unset while `--auth` is on, one is generated and printed at startup |
| `RETYC_ENV_FILE`        | no              | File of `RETYC_*` variables (same as `--env-file`), where a service keeps the two above |

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

| Action              | WebDAV method     | Notes                                                                 |
|---------------------|-------------------|-----------------------------------------------------------------------|
| List / browse       | `PROPFIND`        | Names, sizes and MIME types are decrypted on the fly                  |
| Read / download     | `GET`             | Streamed and decrypted locally; supports range requests               |
| Upload / overwrite  | `PUT`             | Encrypted locally; an existing name gets a new **version**            |
| Create folder       | `MKCOL`           |                                                                       |
| Delete              | `DELETE`          | A node, or a folder and its contents                                  |
| Rename / move       | `MOVE`            | Within the **same** dataroom only                                     |
| Copy                | `COPY`            | Files only, within the **same** dataroom, done by the server          |
| Lock / unlock       | `LOCK` / `UNLOCK` | Mirrored onto the dataroom, see below                                 |
| Change permissions  | `PROPPATCH`       | The execute bits only (`chmod +x`), see below                         |
| Quota               | `PROPFIND`        | `quota-used-bytes` / `quota-available-bytes` (RFC 4331)               |

- **Move and copy stay inside a dataroom.** To relocate across datarooms, download
  then upload.
- **Copy** duplicates the file's last version on the server: nothing is downloaded
  (about a second per gigabyte). The copy keeps the MIME type, mode and modification
  time. An existing destination is deleted first, with its versions, unless the client
  sends `Overwrite: F`; it is not restored if the copy fails. Folders answer `501`.
- **Permissions.** WebDAV only carries a file's execute permission, through the
  `executable` property (the one davfs2 uses). Setting it gives the execute bits to
  whoever can read (`0644` → `0755`); clearing it removes them. Other `chmod` bits are
  not sent to the server. Folders and every other property are read-only (`403`).
- **Locks.** A `LOCK` on a file takes an advisory lock on it in the dataroom, held until
  `UNLOCK`, the shutdown, or within two minutes of the WebDAV lock timing out. A file locked
  elsewhere (another mount, the web app, another `webdav serve` of the same user) answers
  `423`. Clients that do not lock can still write. Locks on folders stay local.
- **Symbolic links are hidden**: WebDAV has none. A `PUT` on a symlink's name answers
  `409`; `retyc dataroom ls` shows them.
- **Quota** is reported on every folder of a dataroom; file managers show it as the free
  space of the mount.
- **File names containing `/`** cannot be a path component: they are left out of
  listings, with a warning on stderr.
- Files expose their version ID as `ETag` and its creation time as `Last-Modified`.
  Folders have no timestamp.
- A listing that takes more than 2 minutes fails; the next request tries again.

## Caching

Every request needs the listing of its folder, and every listing is an API round trip:
folder listings and the dataroom list are cached.

| Age of the cached listing                   | Behaviour                                                       |
|---------------------------------------------|-----------------------------------------------------------------|
| under `cache.ttl` (default `1m`)            | served from memory                                              |
| up to `cache.max_stale` more (default `5m`) | served from memory **while a background refresh replaces it**   |
| older                                       | the request waits for a fresh listing                           |

- **Changes made through the server** are visible at once, to every client of it.
- **Changes made elsewhere** (web app, another client) appear when the listing is
  refreshed. A listing in use is renewed in the background past 30 to 50% of
  `cache.ttl`; an idle one is refreshed by the next request, which still gets the old
  one if it is within `max_stale`. A name an expired listing does not hold waits for
  the refresh instead of answering `404`.
- **Refreshes are cheap when nothing changed**: the API answers `304`. Any change in the
  dataroom makes the next refresh of each of its folders a full listing.
- **`cache.max_stale: 0`** never serves an expired listing.
- **`cache.negative_ttl`** (default `1s`): how long a name found missing is answered
  missing without asking again. `0` disables it.
- The settings are durations and **need a unit** (`90s`, `2m`): a bare number would be
  nanoseconds, and is refused.

```yaml
cache:
  ttl: 1m
  max_stale: 5m
  negative_ttl: 1s
```

The `cache` section is shared with [`retyc fs mount`](retycfs.md#freshness);
`max_stale` applies to the WebDAV server only. Several servers and mounts can share the
cache through a Redis (`cache.store: redis`), see
[Shared metadata cache (Redis)](retycfs.md#shared-metadata-cache-redis).

## Authentication (`--auth`)

By default the server binds to `127.0.0.1` and serves **without** HTTP authentication —
appropriate for a local-only mount. Anyone able to reach the port can read your
decrypted dataroom contents, so if you bind to a non-loopback address you should enable
`--auth`. A warning is printed when you bind to a public interface without it.

```sh
# Generate a random password (printed once at startup)
retyc fs webdav serve --auth

# Or provide your own
RETYC_WEBDAV_PASSWORD='choose-a-strong-password' retyc fs webdav serve --auth
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

`webdav serve` exposes none: no Prometheus metrics, no health probes, no
OpenTelemetry traces. Only [`fs mount`](retycfs.md#metrics-and-probes) has them.

## Lifecycle & auth expiry

- The server keeps your access token warm by refreshing it in the background.
- If the **refresh token expires**, the server shuts down gracefully (draining any
  in-flight uploads) and exits with a message. Run `retyc auth login` and restart it.
- A refresh that fails for another reason (identity provider down) keeps the server
  up; it is reported once and retried every minute. API requests fail meanwhile once
  the access token has expired.
- A login that cannot recover, at startup or while serving (no stored token, refresh
  token expired or revoked), exits with code **77**; a missing or wrong key passphrase
  exits with **78**; any other failure exits with 1. A supervisor should stop restarting
  on 77 and 78: the same credentials will fail again.
- `Ctrl-C` (SIGINT) or SIGTERM shuts down gracefully: in-flight uploads finish, and a
  failed upload is discarded (best-effort: a contributor may lack the right to delete).

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
RETYC_WEBDAV_PASSWORD='s3cret' retyc fs webdav serve --addr 127.0.0.1:9000 --auth
# → WebDAV server listening on http://127.0.0.1:9000
# → WebDAV auth enabled: user "retyc", password from RETYC_WEBDAV_PASSWORD

# In another terminal / your file manager:
#   mount http://localhost:9000  (user retyc / s3cret)
#   open  /dataroom/Project Alpha/report.pdf
```

## Breaking changes

Nothing below has an alias: a deployment (service unit, container arguments,
Helm values, dashboards, alerts) must be updated together with the binary.

| Before | Now | What happens with the old form |
|---|---|---|
| `retyc webdav serve` | `retyc fs webdav serve` | unknown command, the process exits at once |
| `webdav.cache.ttl`, `RETYC_WEBDAV_CACHE_TTL` | `cache.ttl`, `RETYC_CACHE_TTL`, `--cache-ttl` | refused at startup: `webdav.cache.ttl was replaced by cache.ttl` |
| `webdav.cache.max_stale`, `RETYC_WEBDAV_CACHE_MAX_STALE` | `cache.max_stale`, `RETYC_CACHE_MAX_STALE`, `--cache-max-stale` | refused at startup: `webdav.cache.max_stale was replaced by cache.max_stale` |

The old cache keys are refused by **every** command that reads the configuration,
not only by the server: a `config.yaml` or an environment that still carries one
stops `retyc dataroom ls` too, until the key is renamed. The values and their
meaning did not change. `cache.negative_ttl` (`1s`) is new and was a fixed second
before.

The cache settings moved because they belong to the tree both
`retyc fs webdav serve` and `retyc fs mount` are built on. The other `webdav.*`
keys and `RETYC_WEBDAV_*` variables are unchanged.
