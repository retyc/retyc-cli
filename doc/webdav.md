# WebDAV Server

`retyc fs webdav serve` exposes your datarooms as a network drive for Finder, Windows
Explorer, a file manager or any WebDAV client. Files are encrypted and decrypted locally:
the Retyc servers never see plaintext. On Linux, [RetycFS](retycfs.md) mounts them
directly.

```sh
retyc fs webdav serve            # http://127.0.0.1:8888, datarooms under /dataroom
```

It needs a login (`retyc auth login`) and the key passphrase: prompted, taken from the
[key cache](configuration.md#key-cache-linux), or `RETYC_KEY_PASSPHRASE` (required without
a terminal). A service keeps `RETYC_TOKEN`, `RETYC_KEY_PASSPHRASE` and
`RETYC_WEBDAV_PASSWORD` in an [environment file](configuration.md#environment-file).

## Options

| Flag                                 | Default          | Description                                                                                              |
|--------------------------------------|------------------|----------------------------------------------------------------------------------------------------------|
| `--addr`                             | `127.0.0.1:8888` | `host:port` to bind (`webdav.addr`)                                                                      |
| `--auth`                             | `false`          | Require HTTP Basic auth, see [Authentication](#authentication)                                           |
| `--cache-ttl`                        | `1m`             | How long a listing is served from memory (`cache.ttl`)                                                   |
| `--cache-max-stale`                  | `5m`             | How much longer an expired listing is served while refreshed, `0` to disable (`cache.max_stale`)         |
| `--cache-negative-ttl`               | `1s`             | How long a missing name is answered missing, `0` to disable (`cache.negative_ttl`)                        |
| `--cache-store`                      | `memory`         | `redis` to share the cache, see [Redis](retycfs.md#shared-metadata-cache-redis) (`cache.store`)           |
| `--cache-redis-url`                  | —                | Redis URL, password included: prefer the variable (`cache.redis.url`)                                    |
| `--cache-redis-high-confidentiality` | `false`          | Store names encrypted in Redis (`cache.redis.high_confidentiality`)                                      |
| `--unsafe-write`                     | `false`          | Faster uploads, [at a risk](configuration.md#acknowledge-uploads-before-they-are-stored) (`api.unsafe_write`) |

Every key also has a `RETYC_…` variable, see [Configuration](configuration.md#settings).
Durations need a unit (`90s`, `2m`).

## Layout

```
/
└── dataroom/
    ├── Project Alpha/        ← one folder per dataroom (its title)
    │   └── report.pdf
    └── Project Alpha (2)/    ← same title: numeric suffix, stable across refreshes
```

## Supported operations

| Action             | WebDAV method     | Notes                                                       |
|--------------------|-------------------|-------------------------------------------------------------|
| List / browse      | `PROPFIND`        | Names, sizes and MIME types decrypted on the fly            |
| Read / download    | `GET`             | Streamed, range requests supported                          |
| Upload / overwrite | `PUT`             | An existing name gets a new **version**                     |
| Create folder      | `MKCOL`           |                                                             |
| Delete             | `DELETE`          | A file, or a folder and its contents                        |
| Rename / move      | `MOVE`            | Within the **same** dataroom only                           |
| Copy               | `COPY`            | Files only, same dataroom, done by the server               |
| Lock / unlock      | `LOCK` / `UNLOCK` | Mirrored onto the dataroom                                  |
| Change permissions | `PROPPATCH`       | Execute bits only (`chmod +x`)                              |
| Quota              | `PROPFIND`        | `quota-used-bytes` / `quota-available-bytes` (RFC 4331)     |

- **Copy** duplicates the last version on the server, nothing downloaded. An existing
  destination is deleted first, unless `Overwrite: F`. Folders answer `501`.
- **Permissions**: only the `executable` property (davfs2's) is writable; it adds or
  removes the execute bits. Everything else answers `403`.
- **Locks** on a file are advisory locks in the dataroom: a file locked elsewhere answers
  `423`; clients that do not lock can still write. Locks on folders stay local.
- **Symbolic links are hidden** (WebDAV has none); a `PUT` on one answers `409`.
- File names containing `/` are left out of listings, with a warning.
- `ETag` is the version ID, `Last-Modified` its creation time.

## Caching

Listings are cached ([Freshness](retycfs.md#freshness)):

| Age of the cached listing                   | Behaviour                                          |
|---------------------------------------------|----------------------------------------------------|
| under `cache.ttl` (default `1m`)            | served from memory                                 |
| up to `cache.max_stale` more (default `5m`) | served from memory while refreshed in background   |
| older                                       | the request waits for a fresh listing              |

Changes made through the server are visible at once; changes made elsewhere appear at the
next refresh. `cache.max_stale` applies to WebDAV only (`0`: never serve an expired
listing).

## Authentication

By default the server binds to `127.0.0.1` without authentication: anyone who reaches
the port reads your decrypted files. On any other address, enable `--auth` and put the
server behind an HTTPS reverse proxy (WebDAV here is plain HTTP).

```sh
retyc fs webdav serve --auth                                      # password generated, printed once
RETYC_WEBDAV_PASSWORD='a-strong-password' retyc fs webdav serve --auth
```

The user name is always `retyc`.

## Connecting a client

| Client                 | How                                                                                     |
|------------------------|-----------------------------------------------------------------------------------------|
| macOS Finder           | **Go → Connect to Server…** (`⌘K`), `http://localhost:8888`                             |
| Windows Explorer       | **This PC → Map network drive…**, `http://localhost:8888` (Basic auth over HTTP may be refused: run without `--auth` locally) |
| GNOME Files            | **Other Locations → Connect to Server**, `dav://localhost:8888`                         |
| davfs2                 | `sudo mount -t davfs http://localhost:8888 /mnt/retyc`                                  |
| rclone                 | `rclone config create retyc webdav url http://localhost:8888 vendor other`              |

## Lifecycle

- The access token is refreshed in the background. If the refresh token expires, the
  server drains in-flight uploads and exits with code **77**: run `retyc auth login`.
  A transient failure (identity provider down) keeps it up and is retried every minute.
- `Ctrl-C` or `SIGTERM` finishes in-flight uploads, then exits.
- Exit codes: [Exit codes](commands.md#exit-codes). A supervisor should not restart on
  77 or 78.
- No metrics, probes nor traces: only [`fs mount`](retycfs.md#metrics-and-probes) has them.
