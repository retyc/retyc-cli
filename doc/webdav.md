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
retyc fs webdav serve
```

Then mount `http://localhost:8888` in your WebDAV client. Your datarooms appear under
the `/dataroom` folder.

## Requirements

- You must be authenticated first: `retyc auth login`.
- `RETYC_KEY_PASSPHRASE` **must** be set — the server never prompts interactively.
  It is used to unlock your AGE identity for decrypting/encrypting file contents.
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
| `RETYC_KEY_PASSPHRASE`  | yes             | Passphrase that unlocks your AGE identity (no interactive prompt)  |
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

| Action              | WebDAV method | Notes                                                     |
|---------------------|---------------|-----------------------------------------------------------|
| List / browse       | `PROPFIND`    | Names, sizes and MIME types are decrypted on the fly      |
| Read / download     | `GET`         | Streamed and decrypted locally; supports range requests   |
| Upload / overwrite  | `PUT`         | Encrypted locally, then chunked to the dataroom           |
| Create folder       | `MKCOL`       | `mkdir` inside a dataroom                                  |
| Delete              | `DELETE`      | Removes a node (or a folder and its contents)             |
| Rename / move       | `MOVE`        | Within the **same** dataroom only                         |
| Copy                | `COPY`        | Files only, within the **same** dataroom: the storage duplicates the chunks, nothing is downloaded (folders return `501`) |
| Lock / unlock       | `LOCK` / `UNLOCK` | Standard WebDAV locks; a lock on a file is mirrored onto the dataroom so other RETYC clients see it, and a file locked elsewhere answers `423` |
| Change permissions  | `PROPPATCH`   | The execute bits of a file's mode, through the `executable` property (`chmod +x` on a mount) |
| Quota               | `PROPFIND`    | `quota-used-bytes` / `quota-available-bytes` (RFC 4331) on every folder of a dataroom |

Notes and limitations:

- **Move is intra-dataroom only.** Moving a node from one dataroom to another is
  rejected. To relocate across datarooms, download then upload.
- **Copy is server-side, for files.** A `COPY` of a file asks the dataroom API to duplicate
  its last complete version into a new node; the server answers once the copy is sealed
  (about a second per gigabyte). The copy keeps the MIME type, mode and modification time.
  A destination that already exists is replaced (a new node, not a new version) unless the
  client sends `Overwrite: F`: it is deleted first, with its versions, which needs the right
  to delete it, and it is not restored when the copy then fails. The server keeps the name of
  a deleted file until its purge has run, so the copy is tried again for up to 15 seconds
  before answering `409`. Copying a folder is not supported (`501`): copy its files.
  The WebDAV locks apply as for any write: a destination locked by another client answers
  `423`, or `412` when the `If` header names no lock on it.
- **Permissions.** A dataroom stores a POSIX mode with every node, but WebDAV only
  carries a file's execute permission: the `executable` property (`T` / `F`, the one
  Apache mod_dav defines and davfs2 uses). A `PROPFIND` reports it from the stored mode,
  and a `PROPPATCH` of it (`chmod +x`, `chmod -x` on a mount) changes the execute bits of
  that mode, without creating a version: set, they follow the read bits (`0644` becomes
  `0755`, `0600` becomes `0700`); cleared, all three go. The other bits of a `chmod`
  (`chmod 600`) do not reach the server: the mount keeps them to itself until it forgets
  the file. Folders, and every other property, are read-only (`403`).
- **Locks are mirrored.** A `LOCK` on a file takes an exclusive advisory lock on the node
  in the dataroom, renewed in the background while the WebDAV lock stands (the server's
  lease is 5 minutes at most) and released on `UNLOCK` or when the server shuts down. A file
  already locked by another client, on another mount or in the web app, answers `423`.
  A lock whose timeout ran out without `UNLOCK` (its client went away) stops being
  renewed and is released within two minutes.
  The lock is advisory: it arbitrates between clients that lock, it does not block a write
  from one that does not. Locks on folders, and on files being created, stay local.
  The server holds one lock per client, so a second `retyc fs webdav serve` of the same user
  locking the same file gets `423` too; a lock this server still mirrors for a WebDAV lock
  that lapsed is released before the next `LOCK` on the file takes its place.
- **Symbolic links are not shown.** A dataroom may hold symlinks (created by a mount or
  another client); WebDAV has no such thing, so they are left out of listings and do not
  exist for this server: a `PUT` on a name a symlink holds answers `409`. `retyc dataroom ls`
  lists them as `LINK name -> target`.
- **Quota.** Every folder of a dataroom reports `quota-used-bytes` (what the dataroom
  stores, versions pending purge included) and `quota-available-bytes` (the room left on
  its reserved capacity, or on its owner's plan), refreshed with the listing TTL. File
  managers show them as the free space of the mount.
- **Uploading an existing name** creates a new **version** of that node rather than a
  duplicate.
- **Small files are one request.** A file of at most 8 MiB, one chunk (an empty one
  included), is sent with its node and its version in a single API call
  (`POST /dataroom/{id}/node/file`), kept in memory until the PUT completes; a larger
  file is streamed in 8 MiB chunks into a version created when the PUT starts. If a
  proxy in front of the API answers `413` (an older deployment limited that route to
  1 MiB), the file is sent again as a version and its chunks.
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
| under `cache.ttl` (default `1m`) | served from memory |
| up to `cache.max_stale` more (default `5m`) | served from memory **while one background refresh replaces it** |
| older | the request waits for a fresh listing |

The second row matters to clients that walk a whole tree after a pause: PrivateBin,
for instance, lists every folder of its store when it purges expired pastes, one
folder after the other. Without it, each folder of the walk waits for its own
API round trip; with it, the walk is answered from memory and the listings are
refreshed behind it. Background refreshes run at most `api.concurrency.list` at a
time; a request that needs a listing a refresh is still queued for starts it at
once. A failed refresh keeps the expired listing, except for a folder deleted
elsewhere, which is dropped so the next request answers `404`.

A refresh is conditional when the API supports it: the listing is kept with the
`ETag` of its dataroom and sent back as `If-None-Match`. While nothing changed in
the dataroom the API answers `304`, and the listing is kept for another TTL at the
cost of one round trip, with no page to fetch and no name to decrypt. The `ETag`
is per dataroom, not per folder: any change anywhere in the dataroom makes the
next refresh of each of its folders a full listing.

Mutations made through the server keep the cache exact. Changes made elsewhere
(web app, another client, another `webdav serve`) appear once the listing is
refreshed: after `cache.ttl` at best, after `ttl + max_stale` at worst, and
always one request late for an expired listing (that request still gets the
previous one: an old size, version or `ETag`, a node deleted since). A name the
expired listing does not hold is the exception: the request waits for the refresh
instead of answering `404`, so a file created elsewhere is found on first access.
Set `cache.max_stale` to `0` (`RETYC_CACHE_MAX_STALE=0`, `--cache-max-stale 0`)
to never serve an expired listing.

A file or folder whose parent has no listing in memory is looked up on its own.
A name found missing that way is answered missing for `cache.negative_ttl`
(default `1s`) without asking the API again, which absorbs the burst of probes a
client makes for one name; a name created elsewhere therefore shows up at most
that much later. `0` disables it: every such lookup asks the API. When a second
name of the same folder is looked up that way within `cache.ttl`, the listing of
the folder is also loaded in the background, and answers the lookups that follow.
A folder gets one such listing per `cache.ttl` at most, and none when it holds
more than 5,000 nodes: its lookups keep asking for one name each.

The three settings are durations and need a unit (`90s`, `2m`, `500ms`): a bare
number in `config.yaml` would be read as nanoseconds, so `ttl` and `max_stale`
under a second, and `negative_ttl` under a millisecond, are rejected at startup.

```yaml
cache:
  ttl: 1m
  max_stale: 5m
  negative_ttl: 1s
```

The section is shared with [`retyc fs mount`](retycfs.md#freshness), which never
serves an expired listing: `cache.max_stale` applies to the WebDAV server only.

Several servers, and mounts, can share this cache through a Redis
(`cache.store: redis`, `cache.redis.url`, `cache.redis.high_confidentiality`): what
one lists or changes is served to the others without a request, and survives a
restart. What Redis then holds, and what it requires, is described under
[Shared metadata cache (Redis)](retycfs.md#shared-metadata-cache-redis); it applies to
the WebDAV server as it stands.

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
- A refresh that fails for another reason (the identity provider unreachable,
  answering a 5xx or `429`, timing out) does not stop the server: it is reported once
  on stderr and tried again every minute. Requests to the API fail meanwhile if the access token has expired.
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
