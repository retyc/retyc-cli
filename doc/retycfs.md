# RetycFS

RetycFS mounts your datarooms as a local folder (`retyc fs mount`). Any program reads and
writes them like local files; files are encrypted and decrypted **locally**, the Retyc
servers never see plaintext. Linux only; elsewhere, see
[Without a mount: WebDAV](#without-a-mount-webdav).

The mount is read-write; `--read-only` refuses every change. A dataroom you may only
read (viewer role, or a plan that refuses writes) is read-only whatever the option.

## Quick start

```sh
# The key passphrase is required (never prompted)
read -rs RETYC_KEY_PASSPHRASE
export RETYC_KEY_PASSPHRASE

mkdir -p ~/dr
retyc fs mount retyc://<dataroom-id> ~/dr      # one dataroom, at the root of ~/dr
retyc fs mount --all ~/retyc                   # every dataroom, one folder each
```

The command stays in the foreground until it is unmounted.

## Requirements

- A login (`retyc auth login`, or `RETYC_TOKEN`) and `RETYC_KEY_PASSPHRASE`, in the
  environment or in
  an [environment file](configuration.md#keep-the-secrets-in-an-environment-file-boot-mounts-systemd-csi)
  (`--env-file`, for boot mounts and systemd units).
- `/dev/fuse`, and unless run as root the `fusermount3` helper (package `fuse3`).
- An empty directory as mount point.

## Features and limits

| Feature                                   |    | Notes                                                                         |
|-------------------------------------------|:--:|-------------------------------------------------------------------------------|
| Read and write files, folders, `mv`, `rm` | ✅  | A file is sent as a new version when it is closed ([Writing](#writing))       |
| Version history                           | ✅  | When the dataroom keeps versions                                              |
| Server-side copy (`cp` within a dataroom) | ✅  | Nothing downloaded nor uploaded, up to 4 GiB (coreutils 9 and later)          |
| Symbolic links, file modes, mtimes        | ✅  | Stored encrypted with the file                                                |
| Free space (`df`)                         | ✅  | The dataroom's storage quota                                                  |
| Node identifiers as extended attributes   | ✅  | `getfattr -d file`: `user.retyc.node_id`, `version_id`, `dataroom_id`, `mime` |
| Editor swap and backup files kept local   | ✅  | [Local files](#local-files)                                                   |
| API locks while a file is written         | ✅  | Optional, [Locks](#locks)                                                     |
| Removal answered at once                  | ✅  | Optional, [Deleting in the background](#deleting-in-the-background)           |
| Metadata cache shared between instances   | ✅  | [Redis](#shared-metadata-cache-redis)                                         |
| Metrics, probes, traces                   | ✅  | [Metrics and probes](#metrics-and-probes)                                     |
| Partial upload of a change                | ❌  | Changing one byte of a large file downloads and uploads it whole              |
| Hard links, special files, writing xattrs | ❌  | Refused                                                                       |
| `chown`, access times, mode of a folder   | ❌  | Accepted and ignored; the owner shown is `--uid` / `--gid`                    |
| `mv` between two datarooms                | ⚠️ | Copy then delete                                                              |

The mount suits documents, not databases or disk images.

## Writing

A file opened for writing is kept in a local temporary file (the *spool*, `--spool-dir`,
mode 0600, cleartext) and sent, encrypted, **when it is closed** or `fsync`ed:

- **the error of the upload is the error of `close`** (`No space left on device` when the
  dataroom or the spool is full, `Read-only file system` when the owner's plan is
  exceeded). A program that ignores it does not see it; the command's output reports it;
- nothing is sent before: a crash loses what was written since the last `close`;
- uploads go `api.concurrency.upload` at a time (4 by default): thousands of small files
  written at once take a while to reach the API, see [Unmounting](#unmounting).

Size the spool directory for the largest files written at the same time.

## Freshness

Listings are cached for `cache.ttl` (one minute): a change made elsewhere is seen at most
that late. Opening a file always checks its current version against that cache; a file
already open keeps reading the version it opened. File content is never cached on disk;
the kernel keeps what it read in memory until the file changes.

| Flag                   | Key, variable                                    | Default |                                                                          |
|------------------------|--------------------------------------------------|---------|--------------------------------------------------------------------------|
| `--cache-ttl`          | `cache.ttl`, `RETYC_CACHE_TTL`                   | `1m`    | How long a listing or a name is trusted, by the mount and by the kernel. |
| `--cache-negative-ttl` | `cache.negative_ttl`, `RETYC_CACHE_NEGATIVE_TTL` | `1s`    | How long a missing name is answered missing. `0` disables it.            |

## Warmup

The first `ls` or `stat` of a folder costs an API listing and the decryption of its
names. Once mounted, the mount lists every folder in the background, like a `find` run
right after mounting, so that an application scanning its volume at startup is answered
from the cache. It is on by default; `--warmup=false` turns it off, `--warmup-depth=N`
lists N levels of each dataroom only (its root is the first).

- **The mount does not wait for it**: it is ready (`/readyz`) and answers at once. A
  request for a folder being listed shares that listing.
- **A few listings at a time**: the walk shares the `api.concurrency.list` slots with the
  refreshes of expired listings.
- **Only listings** (names and attributes) are warmed, never file contents.
- **They stay fresh for `cache.ttl` only** (one minute by default): the mount never
  serves an expired listing. For a lasting effect, raise `--cache-ttl` or use a
  [shared Redis](#shared-metadata-cache-redis), where a listing another instance
  fetched is not fetched again: a second mount of the same dataroom warms almost for
  free.
- **Each mount lists the whole dataroom once**, and holds it in memory while it is fresh
  (see [Memory](#memory)). On very large datarooms, or many mounts without Redis,
  consider `--warmup=false`.
- A folder that cannot be listed is reported and skipped; the walk goes on. It stops at
  the unmount, and when the login is lost. One line tells what it did:

  ```
  mount: listing cache warmed: 513 folders, 50000 files, 0 errors in 41.2s
  ```

## Local files

Files **created through the mount** whose name matches a `--local-file` pattern are kept
on this machine and **never sent**: editor swap files, backups, probes. They are visible
on this mount only and **gone at the unmount**. Defaults: `.*.swp`, `.*.swx`, `*~`,
`4913`. Patterns are globs on the file name; each source replaces the list, `none`
empties it.

```sh
retyc fs mount --local-file '.*.swp' --local-file '*.tmp' retyc://<dataroom-id> ~/dr
```

Office lock files (`.~lock.*#`, `~$*`) are not in the defaults on purpose: they tell
other people the document is open.

## Locks

`--mirror-locks` takes an exclusive lock at the API on an existing file while it is open
for writing. A file another RETYC client has locked fails to open for writing with
`EBUSY`, and can still be read. The locks are advisory: a client that does not take them
(the web application, a mount without the option) writes all the same. A killed mount
leaves its locks to lapse within five minutes.

## Deleting in the background

`rm` waits for one API request per file (100 to 200 ms each). `--background-delete`
answers at once and deletes at the API afterwards, `api.concurrency.upload` at a time.
The trade-off: **a successful `rm` no longer proves the file is deleted**. Other clients
still see it until the delete is sent; a delete the API refuses is reported on the
command's output and the file comes back in the mount. Do not use it where a removal
must be done when `rm` returns.

## Unmounting

`Ctrl-C`, `SIGTERM`, or `fusermount3 -u <mountpoint>`. The files still on their way to
the API get `--drain-timeout` (5 minutes) to be sent; a second signal abandons them:

```
mount: stopping: 120 files still to send to the API, waiting for them up to 5m0s (drain timeout); a second signal abandons them
mount: drain over after 2.1s: everything was sent
```

A file a program still holds open is sent as it is, possibly incomplete: **stop the
programs that write before the mount**. Files that could not be sent are reported by
identifiers (never by name) and are lost. In Kubernetes, keep
`terminationGracePeriodSeconds` above `--drain-timeout`.

| Exit code | Meaning                                                                    |
|-----------|----------------------------------------------------------------------------|
| `0`       | Unmounted, nothing lost                                                    |
| `75`      | Writes lost at the unmount (`kind: lost_writes` with `--json`)             |
| `77`      | Login expired and not renewable: run `retyc auth login`. Do not restart    |
| `78`      | Missing or wrong key passphrase. Do not restart                            |
| `1`       | Any other failure, including at start (Redis unreachable, bad mount point) |

A login revoked on the server unmounts within seconds of the next request. A login check
that fails for a transient reason (identity provider down) keeps the mount up and is
retried every minute.

## Containers

The published image is `scratch`, without `fusermount3`: run it as root so that it mounts
with `mount(2)`, give it `/dev/fuse` and `SYS_ADMIN`, and present the files to the
workload's user with `--uid` / `--gid` / `--allow-other`. Put the spool on a `tmpfs` or
a volume sized for the largest file written.

```sh
docker run --rm --user 0 \
  --device /dev/fuse --cap-add SYS_ADMIN \
  -e RETYC_TOKEN -e RETYC_KEY_PASSPHRASE \
  --tmpfs /tmp \
  -v /mnt/dr:/mnt/dr:rshared \
  retyc/retyc-cli:latest fs mount retyc://<dataroom-id> /mnt/dr \
    --allow-other --uid 1000 --gid 1000
```

Under Docker on Ubuntu add `--security-opt apparmor=unconfined`. To use the mount from
another container, share the mount point with `rshared` / `Bidirectional` propagation.
See also [Docker](docker.md).

## Shared metadata cache (Redis)

With `cache.store: redis`, the listings are kept in a Redis that several instances
share: a folder one instance listed is served to the others without an API request, a
change made through one is seen by the others at once, and a restart finds the cache
warm. File content is never stored there.

```yaml
cache:
  store: redis
  redis:
    url: rediss://:password@redis.example.com:6379/0
    high_confidentiality: false
```

| Flag                                 | Key, variable                                                                | Default  |                                                   |
|--------------------------------------|------------------------------------------------------------------------------|----------|---------------------------------------------------|
| `--cache-store`                      | `cache.store`, `RETYC_CACHE_STORE`                                           | `memory` | `memory` or `redis`.                              |
| `--cache-redis-url`                  | `cache.redis.url`, `RETYC_CACHE_REDIS_URL`                                   | —        | `redis://` or `rediss://` URL, password included. |
| `--cache-redis-high-confidentiality` | `cache.redis.high_confidentiality`, `RETYC_CACHE_REDIS_HIGH_CONFIDENTIALITY` | `false`  | Store names encrypted, see below.                 |

- **Redis 7.4 or later, standalone** (no Cluster nor Sentinel). It is checked at start.
- **The URL is a secret**: pass it by variable or environment file, not by flag.
- **By default Redis holds the decrypted file names**, which the RETYC servers never see:
  use a Redis you trust as much as the machines that mount (`rediss://`, a password, no
  other tenant). With `high_confidentiality`, names are stored encrypted as the API sends
  them, at the cost of one decryption per name read (about 0.2 ms) and about eight times
  more memory in Redis.
- **Give Redis a `maxmemory` and `allkeys-lru`**: an evicted key only costs an API
  request, never a stale answer. Instances sharing a Redis should share their `cache.*`
  settings.
- **If Redis fails**, the instance falls back on its own memory for a few minutes and
  tries again; no operation fails. The output says so:

  ```
  mount: listing cache: the store failed and is set aside for an in-memory one for 6m0s: …
  mount: listing cache: back on the configured store
  ```

`scripts/redis-cache-dump.sh` (source repository) decodes a cache to JSON for diagnosis.

## Memory

Most of a mount's memory is what it keeps per file the kernel holds: every file that
was `stat`ed, opened or shown by `ls -l`, about **1.4 kB each**, until the kernel needs
the memory back. A file only listed (`ls`, `find`) costs **300 to 600 B**. The process
starts at about 30 MB, and its resident memory (RSS) is about twice these figures.

Measured on 50,000 files in 513 folders, everything listed once:

### Cache in memory

| Walk                         | RetycFS process |
|------------------------------|-----------------|
| names only (`find`)          | + 29 MB         |
| with attributes (`ls -lR`)   | + 71 MB         |
| names only, `--readdir-plus` | + 68 MB         |

### Cache in Redis

| Walk                         | RetycFS process | Redis server (default / `high_confidentiality`) |
|------------------------------|-----------------|-------------------------------------------------|
| names only (`find`)          | + 14 MB         | 11 MB / 96 MB                                   |
| with attributes (`ls -lR`)   | + 67 MB         | 11 MB / 96 MB                                   |
| names only, `--readdir-plus` | + 59 MB         | 11 MB / 96 MB                                   |

### Notes

- **Redis lightens a mount that lists, not one that reads attributes.** It also slows
  `ls -l` on large folders a little (one Redis round trip per file not in memory).
- **`--readdir-plus`** makes a plain listing cost as much as `ls -l`, in exchange for
  fewer kernel requests: leave it off unless `ls -l` latency matters more than memory.
- What nobody reads for about eleven `cache.ttl` is released. A backup or an indexer that
  walks the whole tree holds all of it while it walks: size on the table above.

## Options

Every flag has a configuration key and an environment variable; the flag wins, then the
variable, then the [configuration file](configuration.md#settings).

| Flag                        | Key, variable                                                                        | Default                    |                                                                                                                                      |
|-----------------------------|--------------------------------------------------------------------------------------|----------------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| `--read-only`               | `mount.read_only`, `RETYC_MOUNT_READ_ONLY`                                           | `false`                    | Refuse every change.                                                                                                                 |
| `--entry-ttl`, `--attr-ttl` | `mount.entry_ttl`, `mount.attr_ttl`, `RETYC_MOUNT_ENTRY_TTL`, `RETYC_MOUNT_ATTR_TTL` | `0` (= `cache.ttl`)        | How long the kernel keeps a name, and a file's attributes, without asking again.                                                     |
| `--kernel-cache`            | `mount.kernel_cache`, `RETYC_MOUNT_KERNEL_CACHE`                                     | `true`                     | The kernel keeps what it read of a file between two opens. `false`: every open downloads again.                                      |
| `--readdir-plus`            | `mount.readdir_plus`, `RETYC_MOUNT_READDIR_PLUS`                                     | `false`                    | Send attributes with listings: faster `ls -l`, more memory (see [Memory](#memory)).                                                  |
| `--spool-dir`               | `mount.spool_dir`, `RETYC_MOUNT_SPOOL_DIR`                                           | system temporary directory | Where files being written are kept until sent (cleartext, 0600). Checked at start.                                                   |
| `--allow-other`             | `mount.allow_other`, `RETYC_MOUNT_ALLOW_OTHER`                                       | `false`                    | Let other users in. Unless root, needs `user_allow_other` in `/etc/fuse.conf`.                                                       |
| `--uid`, `--gid`            | `mount.uid`, `mount.gid`, `RETYC_MOUNT_UID`, `RETYC_MOUNT_GID`                       | `-1` (the command's)       | Owner shown for every file.                                                                                                          |
| `--file-mode`, `--dir-mode` | `mount.file_mode`, `mount.dir_mode`, `RETYC_MOUNT_FILE_MODE`, `RETYC_MOUNT_DIR_MODE` | `0644`, `0755`             | Permissions of a file or folder with none stored (quote them in YAML).                                                               |
| `--drain-timeout`           | `mount.drain_timeout`, `RETYC_MOUNT_DRAIN_TIMEOUT`                                   | `5m`                       | Time given to pending uploads at the unmount. See [Unmounting](#unmounting).                                                         |
| `--mirror-locks`            | `mount.mirror_locks`, `RETYC_MOUNT_MIRROR_LOCKS`                                     | `false`                    | See [Locks](#locks).                                                                                                                 |
| `--background-delete`       | `mount.background_delete`, `RETYC_MOUNT_BACKGROUND_DELETE`                           | `false`                    | See [Deleting in the background](#deleting-in-the-background).                                                                       |
| `--warmup`                  | `mount.warmup`, `RETYC_MOUNT_WARMUP`                                                 | `true`                     | See [Warmup](#warmup).                                                                                                               |
| `--warmup-depth`            | `mount.warmup_depth`, `RETYC_MOUNT_WARMUP_DEPTH`                                     | `0` (all)                  | Levels of folders the warmup lists in each dataroom, its root being the first.                                                       |
| `--local-file pattern`      | `mount.local_files`, `RETYC_MOUNT_LOCAL_FILES` (separated by spaces)                 | `.*.swp .*.swx *~ 4913`    | See [Local files](#local-files).                                                                                                     |
| `--unsafe-write`            | `api.unsafe_write`, `RETYC_API_UNSAFE_WRITE`                                         | `false`                    | Faster `close`, at the risk of an unreadable file. See [Configuration](configuration.md#acknowledge-uploads-before-they-are-stored). |
| `--metrics-addr`            | `mount.metrics.addr`, `RETYC_MOUNT_METRICS_ADDR`                                     | — (off)                    | See [Metrics and probes](#metrics-and-probes).                                                                                       |
| `--metrics-label key=value` | `mount.metrics.labels`, `RETYC_MOUNT_METRICS_LABELS` (separated by spaces)           | —                          | Constant label on every metric; repeatable.                                                                                          |

The cache settings are under [Freshness](#freshness) and
[Shared metadata cache](#shared-metadata-cache-redis).

## Metrics and probes

`--metrics-addr 127.0.0.1:9090` starts an unauthenticated listener, bound before
mounting:

| Path       | Response                                                                                       |
|------------|------------------------------------------------------------------------------------------------|
| `/metrics` | Prometheus metrics, Go runtime and process ones (`go_*`, `process_*`) included                  |
| `/healthz` | `200` while the process answers                                                                |
| `/readyz`  | `200` once mounted; `503` before, and as soon as the mount starts to stop (signal, lost login) |

`--metrics-label key=value` adds a constant label to every series, so a supervisor
aggregating several mounts can tell them apart. The first `=` splits key and value;
an invalid name, a reserved one (`le`, `quantile`, `__*`) or one a metric already
uses (`method`, `route`, `status`, …) stops the mount at startup.

Labels never carry an identifier, a name or a path. Every metric starts with
`retycfs_` (the full list is on `/metrics`, with its `HELP` text). The ones to watch:

| Metric                                                    | Meaning                                                                 |
|-----------------------------------------------------------|-------------------------------------------------------------------------|
| `retycfs_ops_total{op,result}`                            | Filesystem operations, by result (`ok`, `ENOENT`, `EIO`, …)             |
| `retycfs_op_duration_seconds{op}`                         | Duration of an operation                                                |
| `retycfs_api_requests_total{method,route,status}`         | Calls to the Retyc API (`status="error"`: no response)                  |
| `retycfs_api_request_duration_seconds{method,route}`      | API round-trip latency, the dominant cost of an operation               |
| `retycfs_api_rate_limited_total{method}`                  | API requests given up on `429`                                          |
| `retycfs_uploads_total{result}`                           | Files sent to the API                                                   |
| `retycfs_spool_bytes`                                     | Bytes held in the spool directory                                       |
| `retycfs_cache_lookups_total{result}`                     | Listing cache efficiency (`hit`, `stale`, `miss`)                       |
| `retycfs_warmup_folders_total{result}`                    | Folders listed by the [warmup](#warmup) (`ok`, `error`)                 |
| `retycfs_warmup_duration_seconds`                         | Duration of the warmup, set when it ends                                |
| `retycfs_token_expiry_seconds`                            | Seconds left on the access token, 0 when unknown                        |

Chunk counts are the `retycfs_api_requests_total` series of the chunk routes
(`/dataroom/node/version/{id}/chunk/{n}`); files of at most 8 MiB are uploaded
through `/dataroom/{id}/node/file` instead.

### Traces

With an OTLP endpoint in the environment (see
[Tracing](configuration.md#tracing-opentelemetry)), the mount exports one startup
span (`retyc fs mount init`: login check, key unlock, mount), parented to
`TRACEPARENT` when set, then one new trace per filesystem operation that reached
the API or Redis (`FUSE <op>`), with identifiers only. An operation answered from
memory exports nothing. A request refused by the API rate limit shows one call per
attempt, with an `api.throttle` event for each wait. No other command traces.

## Diagnosing: the access log

A hidden file shows the operations as they happen, by inode number (`ls -i`), never by
name; the last 4,096 are kept:

```sh
cat ~/dr/.retycfs/accesslog
# 2026-10-12T08:30:16.002113Z open ino=7 310µs ok
# 2026-10-12T08:30:16.004871Z read ino=7 off=0 len=131072 86.4ms ok
```

Use `cat` or `tail -n +1 -f` (plain `tail -f` shows nothing).

## Known limits

- The mount is visible to the user who made it only, unless `--allow-other`.
- A file being written cannot be mapped shared (`mmap MAP_SHARED`) on kernels older than
  6.6.
- Inode numbers are not stable across a kernel's forgetting them: tools that track files
  by inode between runs (`tar --listed-incremental`) may copy them again.
- File names the kernel cannot represent (over 255 bytes) are not listed.
- Requests refused by the API rate limit are retried for up to 30 seconds, then fail with
  an I/O error.

## Without a mount: WebDAV

On macOS or Windows, or wherever a mount is not possible, `retyc fs webdav serve`
exposes the same datarooms over WebDAV, with the same local encryption: see
[WebDAV server](webdav.md).
