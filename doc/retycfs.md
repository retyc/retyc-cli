# RetycFS

`retyc fs mount` mounts your datarooms as a local folder (Linux only; elsewhere use
[WebDAV](webdav.md)). Files are encrypted and decrypted locally: the Retyc servers never
see plaintext.

```sh
mkdir -p ~/dr
retyc fs mount retyc://<dataroom-id> ~/dr      # one dataroom, at the root of ~/dr
retyc fs mount --all ~/retyc                   # every dataroom, one folder each
```

The command stays in the foreground until unmounted. It needs:

- a login (`retyc auth login` or `RETYC_TOKEN`);
- the key passphrase: prompted, taken from the [key cache](configuration.md#key-cache-linux),
  or `RETYC_KEY_PASSPHRASE` (required for a service, ideally from an
  [environment file](configuration.md#environment-file));
- `/dev/fuse` and, unless run as root, `fusermount3` (package `fuse3`);
- an empty directory as mount point.

The mount is read-write; `--read-only` refuses every change, and so does a dataroom you
may only read. The `.deb` and `.rpm` packages ship example systemd units in
`/usr/share/doc/retyc/examples/systemd/`: [`system/`](../packaging/systemd/system/retyc-mount.service)
(server, machine account) and [`user/`](../packaging/systemd/user/retyc-mount.service)
(your own account).

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

A file being written is kept in a local temporary file (`--spool-dir`, mode 0600,
cleartext; size it for the largest files written at once) and sent, encrypted, **when it
is closed** or `fsync`ed:

- **the error of the upload is the error of `close`** (`No space left on device` when the
  dataroom or the spool is full, `Read-only file system` when the owner's plan is
  exceeded);
- a crash loses what was written since the last `close`;
- uploads go `api.concurrency.upload` at a time (4 by default).

## Freshness

Listings are cached for `cache.ttl` (one minute): a change made elsewhere is seen at most
that late. Opening a file checks its current version; a file already open keeps reading
the version it opened. File content is never cached on disk.

A listing in use is renewed in the background before it expires, so a folder used often
never makes a request wait for the API.

## Warmup

`--warmup` lists every folder in the background once mounted, so that an application
scanning its volume at startup is answered from the cache. `--warmup-depth=N` stops at N
levels (the dataroom root is the first).

- The mount is ready at once and does not wait for it.
- Only listings are warmed, never file contents, and they stay fresh for `cache.ttl` only:
  it pays off with a long `--cache-ttl` or a [shared Redis](#shared-metadata-cache-redis).
- The whole tree is held in memory while fresh (see [Memory](#memory)).
- A folder that cannot be listed is skipped. One line sums it up at the end:

  ```
  mount: listing cache warmed: 513 folders, 50000 files, 0 errors in 41.2s
  ```

## Local files

Files created through the mount whose name matches a `--local-file` glob are kept on this
machine, **never sent**, and gone at the unmount. Defaults: `.*.swp`, `.*.swx`, `*~`,
`4913`. Each source replaces the list; `none` empties it.

```sh
retyc fs mount --local-file '.*.swp' --local-file '*.tmp' retyc://<dataroom-id> ~/dr
```

Office lock files (`.~lock.*#`, `~$*`) are left out on purpose: they tell other people the
document is open.

## Locks

`--mirror-locks` takes an exclusive API lock on an existing file while it is open for
writing. A file locked by another Retyc client fails to open for writing with `EBUSY`. The
locks are advisory (the web application does not take them); those of a killed mount lapse
within five minutes.

## Deleting in the background

`--background-delete` makes `rm` return at once and deletes at the API afterwards. **A
successful `rm` then no longer proves the file is deleted**: other clients still see it
for a while, and a refused delete brings the file back in the mount.

## Unmounting

`Ctrl-C`, `SIGTERM`, or `fusermount3 -u <mountpoint>`. Files still being sent get
`--drain-timeout` (5 minutes); a second signal abandons them. Stop the programs that write
first: a file still open is sent as it is. In Kubernetes, keep
`terminationGracePeriodSeconds` above `--drain-timeout`.

A login revoked on the server unmounts at its next API request; a transient login failure (identity
provider down) keeps the mount up and is retried every minute.

Exit codes: `0` nothing lost, `75` writes lost (reported by identifiers), `77` login
expired, `78` missing or wrong passphrase, `1` anything else. Do not restart on 77 or 78;
see [Exit codes](commands.md#exit-codes).

## Containers

The image has no `fusermount3`: run it as root, with `/dev/fuse` and `SYS_ADMIN`, and
present the files to the workload's user with `--uid` / `--gid` / `--allow-other`. Put the
spool on a `tmpfs` or a volume.

```sh
docker run --rm --user 0 \
  --device /dev/fuse --cap-add SYS_ADMIN \
  -e RETYC_TOKEN -e RETYC_KEY_PASSPHRASE \
  --tmpfs /tmp \
  -v /mnt/dr:/mnt/dr:rshared \
  retyc/retyc-cli:latest fs mount retyc://<dataroom-id> /mnt/dr \
    --allow-other --uid 1000 --gid 1000
```

On Ubuntu add `--security-opt apparmor=unconfined`. To share the mount with another
container, use `rshared` / `Bidirectional` propagation.

## Shared metadata cache (Redis)

With `cache.store: redis`, several instances share their listings: one listing serves
them all, a change made through one is seen by the others at once, and a restart finds the
cache warm. File content is never stored there.

```yaml
cache:
  store: redis
  redis:
    url: rediss://:password@redis.example.com:6379/0   # a secret: use the env file
    high_confidentiality: false
```

- Redis 7.4 or later, standalone (no Cluster nor Sentinel).
- **By default Redis holds the decrypted file names.** Use a Redis you trust as much as
  the machines that mount, or `high_confidentiality: true` (names stored encrypted; about
  8× the Redis memory and 0.2 ms per name read).
- Set `maxmemory` and `allkeys-lru`: an evicted key only costs an API request. Instances
  sharing a Redis should share their `cache.*` settings.
- If Redis fails, the instance falls back on its own memory for a few minutes; no
  operation fails.

`scripts/redis-cache-dump.sh` (source repository) decodes a cache to JSON for diagnosis.

## Memory

A file the kernel holds (`stat`, open, `ls -l`) costs about 1.4 kB; a file only listed,
300 to 600 B. The process starts at about 30 MB; its RSS is about twice these figures.
Measured on 50,000 files in 513 folders:

| Walk                         | Cache in memory | Cache in Redis | Redis server (default / high confidentiality) |
|------------------------------|-----------------|----------------|-----------------------------------------------|
| names only (`find`)          | + 29 MB         | + 14 MB        | 11 MB / 96 MB                                 |
| with attributes (`ls -lR`)   | + 71 MB         | + 67 MB        | 11 MB / 96 MB                                 |
| names only, `--readdir-plus` | + 68 MB         | + 59 MB        | 11 MB / 96 MB                                 |

What nobody reads for about eleven `cache.ttl` is released.

## Options

Each flag has a key and a variable ([Configuration](configuration.md#settings)); the flag
wins.

| Flag                                 | Key                                         | Default                 |                                                                                         |
|--------------------------------------|---------------------------------------------|-------------------------|-----------------------------------------------------------------------------------------|
| `--read-only`                        | `mount.read_only`                           | `false`                 | Refuse every change                                                                     |
| `--cache-ttl`                        | `cache.ttl`                                 | `1m`                    | How long a listing is trusted                                                           |
| `--cache-negative-ttl`               | `cache.negative_ttl`                        | `1s`                    | How long a missing name is answered missing (`0`: off)                                  |
| `--cache-store`                      | `cache.store`                               | `memory`                | `memory` or `redis`                                                                     |
| `--cache-redis-url`                  | `cache.redis.url`                           | —                       | Prefer the variable: it holds the password                                              |
| `--cache-redis-high-confidentiality` | `cache.redis.high_confidentiality`          | `false`                 | Store names encrypted in Redis                                                          |
| `--entry-ttl`, `--attr-ttl`          | `mount.entry_ttl`, `mount.attr_ttl`         | `0` (`cache.ttl` / 2)   | How long the kernel keeps a name, and attributes                                        |
| `--kernel-cache`                     | `mount.kernel_cache`                        | `true`                  | Keep file content in the kernel between two opens                                       |
| `--readdir-plus`                     | `mount.readdir_plus`                        | `false`                 | Faster `ls -l`, more memory                                                             |
| `--spool-dir`                        | `mount.spool_dir`                           | system temp dir         | Files being written (cleartext, 0600)                                                   |
| `--allow-other`                      | `mount.allow_other`                         | `false`                 | Let other users in (needs `user_allow_other` in `/etc/fuse.conf` unless root)           |
| `--uid`, `--gid`                     | `mount.uid`, `mount.gid`                    | `-1` (the command's)    | Owner shown for every file                                                              |
| `--file-mode`, `--dir-mode`          | `mount.file_mode`, `mount.dir_mode`         | `0644`, `0755`          | Permissions when none is stored (quote them in YAML)                                    |
| `--drain-timeout`                    | `mount.drain_timeout`                       | `5m`                    | See [Unmounting](#unmounting)                                                           |
| `--mirror-locks`                     | `mount.mirror_locks`                        | `false`                 | See [Locks](#locks)                                                                     |
| `--background-delete`                | `mount.background_delete`                   | `false`                 | See [Deleting in the background](#deleting-in-the-background)                           |
| `--warmup`, `--warmup-depth`         | `mount.warmup`, `mount.warmup_depth`        | `false`, `0` (all)      | See [Warmup](#warmup)                                                                   |
| `--local-file pattern`               | `mount.local_files`                         | `.*.swp .*.swx *~ 4913` | See [Local files](#local-files)                                                         |
| `--unsafe-write`                     | `api.unsafe_write`                          | `false`                 | Faster `close`, [at a risk](configuration.md#acknowledge-uploads-before-they-are-stored) |
| `--metrics-addr`                     | `mount.metrics.addr`                        | — (off)                 | See [Metrics and probes](#metrics-and-probes)                                           |
| `--metrics-label key=value`          | `mount.metrics.labels`                      | —                       | Constant label on every metric; repeatable                                              |

## Metrics and probes

`--metrics-addr 127.0.0.1:9090` starts an unauthenticated listener:

| Path       | Response                                                                     |
|------------|------------------------------------------------------------------------------|
| `/metrics` | Prometheus metrics, `go_*` and `process_*` included                          |
| `/healthz` | `200` while the process answers                                              |
| `/readyz`  | `200` once mounted; `503` before, and as soon as the mount starts to stop    |

`--metrics-label key=value` tells several mounts apart; a reserved or already used label
name stops the mount at startup. Labels never carry an identifier, a name or a path. All
metrics start with `retycfs_` (full list with `HELP` on `/metrics`); the main ones:

| Metric                                               | Meaning                                                  |
|------------------------------------------------------|----------------------------------------------------------|
| `retycfs_ops_total{op,result}`                       | Filesystem operations, by result (`ok`, `ENOENT`, `EIO`…) |
| `retycfs_op_duration_seconds{op}`                    | Duration of an operation                                 |
| `retycfs_api_requests_total{method,route,status}`    | Calls to the Retyc API (`status="error"`: no response)   |
| `retycfs_api_request_duration_seconds{method,route}` | API round-trip latency                                   |
| `retycfs_api_rate_limited_total{method}`             | API requests given up on `429`                           |
| `retycfs_uploads_total{result}`                      | Files sent to the API                                    |
| `retycfs_spool_bytes`                                | Bytes held in the spool directory                        |
| `retycfs_cache_lookups_total{result}`                | Listing cache efficiency (`hit`, `stale`, `miss`)        |
| `retycfs_warmup_folders_total{result}`               | Folders listed by the warmup (`ok`, `error`)             |
| `retycfs_warmup_duration_seconds`                    | Duration of the warmup, set when it ends                 |
| `retycfs_token_expiry_seconds`                       | Seconds left on the access token, 0 when unknown         |

### Traces

With an OTLP endpoint set ([Tracing](configuration.md#tracing-opentelemetry)), the mount
exports one startup span (`retyc fs mount init`, child of `TRACEPARENT` when set), then
one trace per filesystem operation that reached the API or Redis (`FUSE <op>`), with
identifiers only.

## Diagnosing: the access log

A hidden file shows the last 4,096 operations, by inode number (`ls -i`), never by name:

```sh
cat ~/dr/.retycfs/accesslog        # or tail -n +1 -f (plain tail -f shows nothing)
# 2026-10-12T08:30:16.002113Z open ino=7 310µs ok
# 2026-10-12T08:30:16.004871Z read ino=7 off=0 len=131072 86.4ms ok
```

## Known limits

- Only the user who mounted sees the mount, unless `--allow-other`.
- A file being written cannot be mapped shared (`mmap MAP_SHARED`) before Linux 6.6.
- Inode numbers are not stable over time: `tar --listed-incremental` may copy files again.
- File names over 255 bytes are not listed.
- Requests refused by the API rate limit are retried for up to 30 seconds, then fail with
  an I/O error.
