# RetycFS

RetycFS mounts your datarooms as a local folder. Any program reads and writes them like
local files: `ls`, `cat`, `grep`, `cp`, a file manager or an editor. Files are encrypted
and decrypted **locally**, end to end; the Retyc servers never see plaintext. RetycFS
runs on Linux, through `retyc fs mount`.

The mount is read-write. `retyc fs mount --read-only ...` mounts it read-only: every
change (`cp` into it, `rm`, `mv`, `chmod`, `touch`) then answers `Read-only file system`.

A dataroom you may only read (you are a *viewer* of it, or the plan of its owner
refuses writes) is read-only whatever the option: mounted alone, the mount is made
read-only and the message printed at mount time says why; with `--all`, its folder
answers `Read-only file system` to every change while the other datarooms stay
writable. This is checked once, at mount time or when the dataroom is first entered:
after a change of role, mount again. If the check itself fails (the API cannot be
reached), the dataroom can be read, its writes are refused, and the check is made
again at the next access.

Linux only. On other platforms the command answers that it is not available; see
[Without a mount: WebDAV](#without-a-mount-webdav).

## Quick start

```sh
# The key passphrase is required (never prompted)
read -rs RETYC_KEY_PASSPHRASE
export RETYC_KEY_PASSPHRASE

mkdir -p ~/dr
retyc fs mount retyc://<dataroom-id> ~/dr      # the dataroom is the root of ~/dr
```

The command stays in the foreground. From another terminal:

```sh
ls -l ~/dr
cat ~/dr/report.pdf > /tmp/report.pdf
```

To mount every dataroom you can reach, one folder each:

```sh
retyc fs mount --all ~/retyc
ls ~/retyc
# Project Alpha   Finance   Finance (2)
```

Datarooms that share a title get a suffix.
A `/` in a title is shown as `_`.

## Features

| Feature                                             |    | Notes                                                                                                                                  |
|-----------------------------------------------------|:--:|----------------------------------------------------------------------------------------------------------------------------------------|
| Read and write files                                | ✅  | Any program; a file is sent as a new version when it is closed ([Writing](#writing))                                                   |
| Version history                                     | ✅  | Saving an existing file adds a version of it, when the dataroom keeps versions (the default, see `retyc dataroom create --versioning`) |
| Folders (`mkdir`, `rmdir`, `rm -r`)                 | ✅  |                                                                                                                                        |
| Rename and move (`mv`)                              | ✅  | `mv` over a file replaces it in one step, for everybody                                                                                |
| Server-side copy (`cp`)                             | ✅  | A whole file into a new one, same dataroom: nothing downloaded nor uploaded                                                            |
| Symbolic links (`ln -s`)                            | ✅  | Target stored encrypted, as given                                                                                                      |
| File modes (`chmod`)                                | ✅  | Stored per file, `0000` included; ignored on folders                                                                                   |
| Modification times (`touch -d`, `cp -p`)            | ✅  |                                                                                                                                        |
| Read-only datarooms                                 | ✅  | `--read-only`, or automatic for a viewer or a plan that refuses writes                                                                 |
| Every dataroom in one mount (`--all`)               | ✅  | One folder per dataroom                                                                                                                |
| Free space (`df`)                                   | ✅  | The dataroom's storage                                                                                                                 |
| Node identifiers as extended attributes             | ✅  | `user.retyc.*`, read-only ([What you see](#what-you-see))                                                                              |
| Editor swap and backup files kept local             | ✅  | Never sent ([Local files](#local-files))                                                                                               |
| API locks while a file is written                   | ✅  | Optional, `--mirror-locks` ([Locks](#locks))                                                                                           |
| Removal answered at once, deleted in the background | ✅  | Optional, `--background-delete`                                                                                                        |
| Metadata cache shared by several instances          | ✅  | Redis ([Shared metadata cache](#shared-metadata-cache-redis))                                                                          |
| Metrics, health probes, traces                      | ✅  | `--metrics-addr`, OpenTelemetry                                                                                                        |
| Containers                                          | ✅  | [Containers](#containers)                                                                                                              |
| Hard links, special files (`mknod`, FIFOs)          | ❌  | `Operation not permitted`                                                                                                              |
| Writing extended attributes                         | ❌  | `Operation not supported`                                                                                                              |
| Owner (`chown`), access times                       | ❌  | Accepted and ignored: files show the owner the mount presents (`--uid` / `--gid`, by default the user who mounted)                     |
| `mv` between two datarooms                          | ⚠️ | Copy then delete, like between two disks                                                                                               |
| Partial upload of a change                          | ❌  | A change to a large file sends the whole file again                                                                                    |
| macOS, Windows                                      | ❌  | Linux only; elsewhere, [WebDAV](#without-a-mount-webdav)                                                                               |

Other limits are listed under [Known limits](#known-limits).

## Requirements

- You must be authenticated first: `retyc auth login`.
- `RETYC_KEY_PASSPHRASE` must be set, in the environment or in an environment file
  (`retyc --env-file /etc/retyc/env fs mount …`, or `RETYC_ENV_FILE`): the way to mount at
  boot or from a systemd unit, see
  [Configuration](configuration.md#keep-the-secrets-in-an-environment-file-boot-mounts-systemd-csi).
- `/dev/fuse` must exist (kernel module `fuse`).
- Unless you run as root, the `fusermount3` helper: package `fuse3` on Debian, Ubuntu,
  Fedora and Arch. As root the CLI mounts with `mount(2)` and needs no helper.
- The mount point must exist, be a directory and be empty.
- The API must be recent enough (lookup by name). Against an older one the command
  refuses to start.

## Unmounting

Any of:

- `Ctrl-C`, or `SIGTERM` to the process;
- `fusermount3 -u <mountpoint>` (or `umount <mountpoint>` as root) from another
  terminal: the command then exits cleanly, with code 0.

A mount point that is still in use when the command is stopped (a shell whose current
directory is inside, a file open) is retried for five seconds, then detached: it leaves
the directory tree at once, and the programs still using it get `Transport endpoint is
not connected`.

### What happens to the files being written

When the command is stopped, what is on its way to the API gets `--drain-timeout`
(`mount.drain_timeout`, 5 minutes by default), counted from the signal. It is a
maximum, not a wait: the command ends as soon as everything is sent, at once when
nothing is pending. When something is, it says so on its error output, then once more
at the end:

```
mount: stopping: 120 files still to send to the API, waiting for them up to 5m0s (drain timeout); a second signal abandons them
mount: drain over after 2.1s: everything was sent
```

A mount sends `api.concurrency.upload` files at once (see [Writing](#writing)): about
50 small files a second with the default of 4 on a local API, so thousands of files
written just before the stop take a minute or more.

- a file being sent (its `close` or `fsync` is in progress, or it was just closed) is
  waited for;
- a file a program still holds open is sent **as it is at that moment**, which may be
  half of what the program meant to write: the command says so, once per file (`a file
  was sent as it was at shutdown`);
- past the delay, the uploads still in progress are cancelled and what they held is
  **lost**. The command reports each file on its error output, by identifiers and never
  by name, and unmounts all the same:

  ```
  the last flush of a file failed, its changes are lost: dataroom <id>, node <id>, inode <n>, <size> bytes: <reason>
  the last flush of a file failed, its changes are lost: dataroom <id>, no node (never stored), parent <id>, inode <n>, <size> bytes: <reason>
  ```

  The second form is a file that was created through the mount and never reached the
  API: it has no node, so the line gives the folder it was created in (`parent root` at
  the root of the dataroom, `parent unknown` when its folder is not known any more).
  `<size>` is the size of the file as it was written
  locally. What a cancelled upload had already created on the API is removed, and
  reported the same way (`cleaned up orphaned node: dataroom <id>, node <id>`, or
  `discarded the failed version: dataroom <id>, node <id>, version <id>`).

With `--background-delete`, the deletes not sent yet are waited for the same way, and
reported when they are not (see [Deleting in the background](#deleting-in-the-background)).

A second `Ctrl-C` (or `SIGTERM`) during that wait ends it at once, with the same report.
`--drain-timeout 0` waits for nothing. Size the delay on your largest files and your
uplink; in Kubernetes, keep `terminationGracePeriodSeconds` above it. Writes are not
refused during the wait: a program that keeps writing is part of what is sent, or lost.

### Exit codes

Those of the other long-running commands: `77` when the login expired and cannot be
renewed (run `retyc auth login`), `78` for a missing or wrong key passphrase, `1`
otherwise; and `75` for writes lost at the unmount, below. A supervisor should not restart on `77` or `78`.

`0` means the filesystem was unmounted and nothing was lost, whoever unmounted it
(a signal, `fusermount3 -u`). When files being written could not be sent before the
filesystem went away (the drain timed out or was cut short, the API refused them),
the command exits with `75` and an error that gives their number; each one is
reported on stderr by its dataroom and node IDs, never by name. A login lost at the
same time keeps `77`. `1` is any other failure, a failure to start included (Redis
unreachable, a mount point that is not usable): with `--json` the error's `kind`
is `lost_writes` for `75` (see [Errors in JSON](commands.md#errors-in-json)).

Only a login that is lost for good unmounts: no refresh token, or one the identity
provider refuses. A check of the login that fails for another reason (the identity
provider unreachable, answering a 5xx, timing out) is reported once on stderr and
tried again every minute; the filesystem stays mounted and `/readyz` keeps
answering `200`. Requests to the API fail meanwhile if the access token has expired.

The login is checked every minute, and at once when the API refuses a request of the
mount as unauthenticated (401): a login revoked on the server stops the mount within
seconds, not at the next check. The filesystem is unmounted first, as on a signal.

## Containers

- Give the container the device and the capability: `--device /dev/fuse
  --cap-add SYS_ADMIN` (under Docker on Ubuntu also `--security-opt
  apparmor=unconfined`). In Kubernetes, a privileged container or a device plugin
  that provides `/dev/fuse`.
- The published image is built from `scratch`, has no `fusermount3` and runs as a
  non-root user: run it as root (`--user 0`) so that it mounts with `mount(2)`, which
  needs `CAP_SYS_ADMIN` and no helper. The image's default user is unchanged: every
  other command keeps running unprivileged.
- As root, the files are presented as owned by root: give `--uid` / `--gid` the user of
  the workload, and `--allow-other` so that it may enter the mount (root needs no
  `user_allow_other` in `/etc/fuse.conf`).
- A file being written is kept in the spool directory, `/tmp` by default, which the
  image provides (empty, mode 1777). It is in the container's writable layer: mount a
  volume or a `tmpfs` there, or point `--spool-dir` at one, sized for the largest file
  written. A read-only root filesystem needs one.

```sh
docker run --rm --user 0 \
  --device /dev/fuse --cap-add SYS_ADMIN \
  -e RETYC_TOKEN -e RETYC_KEY_PASSPHRASE \
  --tmpfs /tmp \
  -v /mnt/dr:/mnt/dr:rshared \
  retyc/retyc-cli:latest fs mount retyc://<dataroom-id> /mnt/dr \
    --allow-other --uid 1000 --gid 1000
```

- To use the mount from another container, share the mount point with mount propagation
  (`rshared` / `Bidirectional`).

## What you see

|                   |                                                                                                           |
|-------------------|-----------------------------------------------------------------------------------------------------------|
| Size              | the plaintext size of the current version                                                                 |
| Dates             | the modification time the uploader declared, else the upload time; a folder's creation time               |
| Mode              | the mode stored with the file, `0000` included, or `0644` (files) and `0755` (folders) when there is none |
| Owner             | `--uid` / `--gid`, by default the user who runs `retyc fs mount`                                          |
| Symbolic links    | shown as links (`ls -l`, `readlink`); the kernel follows them, the target is never checked                |
| Free space (`df`) | the dataroom's storage quota; a large constant at the root of `--all`                                     |

Extended attributes give the identifiers the API and the web application know a file by:

```sh
getfattr -d ~/dr/report.pdf
# user.retyc.dataroom_id="019d3de3-…"
# user.retyc.mime="application/pdf"
# user.retyc.node_id="019d4a11-…"
# user.retyc.version_id="019d4a12-…"
```

## Writing

The API stores a file as whole versions, each announced with its size: it cannot be
written piece by piece. A file opened for writing is therefore kept in a **temporary
local file** (the *spool*: mode `0600`, in the system's temporary directory, under a name
that says nothing of the file, removed when the file is closed), and sent, encrypted,
as **one new version**:

- when a program closes it (`close`), or calls `fsync`. **The error of the upload is
  the error of `close`**: `No space left on device` when the dataroom, or the temporary
  directory, has no room left; `Permission denied` when you may only read the dataroom;
  `Read-only file system` (`EROFS`) when your role allows the write but the API answers
  that the dataroom is read-only because its owner's plan is exceeded (the error code
  `DATAROOM_READ_ONLY`, on every change: a write, `mkdir`, `rm`, `mv`, `chmod`, `touch`, `truncate`, `ln -s`).
  A program that ignores what `close` returns does not see it; the last close then
  leaves a line in the output of `retyc fs mount`;
- a file that was only created, or emptied by its opening (`O_TRUNC`), and that nothing
  was written to since, is not sent by `close`: it is sent once its last descriptor is
  closed. A shell redirection (`echo text > file`) closes a copy of the descriptor
  before it writes, and would otherwise store an empty version, then the text. The
  empty file of `touch file` or `: > file` is therefore created just after `close`
  returned, and **the error of that upload is not the error of `close`**: it is
  reported as a loss in the output of `retyc fs mount`, by the identifiers of the
  dataroom and of the node, never by the name. `fsync` sends such a file at once and
  reports its error;
- nothing is sent before: a crash of the CLI, or of the machine, loses what was written
  since the last `close` or `fsync`.
- the mount sends `api.concurrency.upload` files at once (4 by default), all files
  together: the others wait for their turn, in `close` or after it. Creating thousands
  of empty files with `touch` returns at once, and their uploads then go out four at a
  time; unmounting before they are sent leaves the rest to `--drain-timeout` (see
  [What happens to the files being written](#what-happens-to-the-files-being-written)).

What this means in practice:

|                                                                           | Requests                                              |
|---------------------------------------------------------------------------|-------------------------------------------------------|
| Create a file of at most 8 MiB (`echo > f`, `touch f`), whatever its mode | 1                                                     |
| Create a larger file                                                      | 2 + one per 8 MiB started                             |
| `cp a b` within a dataroom, `b` being new                                 | 1, nothing downloaded or uploaded                     |
| `ln -s target link`                                                       | 1                                                     |
| Overwrite a file (`>`), small / large                                     | 1 / 1 + one per 8 MiB                                 |
| Append to a file, or change it in place                                   | its download, then as above                           |
| `truncate -s 0`                                                           | 1                                                     |
| `truncate` to another size                                                | the download of what is kept, then as above           |
| `mkdir`, `rm`, `mv`, `chmod`, `touch` of an existing file                 | 1                                                     |
| `rmdir`                                                                   | 2 (the folder is listed first: `Directory not empty`) |

- **Changing one byte of a large file downloads it and uploads it again**, whole. The
  mount suits documents, not databases or disk images.
- A file created and not closed yet is visible in its folder, with its current size,
  on this mount only: other users see it once it is closed.
- Every program that has the file open while it is written reads and writes the same
  content. A program that had it open *before* keeps reading the version it opened.
- Only the programs that opened the file for writing send it when they `close` it (or
  `fsync`): reading a file another program is half-way through writing (`cat`, a
  backup) stores nothing.
- **`cp` of a file into a new one, in the same dataroom, is a copy made by the
  servers**: one request, whatever the size (up to 4 GiB), nothing downloaded and
  nothing uploaded. It needs a `cp` that uses `copy_file_range` (coreutils 9 and
  later; `--reflink=auto` is the default). The copy keeps the modification time of
  its source. Every other copy goes through reads and writes, as before: `cp` over a
  file that exists (it gets a new version and keeps its history), a copy between
  two datarooms, a part of a file, a source that is being written.
- `mv` over an existing file replaces it in one step, for everybody. The pattern editors
  use (write `f.tmp`, `fsync`, rename over `f`) works, and costs two requests.
- `rm` of a file that is open: programs keep reading and writing their copy, nothing
  of it is stored any more.
- `mv` between two datarooms (`--all`) copies then deletes, like between two disks.
- `chmod` is stored for files; a file gets the mode it is created with in the request
  that creates it. The mode of a folder, `chown` and access times are accepted and
  ignored.
- Symbolic links can be created (`ln -s`), read, renamed and removed. The target is
  stored encrypted, as it is given: relative or absolute, existing or not. It is
  resolved on the machine that follows the link, so an absolute target, or one that
  leaves the dataroom, means something else on another machine. Hard links and special files (`mknod`,
  FIFOs) cannot be created: `Operation not permitted`.
- At the root of `--all`, nothing can be created, renamed or removed: a dataroom is
  created with `retyc dataroom create`.
- When the mount is stopped while a file is still open, what that file holds is sent
  before the command exits, as a complete version: a program that was halfway through
  writing it leaves half a file, and nothing marks it as such. The command says so on
  its error output for each such file (dataroom, node and inode, never the name), and
  says which files could not be sent at all. Stop the programs that write before the
  mount.
- Creating a file that must not exist yet (`O_EXCL`: `cp` of a new file, `mktemp`, lock
  files) asks the server whether the name is taken, one light request per file, so a
  file created by somebody else a moment ago is not overwritten. A file created
  elsewhere between that check and the moment yours is closed still is: it gets your
  content as a new version, and keeps its history.
- Renaming a file while it is being uploaded (it was just closed, or `fsync` is
  running) waits for that upload to end.

## Local files

Editors create files next to the one they edit, for themselves alone: vim keeps a swap
file (`.name.swp`) that it writes and syncs for as long as the file is open, probes
the folder with a file called `4913` and makes a backup (`name~`) before it saves.
Sent to the dataroom, each of them would be an upload, one version per `fsync` and a
request to delete it, for a file nobody else is meant to see.

A file **created through the mount** under a name that matches one of the patterns of
`--local-file` is therefore a *local file*:

- it is kept in the spool directory of this machine (mode 0600, cleartext) and **never
  sent**: it is visible **on this mount only**, absent from the dataroom, from the
  other clients and from another mount of the same dataroom, and takes no version, no
  quota and no lock;
- it is listed in its folder, read, written, truncated, `chmod`ed and removed like any
  other file, at no request to the server, and it stays there after it is closed;
- it is **gone when the filesystem is unmounted** or the command stops, whether it was
  still open or not. Nothing is reported for it: it is not one of the files "lost" at
  shutdown, and does not change the exit code.

Do not keep anything there that you want to find again: a backup `report.odt~` an
editor leaves behind exists until the unmount, no longer.

The default patterns are `.*.swp`, `.*.swx` (vim swap files), `*~` (backup files of
vim, Emacs, gedit and others) and `4913` (vim's probe). A pattern is a glob on the
**name** of the file, not its path, in the syntax of Go's
[`path.Match`](https://pkg.go.dev/path#Match): `*`, `?`, `[a-z]`, `\` to escape; a
malformed pattern, or one that holds a `/`, is refused when the command starts.

```sh
# Replace the list (the flag is repeatable)
retyc fs mount --local-file '.*.swp' --local-file '*.tmp' retyc://<dataroom-id> ~/dr

# No local file at all: every file is sent
retyc fs mount --local-file none retyc://<dataroom-id> ~/dr
```

```yaml
mount:
  local_files: [ ".*.swp", ".*.swx", "*~", "4913", "*.tmp" ]
  # local_files: []        # none
```

`RETYC_MOUNT_LOCAL_FILES` takes the patterns separated by spaces (so none with a space
in it). Each source replaces the list of the one below it, it does not add to it. The
word `none` alone empties the list from any of the three; an empty list in the
configuration file and `--local-file ''` do too. To match a file that is really called
`none`, write `[n]one`.

The lock files of office suites (`.~lock.report.odt#` for LibreOffice, `~$report.docx`
for Microsoft Office) are **not** in the default list, on purpose: they are how two
people working in one dataroom learn that the other has the document open. Kept local,
each would open the document believing to be alone. Add them only on a dataroom you
are the only one to write to.

What to expect:

- A file the dataroom **already holds** under such a name (somebody uploaded a
  `notes~`) is a file like any other: read, written and removed on the server. Only
  the files created here are local.
- A name that matches is looked for in the listing of its folder, the one `ls` reads
  and the cache keeps, never by a request of its own: the many probes of an editor
  cost nothing once the folder is listed. A file created elsewhere under such a name
  shows up here when that listing is next refreshed (`--cache-ttl`), and stays hidden
  behind a local file of the same name for as long as that one exists.
- **Renaming** a local file to a name that matches no pattern makes it a file of the
  dataroom: it is sent when the program that writes it closes it, or by the rename
  itself when no program has it open for writing, in which case `mv` fails with the
  error of the upload and the file stays local under its old name. Renamed over a file
  of the dataroom, it becomes a new version of that file, whatever its new name.
  Renamed to another name that matches, it stays local. A file of the dataroom renamed
  to a name that matches (`mv report.txt report.txt~`) stays a file of the dataroom,
  renamed on the server; it replaces a local file of that name.
- A folder that holds local files is **not empty**: `rmdir` answers `Directory not
  empty` although the dataroom shows it empty everywhere else. Remove the local files
  first (`rm -r` does).
- `cp` into a local file copies the bytes: there is no server-side copy for a file the
  server never holds.
- There is no local file on a read-only mount, nor in a dataroom you may only read:
  creating one fails with `Read-only file system` like any other file.

## Freshness

Folder listings are cached for one minute. A file changed by
someone else is therefore seen at most a minute late (`cache.ttl`, see below):

- opening a file always checks which version is current, against that cache: an `open`
  never returns a version older than a minute;
- a file that is already open keeps reading the version it opened, to its end;
- a file deleted or renamed elsewhere disappears the next time its folder is listed, or
  when its cached entry expires.

The durations are those of the `cache:` section of the
[configuration](configuration.md#settings), shared by the commands that present
datarooms as files:

| Flag                   | Key, variable                                    | Default |                                                                                                                                                                     |
|------------------------|--------------------------------------------------|---------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--cache-ttl`          | `cache.ttl`, `RETYC_CACHE_TTL`                   | `1m`    | How long a listing, and a file or folder looked up by name, is trusted. Also how long the kernel keeps a name and its attributes without asking again.              |
| `--cache-negative-ttl` | `cache.negative_ttl`, `RETYC_CACHE_NEGATIVE_TTL` | `1s`    | How long a name found missing is answered missing, by the filesystem and by the kernel: a file created elsewhere shows up at most that much later. `0` disables it. |

`cache.max_stale` **does not apply to a mount**, and `fs mount` has no
`--cache-max-stale`: a mount never serves an expired listing while it refreshes it, so
that an `open` cannot return a version older than `cache.ttl`. The key may be set in
the configuration file, it is ignored here.

Reading a file twice downloads it once: the kernel keeps what it read in its page
cache, and drops it when the file gets a new version. Nothing is cached on disk.

### Memory used by the local cache

By default (`cache.store: memory`) the listings live in the memory of the
`retyc fs mount` process. Measured on the same trees as
[in Redis](#memory-used-in-redis): one mount walked a tree of empty files, 99 entries
per folder at most, every folder listed once, with `cache.ttl` long enough for nothing
to expire. Live Go heap after a garbage collection, and resident memory of the
process, compared with the same mount before the walk:

| Files  | Folders | Heap     | Resident memory |
|--------|---------|----------|-----------------|
| 1,000  | 12      | + 2.9 MB | + 8 MB          |
| 10,000 | 105     | + 18 MB  | + 40 MB         |
| 50,000 | 513     | + 85 MB  | + 170 MB        |

That is about 1.7 kB of heap per file once the tree is large, names decrypted. It
counts what the mount keeps besides the listings for as long as the kernel holds the
names (`cache.ttl`): one inode per file. The resident memory is about twice the heap,
the margin the Go runtime keeps before its next collection. A mounted process that has
walked nothing holds about 30 MB.

Like Redis, the local cache **lets go of a folder nobody read for `cache.ttl` +
`cache.max_stale` + ten `cache.ttl`** (eleven `cache.ttl` for a mount, which serves no
stale listing): an expired listing is still of use within that window (a name looked up
in the folder refreshes it with one request instead of one lookup per name, and the
refresh is conditional, so while the dataroom has not changed its names are not
decrypted again), not after. A name looked up on its own is kept for `cache.ttl`, a name
found missing for `cache.negative_ttl`. What has outlived its lifetime is never served,
and is removed by a sweep that runs at most every quarter of that window, on the next
access to the cache. The memory is therefore bounded by the folders read within that
window, not by every folder read since the mount started: a folder deleted or renamed
elsewhere, which nobody reads again, leaves with the rest. A mount that walks the whole
tree (a backup, an indexer) still holds all of it while it walks; size it on the table
above. The inodes go once the kernel forgets them.

## Shared metadata cache (Redis)

By default each instance keeps its listings, and the names it looked up, in its own
memory. With `cache.store: redis` they are kept in a Redis that several instances of
the CLI share:

- a folder one instance listed is served to the others without a request to the API;
- a file one instance creates, renames or removes is seen by the others at once, not
  when their own listing expires. A change made by a client that does not use this
  Redis (the web application, another machine) is still seen after `cache.ttl` at most;
- an instance that restarts finds the cache as the others left it.

Only metadata goes there. File content is never cached, and the list of your
datarooms stays in the memory of each instance.

```yaml
cache:
  store: redis
  redis:
    url: rediss://:password@redis.example.com:6379/0
    high_confidentiality: false
```

| Flag                                 | Key, variable                                                                | Default  |                                                                                                          |
|--------------------------------------|------------------------------------------------------------------------------|----------|----------------------------------------------------------------------------------------------------------|
| `--cache-store`                      | `cache.store`, `RETYC_CACHE_STORE`                                           | `memory` | `memory` or `redis`.                                                                                     |
| `--cache-redis-url`                  | `cache.redis.url`, `RETYC_CACHE_REDIS_URL`                                   | —        | `redis://` or `rediss://` (TLS) URL, user, password and database number included. Required with `redis`. |
| `--cache-redis-high-confidentiality` | `cache.redis.high_confidentiality`, `RETYC_CACHE_REDIS_HIGH_CONFIDENTIALITY` | `false`  | See below.                                                                                               |

The URL holds the password, so it is a secret: `retyc config show` masks it, and it is
never printed by `--debug`, an error, a trace or a metric. Prefer the variable (in an
[environment file](configuration.md#keep-the-secrets-in-an-environment-file-boot-mounts-systemd-csi))
to the flag, which every user of the machine reads in the process list.

**Requirements.** A standalone Redis 7.4 or later (the cache relies on a lifetime per
hash field). Redis Cluster and Sentinel are not supported yet. The server is checked
before anything is mounted: one that does not answer, or is too old, fails the start.
For a local test, `scripts/start-redis.sh` starts one in Docker.

**What Redis holds.**

- By default, what an instance holds in memory: the **decrypted** names of files and
  folders, link targets and MIME types, with identifiers, sizes, dates and modes.
  Whoever reads that Redis reads the names in your datarooms, which the RETYC servers
  never see. Use it only with a Redis you trust as much as the machines that mount:
  `rediss://`, a password, no other tenant.
- With `cache.redis.high_confidentiality: true`, the instance stores the names as the
  API sent them, encrypted for the key of the dataroom, and decrypts them when it
  reads: Redis then holds nothing more than the API does. Only the text wrapping of
  each encrypted name (its ASCII armor) is taken off before it is stored, to save
  space: the encrypted bytes are the API's, the instance encrypts nothing itself. The price is one decryption
  per name read from Redis, about 0.2 ms of CPU each, once per instance (it remembers what it
  decrypted). Decryption never holds the rest of the filesystem: a large folder read
  sealed for the first time delays the operation that reads it, not the others.

The setting decides what an instance **writes**. Every instance reads both forms,
whatever its own setting, so instances may be switched one at a time; a Redis is only
free of decrypted names once every instance that writes to it has the setting, and
what was written before has expired.

In both modes no name appears in a key: a key holds the identifier of the dataroom
and a hash of the folder's path, salted with a secret of the dataroom, and the names
looked up one by one are hashed the same way.

The values are stored in a compact binary format, not as text: `redis-cli` shows them
as escaped bytes. To read a cache, run the diagnostic tool of the source repository,
which decodes every key to JSON and only reads (it decrypts nothing: with
`high_confidentiality` a name is shown as the size of its encrypted form):

```bash
REDIS_URL=redis://localhost:6379/0 scripts/redis-cache-dump.sh [-prefix retyc] [-dataroom <id>] [-kind ls|e|g|tl|te]
```

**Lifetimes.** Redis expires everything itself: a listing after `cache.ttl` plus the
time it may still be revalidated (and `cache.max_stale` where it applies), a name
looked up after `cache.ttl`, a missing name after `cache.negative_ttl`. Nothing has to
be purged, and the instances need not agree on the time: Redis is the only clock.
Instances that share a Redis should share their `cache.*` durations.

**Memory.** This is a cache, and losing a key only costs a request to the API: give
Redis a `maxmemory` and the `allkeys-lru` policy. That policy is safe, whatever key
Redis evicts: every value records random tokens of the folders above it, read back in
the same request, and a missing token or generation always means "invalid", never
"unchanged", so an eviction can cost a miss but never serve a stale listing nor let an
older answer of the API overwrite a newer change. Do not combine `noeviction` with a
`maxmemory` that is too tight: writes are then refused, and the instances fall back
on their own memory.

**When Redis fails.** At the first read or write that fails, the instance sets Redis
aside and goes on with a cache in its own memory, empty at first, for `cache.ttl` +
`cache.max_stale`: the time after which nothing it could not invalidate in Redis is
served as current. It then uses Redis again, and sets it aside again if it still
fails. One line tells each change, not each failure:

```
mount: listing cache: the store failed and is set aside for an in-memory one for 6m0s: …
mount: listing cache: back on the configured store
```

Nothing is lost and no operation fails; the instance does not share what it learns
meanwhile, and only the operation that meets the failure waits for Redis.

**Observing it.** Every round trip to Redis is timed in
`retyc_cli_vfs_store_op_duration_seconds{op,result}` (see [Metrics](#metrics-and-probes)).
With tracing on, each one made for a traced operation is a `redis <operation>` span
under it (`redis get_node`, `redis put_listing`, …) carrying the operation, the dataroom
ID and, for a listing, its number of entries: never a Redis key, a name, a path, a
value or the URL, and of a failure only the type of the error. Since an operation of
the mount is exported when something happened under it, one that Redis answered now
leaves a trace, where the in-memory cache leaves none.

### Memory used in Redis

Measured on Redis 8.10 (`used_memory`, the server flushed before each run), after one
mount walked a tree of empty files, 99 entries per folder at most, every folder
listed once:

| Files  | Folders | Default | `high_confidentiality` |
|--------|---------|---------|------------------------|
| 1,000  | 12      | 0.3 MB  | 2.0 MB                 |
| 10,000 | 105     | 2.2 MB  | 19 MB                  |
| 50,000 | 513     | 11 MB   | 96 MB                  |

That is about 220 bytes per file by default and 1.9 kB with `high_confidentiality`,
where each file keeps its name as the API holds it, a post-quantum AGE payload of
about 1.7 kB whatever the length of the name. The names of this tree are three
characters long: by default, count one byte more per character of a longer name.
Each folder adds two tokens and a generation, a few hundred bytes, whatever the
number of its files. Only what was listed or looked up is held, and for `cache.ttl` +
`cache.max_stale` + ten more `cache.ttl` at most: a folder nobody reads leaves Redis by
itself.

## Options

Every flag has a configuration key and an environment variable; the flag wins, then
the variable, then the [configuration file](configuration.md#settings).

| Flag                        | Key, variable                                                                        | Default                          |                                                                                                                                                                                                                                                                                                                                  |
|-----------------------------|--------------------------------------------------------------------------------------|----------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--read-only`               | `mount.read_only`, `RETYC_MOUNT_READ_ONLY`                                           | `false`                          | Refuse every change.                                                                                                                                                                                                                                                                                                             |
| `--entry-ttl`               | `mount.entry_ttl`, `RETYC_MOUNT_ENTRY_TTL`                                           | `0` (= `cache.ttl`)              | How long the kernel keeps a name without asking the filesystem again.                                                                                                                                                                                                                                                            |
| `--attr-ttl`                | `mount.attr_ttl`, `RETYC_MOUNT_ATTR_TTL`                                             | `0` (= `cache.ttl`)              | The same for the size, dates and mode of a file.                                                                                                                                                                                                                                                                                 |
| `--kernel-cache`            | `mount.kernel_cache`, `RETYC_MOUNT_KERNEL_CACHE`                                     | `true`                           | The kernel keeps what it read of a file between two opens of the same version. `false`: every open reads from the API again.                                                                                                                                                                                                     |
| `--spool-dir`               | `mount.spool_dir`, `RETYC_MOUNT_SPOOL_DIR`                                           | the system's temporary directory | Where a file being written is kept (mode 0600, cleartext) until it is sent. It must exist and be writable, which is checked before mounting; it has no size limit of its own: a full disk fails the write with `No space left on device`.                                                                                        |
| `--allow-other`             | `mount.allow_other`, `RETYC_MOUNT_ALLOW_OTHER`                                       | `false`                          | Let the other users of the machine into the mount; the owner and modes presented then decide. Unless run as root, it needs `user_allow_other` in `/etc/fuse.conf`.                                                                                                                                                               |
| `--uid`, `--gid`            | `mount.uid`, `mount.gid`, `RETYC_MOUNT_UID`, `RETYC_MOUNT_GID`                       | `-1` (those of the command)      | The owner every file and folder is presented with.                                                                                                                                                                                                                                                                               |
| `--file-mode`, `--dir-mode` | `mount.file_mode`, `mount.dir_mode`, `RETYC_MOUNT_FILE_MODE`, `RETYC_MOUNT_DIR_MODE` | `0644`, `0755`                   | The permissions of a file or folder that has none stored (octal). In the configuration file, quote them: `file_mode: "0640"`.                                                                                                                                                                                                    |
| `--drain-timeout`           | `mount.drain_timeout`, `RETYC_MOUNT_DRAIN_TIMEOUT`                                   | `5m`                             | See [Unmounting](#what-happens-to-the-files-being-written).                                                                                                                                                                                                                                                                      |
| `--mirror-locks`            | `mount.mirror_locks`, `RETYC_MOUNT_MIRROR_LOCKS`                                     | `false`                          | Lock a file at the API while it is open for writing. See [Locks](#locks).                                                                                                                                                                                                                                                        |
| `--background-delete`       | `mount.background_delete`, `RETYC_MOUNT_BACKGROUND_DELETE`                           | `false`                          | Answer the removal of a file at once and delete it at the API afterwards. Much faster on many files; a removal that succeeded no longer proves the file is deleted. See [Deleting in the background](#deleting-in-the-background).                                                                                               |
| `--local-file pattern`      | `mount.local_files` (a list), `RETYC_MOUNT_LOCAL_FILES` (separated by spaces)        | `.*.swp`, `.*.swx`, `*~`, `4913` | Name patterns of the files kept on this machine and never sent; repeatable, `none` for no such file. See [Local files](#local-files).                                                                                                                                                                                            |
| `--unsafe-write`            | `api.unsafe_write`, `RETYC_API_UNSAFE_WRITE`                                         | `false`                          | Let the API acknowledge an upload before it is stored: `close` returns sooner, and a store that fails afterwards is reported to nobody, so a file closed without error may miss a chunk and fail to read (`EIO`). See [Acknowledge uploads before they are stored](configuration.md#acknowledge-uploads-before-they-are-stored). |
| `--metrics-addr`            | `mount.metrics.addr`, `RETYC_MOUNT_METRICS_ADDR`                                     | — (off)                          | Address of the metrics and probes listener. See [Metrics and probes](#metrics-and-probes).                                                                                                                                                                                                                                       |
| `--metrics-runtime`         | `mount.metrics.runtime`, `RETYC_MOUNT_METRICS_RUNTIME`                               | `true`                           | Include the `go_*` and `process_*` metrics.                                                                                                                                                                                                                                                                                      |
| `--metrics-label key=value` | `mount.metrics.labels` (a list), `RETYC_MOUNT_METRICS_LABELS` (separated by spaces)  | —                                | Constant label added to every metric; repeatable.                                                                                                                                                                                                                                                                                |

The cache durations (`--cache-ttl`, `--cache-negative-ttl`) are described under
[Freshness](#freshness), `--cache-store` and the `--cache-redis-*` flags under
[Shared metadata cache](#shared-metadata-cache-redis). A kernel timeout longer than `cache.ttl` delays what the mount
shows of a change made elsewhere by as much; a shorter one costs more requests to the
filesystem, not to the API.

## Deleting in the background

Removing a file costs one request to the API, which `rm` waits for: 100 to 200 ms each,
so `rm -r` of a thousand files takes minutes. `--background-delete`
(`mount.background_delete`, off by default) makes the removal answer as soon as the
mount has recorded it, and sends the delete to the API afterwards, a few at a time
(`api.concurrency.upload`, 4 by default).

What it changes:

- the file is gone from the mount at once (`ls`, `stat`, opening it by name), and stays
  gone while its delete is on its way, whatever the API still lists;
- **it is still in the dataroom until that delete is sent**: other clients, and the web
  application, see it for a moment longer;
- what needs the name free waits for the delete first: a file created again under the
  same name is sent after it, and so are `mkdir`, `ln -s`, a rename onto the name and a
  server-side copy. `rmdir` waits for the deletes of what was removed from the folder.
  Removing a folder itself is not deferred;
- what the mount can refuse by itself is still an error of `rm`: a read-only mount, a
  dataroom you may only read. A file never sent, and a [local file](#local-files), are
  removed as before, at no request;
- a file removed while a program holds it open stays readable and writable through that
  program's handles, as without the option.

What a successful `rm` no longer guarantees: that the API deleted the file. A delete the
API refuses (a right withdrawn meanwhile, the file locked by another client), or that
fails after the usual retries (network), is reported on the error output of the command,
by identifiers and never by name:

```
a background delete failed, the file is still in the dataroom: dataroom <id>, node <id>: <error>
```

**The file then comes back** in the mount: it was never deleted. Nothing tells the
program that removed it, which has long had its answer.

When the command is stopped, the deletes not sent yet are part of what
[`--drain-timeout`](#what-happens-to-the-files-being-written) waits for. Past it, or at
a second `Ctrl-C`, each delete that did not end is reported and the command exits with
code `1`, like for a file whose changes are lost:

```
a background delete did not end before the end of the shutdown drain, the file may still be in the dataroom: dataroom <id>, node <id>
```

A command that is killed (`SIGKILL`, a machine that stops) reports nothing: the files
whose delete had not been sent are still in the dataroom, and are back at the next
mount. Do not use the option where a removal must be known to have happened when `rm`
returns. `retyc_cli_fuse_background_deletes_total` counts the outcomes (see
[Metrics and probes](#metrics-and-probes)).

## Locks

`--mirror-locks` (`mount.mirror_locks`, off by default) makes the mount take a lock at
the API on a file for as long as a program has it open for writing:

- opening an **existing** file for writing (`O_WRONLY`, `O_RDWR`, `O_TRUNC`) takes an
  exclusive lock on it. There is one lock per file, whatever the number of programs
  writing to it through this mount; it is released when the last of them closes the
  file, once what it wrote is sent. Reading takes no lock;
- a file another RETYC client holds locked (a second mount, another client) fails to
  open for writing with `Device or resource busy` (`EBUSY`), before anything is
  truncated. It can still be read;
- a file created through the mount has nothing to lock until it is stored: it gets no
  lock while it is first written. Once closed, opening it again for writing locks it;
- the locks are renewed while they are held, and those still held when the mount is
  stopped are released then. A mount that is killed leaves its locks to lapse, five
  minutes at most. A lock the API did not renew and would not give again is lost
  (reported on the command's output): the programs that have the file open go on
  writing without it, and the next one that opens it for writing takes the lock again,
  or fails with `EBUSY` when another client took the file meanwhile.

The locks are **advisory**: the API refuses no write because of them. They only keep
apart the clients that take them. A mount without `--mirror-locks`, or the web
application, writes to a locked file all the same. When the API cannot be asked for the
lock (an error other than "locked"), the file is opened without it and the failure is
reported on the command's output. Each open of a file that is not being written yet
costs one request, and each close of the last writer one more.

## Metrics and probes

`--metrics-addr` (or `mount.metrics.addr`, or `RETYC_MOUNT_METRICS_ADDR`) starts an
unauthenticated HTTP listener for Prometheus and container orchestrators. It is off by
default, and bound before anything is mounted: an address already in use fails the
command at once.

```sh
retyc fs mount retyc://<dataroom-id> ~/dr --metrics-addr 127.0.0.1:9090
```

| Path       | Purpose    | Response                                                                                                                                                                                               |
|------------|------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `/metrics` | Prometheus | Go runtime and process metrics plus the CLI metrics below                                                                                                                                              |
| `/healthz` | Liveness   | `200` as long as the process answers                                                                                                                                                                   |
| `/readyz`  | Readiness  | `200` once the filesystem is mounted; `503` before that, and as soon as the mount starts to go away: a signal (for the whole of the drain), a login that cannot be renewed, or an unmount from outside |

`--metrics-runtime=false` drops the `go_*` and `process_*`
families, `--metrics-label key=value` adds constant labels to every series. A probe never calls the
API.

No label ever carries an identifier, a name or a path. Besides the metrics every
command shares (`retyc_cli_api_*`, `retyc_cli_token_*`, `retyc_cli_crypto_*`,
`retyc_cli_sessions_cached`, `retyc_cli_build_info`, `retyc_cli_vfs_node_cache_lookups_total`,
`retyc_cli_vfs_dataroom_cache_refreshes_total`, defined in the
[metrics table of the WebDAV page](webdav.md#metrics)), the mount has:

| Metric                                    | Type      | Labels                         | Meaning                                                                                                                                                                                                                                                                                          |
|-------------------------------------------|-----------|--------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `retyc_cli_fuse_ops_total`                | counter   | `op`, `result`                 | Filesystem operations served. `op` is the operation as the [access log](#diagnosing-the-access-log) names it (`lookup`, `getattr`, `open`, `read`, `write`, `flush`, `release`, `rename`, …); `result` is `ok` or the error (`ENOENT`, `EIO`, `EBUSY`, …, `other` for one that has no name here) |
| `retyc_cli_fuse_op_duration_seconds`      | histogram | `op`                           | Time an operation took. Most are answered from memory; those that reach the API take what the API takes                                                                                                                                                                                          |
| `retyc_cli_fuse_background_deletes_total` | counter   | `result` (`ok`, `error`)       | Deletes sent after the removal had answered (`--background-delete`). `error`: the file is still in the dataroom, see [Deleting in the background](#deleting-in-the-background)                                                                                                                   |
| `retyc_cli_fuse_bytes_total`              | counter   | `direction` (`read`, `write`)  | Plaintext bytes read from and written to the mount                                                                                                                                                                                                                                               |
| `retyc_cli_fuse_open_handles`             | gauge     | `kind` (`read`, `write`)       | Files open right now; `write` for a handle that changes its file                                                                                                                                                                                                                                 |
| `retyc_cli_vfs_spool_bytes`               | gauge     |                                | Bytes held in the spool directory by the files being written. A file opened for writing and not touched yet holds none                                                                                                                                                                           |
| `retyc_cli_vfs_uploads_total`             | counter   | `result` (`ok`, `error`)       | Files sent to the API (a new file or a new version). `error` is what a `close` or an `fsync` reported, or what the command's output reports for a file closed already                                                                                                                            |
| `retyc_cli_vfs_locks_held`                | gauge     |                                | Locks held at the API (`--mirror-locks`)                                                                                                                                                                                                                                                         |
| `retyc_cli_vfs_store_op_duration_seconds` | histogram | `op`, `result` (`ok`, `error`) | Time one operation of the [shared metadata cache](#shared-metadata-cache-redis) took: one round trip to Redis. `op` is the operation of the cache (`get_node`, `get_listing`, `put_listing`, `put_entry`, `generation`, …). Empty with `cache.store: memory`                                     |

## Diagnosing: the access log

A hidden folder at the root of the mount, absent from `ls`, shows what the filesystem
is being asked, as it happens:

```sh
cat ~/dr/.retycfs/accesslog
# 2026-10-12T08:30:15.123456Z lookup ino=1 1.2ms ENOENT
# 2026-10-12T08:30:15.130020Z opendir ino=1 41.7ms ok
# 2026-10-12T08:30:16.002113Z open ino=7 310µs ok
# 2026-10-12T08:30:16.004871Z read ino=7 off=0 len=131072 86.4ms ok
```

One line per operation: time, operation, inode number, offset and length for a read or
a write, duration, and `ok` or the error. **Never a file name or a path**: the inode number is
the one `ls -i` shows. The last 4,096 operations are kept, so opening the log just
after reproducing a problem still shows it; `cat` then follows the log until the
filesystem is unmounted.

Use `cat`, or `tail -n +1 -f`. Plain `tail -f` shows nothing: it seeks to the end of
what is a stream, not a file.

## Signals and interruptions

A program that receives a signal while it waits for the mount (a timer, a child that
ends, a profiler, the scheduler of a Go program) is not disturbed: the operation goes
to its end, `read` returns the bytes and `close` reports whether the file was stored.
No operation fails with `EINTR`, except a read of the [access log](#diagnosing-the-access-log)
that is waiting for the next operation: it is a stream that may stay silent for ever,
so a signal ends the wait as it does on a pipe, and `cat` or `tail` read again.

A program that is killed (`kill`, `kill -9`, Ctrl-C when it does not handle it) leaves
at once, even in the middle of a long download or upload: what it was reading is
abandoned, and a file it was writing is sent as it stands when its descriptors are
closed, like the file of any program that exits.

This relies on `/proc`: the mount looks there whether the program is being killed. When
it cannot tell (no `/proc` where `retyc` runs, a program of another PID namespace, as
when a mount made on the host is used from inside a container, or a `/proc` mounted
with `hidepid` that does not show the program to `retyc`), signals are still
harmless, but a killed program only goes once the operation it waits for has ended, or
when the filesystem is unmounted. A reader of the access log is the exception: it
leaves at once in every case.

## Known limits

- Linux only.
- The swap and backup files of an editor are not sent, and are gone at the unmount
  (see [Local files](#local-files)).
- `--background-delete`: a removal that succeeded is not yet a file deleted at the API,
  and a delete that fails brings the file back (see
  [Deleting in the background](#deleting-in-the-background)).
- `--mirror-locks`: a file created through the mount is not locked while it is first
  written, and the locks stop no client that does not take them (see [Locks](#locks)).
- Unless `--allow-other` is given, the mount is visible to the user who made it only.
- A login revoked on the server is noticed at the first request the API refuses; a
  mount nobody uses notices it at the next check of the login, within a minute of the
  access token expiring.
- A file being written is opened around the kernel's page cache (direct I/O): it
  cannot be mapped shared (`mmap` `MAP_SHARED`) on kernels older than 6.6.
- `cp` over a file that exists, and `cp` of a file larger than 4 GiB, download and
  upload (see "Writing").
- The inode number of a file or folder is kept while the kernel knows it; once the
  kernel has forgotten it, the next lookup may give it another one. Only state kept
  from one run to the next by inode number notices (`tar --listed-incremental` dumps
  such a folder again).
- A file name the kernel cannot represent (containing `/`, or longer than 255 bytes) is
  left out of the listing.
- The kernel has one page cache per file, whatever the version. While a program still
  holds a file open that was replaced since, a program that opens it afterwards reads
  the new version around that cache (direct I/O): always the right content, but not
  kept by the kernel, and such a file cannot be mapped shared (`mmap` `MAP_SHARED`)
  on kernels older than 6.6. The program that had it open keeps its version, read
  under the size of the new one: when the new version is shorter, its reads stop
  there. Both settle when the first program closes the file.
- A request refused by the API rate limit is retried by the CLI for up to 30 seconds
  (`api.retry.*`); the read simply takes longer. Past that it fails with an I/O error.
- Tracing (`OTEL_EXPORTER_OTLP_ENDPOINT`) records one `FUSE <operation>` span for each
  operation that reaches the API or, with `cache.store: redis`, Redis, with identifiers
  only, never a name.

## Without a mount: WebDAV

On macOS or Windows, or wherever a mount is not possible (no `/dev/fuse`, no
privileges), `retyc fs webdav serve` exposes the same datarooms over WebDAV, with the
same local encryption, to any WebDAV client. It is a secondary option: see
[WebDAV server](webdav.md).
