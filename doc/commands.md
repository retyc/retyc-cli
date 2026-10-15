# Commands reference

## JSON output

Every command accepts the global `--json` flag for scripting:

- **stdout** carries the result only, as indented JSON. Prompts, spinners,
  progress bars and warnings always go to stderr, so `retyc --json ... | jq`
  is safe.
- **errors** are written to stderr as one JSON object, on the last line, with a
  non-zero exit code; stdout is then empty (see [Errors in JSON](#errors-in-json)).
  Warnings printed before it stay plain text lines; spinners are drawn only
  when stderr is a terminal.
- Commands that ask for confirmation (`transfer create`, `transfer download`,
  `dataroom cp`, `dataroom rm`, `admin member rm`, `admin dataroom rm`,
  `admin dataroom user rm`, `admin transfer rm`) refuse to prompt under
  `--json`: pass `--yes` / `-y` explicitly.
- Listings are `{"items": [...]}` (plus `total`/`page`/`pages` when the API
  paginates). Detail commands return the API object as-is; state changes
  return a small acknowledgement such as `{"id": "...", "status": "disabled"}`.
- `dataroom cp` upload only reports completion (`{"uploaded": true, ...}`),
  not per-file node IDs.

```bash
retyc --json transfer ls | jq -r '.items[] | select(.status == "active") | .id'
retyc --json user quota | jq .used_storage
```

### Errors in JSON

```json
{
  "error": "...: API error 400: {\"detail\":\"A reserved capacity can only be enlarged\"}",
  "kind": "capacity_shrink",
  "status": 400,
  "code": "STORAGE_CAPACITY_SHRINK",
  "detail": "A reserved capacity can only be enlarged"
}
```

| Field    | Present                    | Content                                                                                                                                                                                                                                                                        |
|----------|----------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `error`  | always                     | The message the CLI prints without `--json`                                                                                                                                                                                                                                    |
| `kind`   | always                     | Stable classification, below: branch on it                                                                                                                                                                                                                                     |
| `status` | API refusals only          | HTTP status the API answered                                                                                                                                                                                                                                                   |
| `code`   | API refusals with a code   | The API's `X-Error-Code` header, verbatim (`STORAGE_EXCEEDED`, `NAME_HOLDER_DELETED`, ...); absent when the API sent none (an older API, a validation error, a proxy). A script may branch on it for a finer case than `kind`, which stays the CLI's own stable classification |
| `detail` | API refusals with a detail | The API's own wording, as is (a validation error's messages joined by `; `). It may change and hold numbers: informative only                                                                                                                                                  |

| `kind`               | Meaning                                                                                                                 |
|----------------------|-------------------------------------------------------------------------------------------------------------------------|
| `auth_required`      | No stored token, or the refresh token was rejected (exit code `77`)                                                     |
| `config`             | Key passphrase missing or wrong, environment file refused (exit code `78`)                                              |
| `lost_writes`        | `fs mount`: writes that did not reach the API before the unmount (exit code `75`)                                       |
| `needs_yes`          | A confirmation is needed: pass `--yes`                                                                                  |
| `rate_limited`       | The API rate limit, after the client's own retries                                                                      |
| `storage_exceeded`   | A write refused for lack of storage (dataroom reservation or owner's plan): code `STORAGE_EXCEEDED`                     |
| `plan_exceeded`      | A reservation the owner's plan cannot hold (`dataroom create` / `set --storage-capacity`): code `STORAGE_PLAN_EXCEEDED` |
| `capacity_too_small` | A reservation below the API's minimum: code `STORAGE_CAPACITY_TOO_SMALL` (a 400; a 422 from an older API)               |
| `capacity_shrink`    | A reservation made smaller than it is: it can only be enlarged: code `STORAGE_CAPACITY_SHRINK`                          |
| `unauthenticated`    | The API answered 401                                                                                                    |
| `forbidden`          | The API answered 403 (a viewer, a dataroom over its plan)                                                               |
| `not_found` / `gone` | The API answered 404 / 410                                                                                              |
| `conflict`           | The API answered 409                                                                                                    |
| `locked`             | The API answered 423                                                                                                    |
| `cli_too_old`        | The API answered 426: this CLI is older than the minimum it accepts                                                     |
| `invalid`            | Any other 400 or 422                                                                                                    |
| `api_error`          | Any other refusal of the API                                                                                            |
| `error`              | Anything else (network, local file, argument)                                                                           |

The four storage kinds come from the API's code. A refusal without a code
(an API that predates `X-Error-Code`) is classified by status and the former
detail texts instead; a refusal with another code never is, whatever its
detail says.

A `kind` is never renamed nor given another meaning; new ones may be added, so
treat an unknown one as `error`.

## Exit codes

| Code | Meaning                                                                                                                                                                                     |
|------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `0`  | Success                                                                                                                                                                                     |
| `1`  | Any failure, including transient ones (network, API or identity provider unreachable)                                                                                                       |
| `77` | Authentication required: no stored token, or the refresh token was rejected (expired or revoked). Retrying cannot help: run `retyc auth login` or provide a new `RETYC_TOKEN`               |
| `75` | `fs mount` only: the mount ran, but files being written (or removed in the background) did not reach the API before it went away. Their changes are lost; each is reported on stderr by IDs |
| `78` | Key passphrase missing (`RETYC_KEY_PASSPHRASE` unset and no TTY to prompt) or wrong. Retrying cannot help: fix the passphrase                                                               |

Codes `77` (`EX_NOPERM` in `sysexits.h`) and `78` (`EX_CONFIG`) are stable: a
supervisor restarting `retyc fs webdav serve` or `retyc fs mount` should stop on them
rather than retry. Code `75` (`EX_TEMPFAIL`) is stable too, and only `fs mount` returns
it: the mount worked, a restart may.

## Config

| Command             | Description                                                          |
|---------------------|----------------------------------------------------------------------|
| `retyc config show` | Effective value of every configuration key, secrets masked           |
| `retyc config path` | Config directory, config file actually loaded, and token file in use |

Both accept `--json`. `config show` returns `{"items": [{"key", "value",
"secret"}]}`.
`config path` returns `{"config_dir", "config_file", "config_file_error",
"token_file"}`: `config_file` is empty when no config file was loaded, and
`config_file_error` (omitted otherwise) says why a config file that exists was
not loaded — an unreadable `--config` path or a YAML syntax error. The CLI
still runs on defaults and environment in that case; `--debug` prints the same
reason on every command. Neither command opens a
network connection. See [Configuration](configuration.md) for the keys
themselves.

## Auth

| Command                      | Description                                            |
|------------------------------|--------------------------------------------------------|
| `retyc auth login`           | Authenticate via OIDC device flow                      |
| `retyc auth login --offline` | Authenticate and print an offline token for CI/CD use  |
| `retyc auth status`          | Check authentication status (silently refreshes token) |
| `retyc auth logout`          | Sign out                                               |

## Transfer

| Command                        | Description                                                                                   |
|--------------------------------|-----------------------------------------------------------------------------------------------|
| `retyc transfer create <file>` | Create and send a new transfer (`--generate-passphrase` to auto-generate a secure passphrase) |
| `retyc transfer info <id>`     | Get transfer details                                                                          |
| `retyc transfer ls`            | List sent and received transfers                                                              |
| `retyc transfer download <id>` | Download a transfer                                                                           |
| `retyc transfer enable <id>`   | Enable a transfer                                                                             |
| `retyc transfer disable <id>`  | Disable a transfer                                                                            |

## Dataroom

Datarooms are persistent, end-to-end encrypted shared spaces for files and folders.
All paths use the `retyc://dataroom-id/path` URI scheme.
Glob patterns (`*`, `?`, `[...]`) are supported in remote paths.

| Command                                                                                    | Description                                                   |
|--------------------------------------------------------------------------------------------|---------------------------------------------------------------|
| `retyc dataroom ls`                                                                        | List all your datarooms                                       |
| `retyc dataroom ls retyc://<id>[/path]`                                                    | List nodes at a path (supports globs)                         |
| `retyc dataroom create --title <title> [--versioning=false] [--storage-capacity SIZE]`     | Create a new dataroom                                         |
| `retyc dataroom info <id>`                                                                 | Show dataroom details, stats and members                      |
| `retyc dataroom set <id> [--title T] [--versioning=true\|false] [--storage-capacity SIZE]` | Change title, versioning or storage capacity                  |
| `retyc dataroom cp <local…> retyc://<id>/<dest>`                                           | Upload files or directories                                   |
| `retyc dataroom cp retyc://<id>/<path> <local-dir>`                                        | Download a file                                               |
| `retyc dataroom cp retyc://<id>/<src> retyc://<id>/<dst>`                                  | Copy a file on the server (same dataroom, nothing downloaded) |
| `retyc dataroom mv retyc://<id>/<src> retyc://<id>/<dst>`                                  | Rename or move a node                                         |
| `retyc dataroom rm retyc://<id>`                                                           | Delete the entire dataroom                                    |
| `retyc dataroom rm retyc://<id>/<path>`                                                    | Delete a node (supports globs)                                |
| `retyc dataroom mkdir retyc://<id>/<path>`                                                 | Create a folder                                               |
| `retyc dataroom user add <id> <email> [--role viewer\|editor\|admin]`                      | Add a member                                                  |
| `retyc dataroom user rm <id> <user-id>`                                                    | Remove a member                                               |

## Admin

Organization administration through the public API. Requires an organization
API key (`admin.api_key` / `RETYC_ADMIN_API_KEY`); commands that decrypt
content also require the organization private key file
(`admin.private_key_file` / `RETYC_ADMIN_PRIVATE_KEY_FILE`). See
[configuration.md](configuration.md#administer-the-organization).

### Organization

| Command                          | Description                                                                  |
|----------------------------------|------------------------------------------------------------------------------|
| `retyc admin org info`           | Show the organization and its member quota                                   |
| `retyc admin org update [flags]` | Update organization settings (name, event retention, API key IP restriction) |
| `retyc admin org scopes`         | List the scopes granted to the configured API key                            |

### Members

| Command                                                    | Description                                                   |
|------------------------------------------------------------|---------------------------------------------------------------|
| `retyc admin member ls [--search <text>] [--all]`          | List organization members (`--all` includes service accounts) |
| `retyc admin member info <user_id>`                        | Show a member with their identity details                     |
| `retyc admin member role <user_id> <owner\|admin\|member>` | Change the organization role of a member                      |
| `retyc admin member enable <user_id>`                      | Enable a member                                               |
| `retyc admin member disable <user_id>`                     | Disable a member                                              |
| `retyc admin member rm <user_id>`                          | Remove a member from the organization                         |

### Blacklist

| Command                                | Description                          |
|----------------------------------------|--------------------------------------|
| `retyc admin blacklist ls`             | List blacklisted email domains       |
| `retyc admin blacklist add <domain>`   | Add an email domain to the blacklist |
| `retyc admin blacklist rm <domain_id>` | Remove a domain from the blacklist   |

### Datarooms

| Command                                                       | Description                                                                                           |
|---------------------------------------------------------------|-------------------------------------------------------------------------------------------------------|
| `retyc admin dataroom ls [--user <user_id>]`                  | List the organization's datarooms                                                                     |
| `retyc admin dataroom info <dataroom_id>`                     | Show a dataroom, its users and their key status                                                       |
| `retyc admin dataroom activity <dataroom_id>`                 | Show the activity feed of a dataroom                                                                  |
| `retyc admin dataroom nodes <dataroom_id>`                    | List every node of a dataroom with decrypted names (needs organization key)                           |
| `retyc admin dataroom download <dataroom_id> [glob] [-o dir]` | Download and decrypt dataroom files with the organization key, recreating the folder tree under `dir` |
| `retyc admin dataroom chown <dataroom_id> <user_id>`          | Transfer the dataroom ownership to an admin member                                                    |
| `retyc admin dataroom user rm <dataroom_id> <user_id>`        | Remove a user from a dataroom and rekey it                                                            |
| `retyc admin dataroom rekey <dataroom_id>`                    | Re-encrypt the dataroom session key for all current members                                           |
| `retyc admin dataroom rm <dataroom_id>`                       | Delete a dataroom                                                                                     |

### Transfers

| Command                                                          | Description                                                    |
|------------------------------------------------------------------|----------------------------------------------------------------|
| `retyc admin transfer ls [--status <status>] [--user <user_id>]` | List the transfers sent by members of the organization         |
| `retyc admin transfer info <transfer_id>`                        | Show a transfer with its recipients and key status             |
| `retyc admin transfer tracking <transfer_id>`                    | Show download tracking for a transfer                          |
| `retyc admin transfer disable <transfer_id>`                     | Disable a transfer (reversible)                                |
| `retyc admin transfer enable <transfer_id>`                      | Re-enable a disabled transfer                                  |
| `retyc admin transfer rm <transfer_id> --force`                  | Permanently delete the data of a transfer                      |
| `retyc admin transfer rekey <transfer_id>`                       | Re-encrypt the transfer session key for all current recipients |

### Full export

| Command                                    | Description                                                    |
|--------------------------------------------|----------------------------------------------------------------|
| `retyc admin export-all-data <output_dir>` | Export the whole organization to a folder (data reversibility) |

The export writes a self-contained tree into `<output_dir>` (which must not
exist or be empty): `export.json` (manifest: counts, skipped datarooms,
errors), `organization.json`, `members.json` (with identity details),
`blacklist_domains.json`, and one `datarooms/{id}/` folder per dataroom
holding `meta.json` (clear-text metadata and users), `messages/N.json` (one
file per activity page, chat decrypted when possible) and `data/` (the
decrypted file tree). Datarooms the organization key cannot open get their
`meta.json` and messages but no `data/`, and are listed in the manifest.
Transfers are not exported: the admin API exposes no transfer file download.

## RetycFS

Mount your datarooms as an ordinary directory (Linux), read-write; `--read-only`
refuses every change. See [RetycFS](retycfs.md).

| Command                                             | Description                                           |
|-----------------------------------------------------|-------------------------------------------------------|
| `retyc fs mount retyc://<dataroom-id> <mountpoint>` | Mount one dataroom; it is the root of the mount point |
| `retyc fs mount --all <mountpoint>`                 | Mount every dataroom, one folder each                 |

Requires `RETYC_KEY_PASSPHRASE`, `/dev/fuse` and, unless run as root, `fusermount3`.
Stays in the foreground; unmount with Ctrl-C or `fusermount3 -u <mountpoint>`.

| Flag                                                                       | Description                                                                                                                                                                    |
|----------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--read-only`                                                              | Refuse every change                                                                                                                                                            |
| `--cache-ttl`, `--cache-negative-ttl`                                      | Listing and missing-name cache durations (`cache.*`)                                                                                                                           |
| `--cache-store`, `--cache-redis-url`, `--cache-redis-high-confidentiality` | Keep the listings in a Redis shared with other instances, see [Shared metadata cache](retycfs.md#shared-metadata-cache-redis)                                                  |
| `--entry-ttl`, `--attr-ttl`                                                | Kernel cache of names and attributes (default: `--cache-ttl`)                                                                                                                  |
| `--kernel-cache`                                                           | Keep what was read of a file between two opens (default `true`)                                                                                                                |
| `--readdir-plus`                                                           | Send the attributes of the entries with a listing: fewer requests to the mount, one inode held per entry listed (default `false`)                                              |
| `--spool-dir`                                                              | Directory of the files being written (default: the temporary directory)                                                                                                        |
| `--allow-other`                                                            | Let other users into the mount                                                                                                                                                 |
| `--uid`, `--gid`                                                           | Owner presented (default: the user running the command)                                                                                                                        |
| `--file-mode`, `--dir-mode`                                                | Permissions of a node that has none stored (`0644`, `0755`)                                                                                                                    |
| `--drain-timeout`                                                          | Time left to the files being sent when the mount is stopped (default `5m`)                                                                                                     |
| `--mirror-locks`                                                           | Lock a file at the API while it is open for writing; a file locked elsewhere fails to open with `EBUSY` (default `false`)                                                      |
| `--background-delete`                                                      | Answer the removal of a file at once and delete it at the API in the background: faster `rm`, but a delete that fails is only logged and the file comes back (default `false`) |
| `--local-file pattern`                                                     | Name pattern of the files kept on this machine and never sent (repeatable; default `.*.swp`, `.*.swx`, `*~`, `4913`; `none`: no such file)                                     |
| `--unsafe-write`                                                           | Let the API acknowledge uploads before they are stored (faster; a failed background store is not reported)                                                                     |
| `--metrics-addr`                                                           | Address for Prometheus metrics and health probes (`/metrics`, `/healthz`, `/readyz`); off by default                                                                           |
| `--metrics-label key=value`                                                | Constant label added to every metric (repeatable)                                                                                                                              |

Each has a `mount.*` key and a `RETYC_MOUNT_*` variable: see [RetycFS](retycfs.md#options).
Exit codes: `77` login expired, `78` key passphrase, `75` writes lost at the unmount, `1` otherwise.

## WebDAV

A secondary option: a local WebDAV server for the clients that cannot use the
mount (macOS, Windows, any WebDAV client), with the same end-to-end encryption.
On Linux, [RetycFS](retycfs.md) is the main way.

The command belongs to the `fs` group (filesystem access to datarooms). It was
`retyc webdav serve` before; that path has been removed, without an alias. Its
cache settings were renamed too (`webdav.cache.ttl` → `cache.ttl`, `webdav.cache.max_stale` →
`cache.max_stale`).

| Command                                     | Description                                                                                                                                                                               |
|---------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `retyc fs webdav serve`                     | Start a local WebDAV server (default `127.0.0.1:8888`)                                                                                                                                    |
| `retyc fs webdav serve --addr <host:port>`  | Bind to a specific address and port (default `127.0.0.1:8888`)                                                                                                                            |
| `retyc fs webdav serve --auth`              | Require HTTP Basic auth (user `retyc`)                                                                                                                                                    |
| `retyc fs webdav serve --cache-store redis` | Keep the listings in a Redis shared with other instances (`--cache-redis-url`, `--cache-redis-high-confidentiality`), see [Shared metadata cache](retycfs.md#shared-metadata-cache-redis) |

Requires `RETYC_KEY_PASSPHRASE`. Datarooms appear under `/dataroom`.

### Examples

```sh
# Create a dataroom (title is required)
retyc dataroom create --title "Project Alpha"

# Create one with a 50 GiB reservation and a single version per file
retyc dataroom create --title "Scans" --storage-capacity 50G --versioning=false

# Rename it, enlarge its reservation (sizes are binary: 100G = 100GiB)
retyc dataroom set 019d3de3-... --title "Scans 2026" --storage-capacity 100G

# Upload a release directory
retyc dataroom cp ./dist/ retyc://019d3de3-.../releases/

# List contents (TYPE is DIR, FILE or LINK; a symlink shows as "name -> target")
retyc dataroom ls retyc://019d3de3-.../releases/

# Download a specific file
retyc dataroom cp retyc://019d3de3-.../releases/binary ./

# Download all PDFs from a folder
retyc dataroom cp retyc://019d3de3-.../docs/*.pdf ./local/

# Delete all log files
retyc dataroom rm retyc://019d3de3-.../*.log

# Delete the entire dataroom
retyc dataroom rm retyc://019d3de3-...

# Add a collaborator
retyc dataroom user add 019d3de3-... alice@example.com --role editor
```
