# Commands reference

## JSON output

With the global `--json` flag:

- **stdout** carries the result only; prompts, progress and warnings go to stderr, so
  `retyc --json ... | jq` is safe.
- **errors** are one JSON object on the last line of stderr, with a non-zero exit code
  and an empty stdout (see [Errors in JSON](#errors-in-json)).
- Commands that ask for confirmation refuse to prompt: pass `--yes` / `-y`.
- Listings are `{"items": [...]}` (plus `total` / `page` / `pages` when paginated);
  detail commands return the API object; state changes return a small acknowledgement
  such as `{"id": "...", "status": "disabled"}`.

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

| Field    | Present                    | Content                                                                          |
|----------|----------------------------|----------------------------------------------------------------------------------|
| `error`  | always                     | The message printed without `--json`                                             |
| `kind`   | always                     | Stable classification, below: branch on it                                      |
| `status` | API refusals               | HTTP status                                                                      |
| `code`   | API refusals with a code   | The API's `X-Error-Code` header (`STORAGE_EXCEEDED`, ...), for finer cases       |
| `detail` | API refusals with a detail | The API's wording: informative only, it may change                               |

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
| `enrollment_expired` | `machine enroll`: the request expired unanswered (exit code `1`: run it again)                                          |
| `enrollment_denied`  | `machine enroll`: an administrator refused the request (exit code `78`)                                                 |
| `error`              | Anything else (network, local file, argument)                                                                           |

A `kind` is never renamed nor given another meaning; new ones may be added, so treat an
unknown one as `error`.

## Exit codes

| Code | Meaning                                                                                                     |
|------|-------------------------------------------------------------------------------------------------------------|
| `0`  | Success                                                                                                     |
| `1`  | Any other failure, transient ones included (network, API unreachable)                                       |
| `75` | `fs mount` only: writes did not reach the API before the unmount and are lost (reported on stderr by IDs)   |
| `77` | Login required: no token, refresh token expired or revoked, machine account disabled. Run `retyc auth login`, provide a new `RETYC_TOKEN`, or `retyc machine enable` |
| `78` | Key passphrase missing or wrong, configuration error, `machine enroll` refused                              |

These codes are stable. A supervisor should **not** restart on `77` (`EX_NOPERM`) or `78`
(`EX_CONFIG`): the same credentials will fail again. After `75` (`EX_TEMPFAIL`) a restart
may work.

## Config

| Command             | Description                                                          |
|---------------------|----------------------------------------------------------------------|
| `retyc config show` | Effective value of every configuration key, secrets masked           |
| `retyc config path` | Config directory, config file actually loaded, and token file in use |

Neither opens a network connection. With `--json`, `config path` adds
`config_file_error` when an existing config file could not be loaded. See
[Configuration](configuration.md).

## Auth

| Command                      | Description                                            |
|------------------------------|--------------------------------------------------------|
| `retyc auth login`           | Authenticate via OIDC device flow                      |
| `retyc auth login --offline` | Authenticate and print an offline token for CI/CD use  |
| `retyc auth status`          | Check authentication status (silently refreshes token); with a machine account, checks the token endpoint and that `age.key` matches the active key |
| `retyc auth logout`          | Sign out                                               |

## MCP

| Command              | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| `retyc mcp serve`    | Run the MCP server on stdio ([mcp.md](mcp.md))                              |
| `retyc mcp setup`    | Interactive setup of Claude Desktop, Hermes, OpenClaw ([mcp.md](mcp.md#install)) |
| `retyc mcp manifest` | Print the MCPB manifest ([mcpb.md](mcpb.md))                                |

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
| `retyc dataroom user chown <id> <user-id\|email> [--yes]`                                  | Transfer the ownership to an admin member (you become admin)  |

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

`<output_dir>` must be empty or absent. It receives `export.json` (manifest),
`organization.json`, `members.json`, `blacklist_domains.json` and one `datarooms/{id}/`
folder per dataroom (`meta.json`, `messages/`, decrypted `data/`). Datarooms the
organization key cannot open have no `data/` and are listed in the manifest. Transfers are
not exported.

## Machine

```bash
# Enroll a server, a CI runner or a cluster (no login needed)
retyc machine enroll --org <uuid> --output-dir ./machine [--name <name>] [--cluster-uid <id>]
```

Generates the keys in `--output-dir` (reused if present) and waits until an administrator
approves the request (Organization > Machines), after comparing the fingerprint. With
`--json`, stdout carries one event per line:

```json
{"event":"pending","enrollment_id":"...","fingerprint":"K7QF-2MXA-PD9R-H3TB","approval_uri":"...","expires_at":"2026-10-17T18:30:00Z"}
{"event":"approved","machine_id":"...","organization_id":"...","client_id":"machine-..."}
```

Exit codes: `0` approved, `1` expired (run it again, the keys are kept), `78` denied or
misconfigured. A machine then works like a user (`retyc dataroom user add` to share its
datarooms).

```bash
# Organization admins, with their own login
retyc machine requests                       # pending enrollments
retyc machine approve <enrollment-id> [--fingerprint K7QF-...] [--name <name>] [-y]
retyc machine deny <enrollment-id> [-y]
retyc machine ls                             # machine accounts and their status
retyc machine disable <machine-id> [-y]      # refused at once (exit 77), keys kept
retyc machine enable <machine-id> [-y]
retyc machine rm <machine-id> [-y]           # refused while it owns datarooms (chown them first); must enroll again
```

`approve` asks for confirmation unless `--fingerprint` matches. An approved machine takes
a seat.

## RetycFS and WebDAV

| Command                                             | Description                                                    |
|-----------------------------------------------------|----------------------------------------------------------------|
| `retyc fs mount retyc://<dataroom-id> <mountpoint>` | Mount one dataroom (Linux), see [RetycFS](retycfs.md)          |
| `retyc fs mount --all <mountpoint>`                 | Mount every dataroom, one folder each                          |
| `retyc fs webdav serve [--addr host:port] [--auth]` | Local WebDAV server (`127.0.0.1:8888`), see [WebDAV](webdav.md) |
