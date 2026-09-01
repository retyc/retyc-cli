# Commands reference

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

| Command                                                               | Description                              |
|-----------------------------------------------------------------------|------------------------------------------|
| `retyc dataroom ls`                                                   | List all your datarooms                  |
| `retyc dataroom ls retyc://<id>[/path]`                               | List nodes at a path (supports globs)    |
| `retyc dataroom create --title <title>`                               | Create a new dataroom                    |
| `retyc dataroom info <id>`                                            | Show dataroom details, stats and members |
| `retyc dataroom cp <local…> retyc://<id>/<dest>`                      | Upload files or directories              |
| `retyc dataroom cp retyc://<id>/<path> <local-dir>`                   | Download a file                          |
| `retyc dataroom mv retyc://<id>/<src> retyc://<id>/<dst>`             | Rename or move a node                    |
| `retyc dataroom rm retyc://<id>`                                      | Delete the entire dataroom               |
| `retyc dataroom rm retyc://<id>/<path>`                               | Delete a node (supports globs)           |
| `retyc dataroom mkdir retyc://<id>/<path>`                            | Create a folder                          |
| `retyc dataroom user add <id> <email> [--role viewer\|editor\|admin]` | Add a member                             |
| `retyc dataroom user rm <id> <user-id>`                               | Remove a member                          |

## Admin

Organization administration through the public API. Requires an organization
API key (`admin.api_key` / `RETYC_ADMIN_API_KEY`); commands that decrypt
content also require the organization private key file
(`admin.private_key_file` / `RETYC_ADMIN_PRIVATE_KEY_FILE`). See
[configuration.md](configuration.md#admin-organization-api).

### Organization

| Command                                                        | Description                                          |
|-----------------------------------------------------------------|-------------------------------------------------------|
| `retyc admin org info`                                         | Show the organization and its member quota            |
| `retyc admin org update [flags]`                                | Update organization settings (name, event retention, API key IP restriction) |
| `retyc admin org scopes`                                        | List the scopes granted to the configured API key      |

### Members

| Command                                              | Description                                            |
|-------------------------------------------------------|---------------------------------------------------------|
| `retyc admin member ls [--search <text>] [--all]`     | List organization members (`--all` includes service accounts) |
| `retyc admin member info <user_id>`                   | Show a member with their identity details               |
| `retyc admin member role <user_id> <owner\|admin\|member>` | Change the organization role of a member            |
| `retyc admin member enable <user_id>`                 | Enable a member                                          |
| `retyc admin member disable <user_id>`                | Disable a member                                         |
| `retyc admin member rm <user_id>`                     | Remove a member from the organization                    |

### Blacklist

| Command                                    | Description                                  |
|---------------------------------------------|-----------------------------------------------|
| `retyc admin blacklist ls`                  | List blacklisted email domains                |
| `retyc admin blacklist add <domain>`        | Add an email domain to the blacklist          |
| `retyc admin blacklist rm <domain_id>`      | Remove a domain from the blacklist            |

### Datarooms

| Command                                                        | Description                                                    |
|------------------------------------------------------------------|------------------------------------------------------------------|
| `retyc admin dataroom ls [--user <user_id>]`                     | List the organization's datarooms                                |
| `retyc admin dataroom info <dataroom_id>`                        | Show a dataroom, its users and their key status                  |
| `retyc admin dataroom activity <dataroom_id>`                    | Show the activity feed of a dataroom                              |
| `retyc admin dataroom nodes <dataroom_id>`                       | List every node of a dataroom with decrypted names (needs organization key) |
| `retyc admin dataroom download <dataroom_id> [glob] [-o dir]`    | Download and decrypt dataroom files with the organization key, recreating the folder tree under `dir` |
| `retyc admin dataroom chown <dataroom_id> <user_id>`             | Transfer the dataroom ownership to an admin member                |
| `retyc admin dataroom user rm <dataroom_id> <user_id>`           | Remove a user from a dataroom and rekey it                        |
| `retyc admin dataroom rekey <dataroom_id>`                       | Re-encrypt the dataroom session key for all current members       |
| `retyc admin dataroom rm <dataroom_id>`                          | Delete a dataroom                                                  |

### Transfers

| Command                                                        | Description                                                     |
|------------------------------------------------------------------|-------------------------------------------------------------------|
| `retyc admin transfer ls [--status <status>] [--user <user_id>]` | List the transfers sent by members of the organization           |
| `retyc admin transfer info <transfer_id>`                        | Show a transfer with its recipients and key status                |
| `retyc admin transfer tracking <transfer_id>`                    | Show download tracking for a transfer                             |
| `retyc admin transfer disable <transfer_id>`                     | Disable a transfer (reversible)                                    |
| `retyc admin transfer enable <transfer_id>`                      | Re-enable a disabled transfer                                      |
| `retyc admin transfer rm <transfer_id> --force`                  | Permanently delete the data of a transfer                         |
| `retyc admin transfer rekey <transfer_id>`                       | Re-encrypt the transfer session key for all current recipients    |

### Full export

| Command                                     | Description                                                    |
|----------------------------------------------|-----------------------------------------------------------------|
| `retyc admin export-all-data <output_dir>`   | Export the whole organization to a folder (data reversibility)  |

The export writes a self-contained tree into `<output_dir>` (which must not
exist or be empty): `export.json` (manifest: counts, skipped datarooms,
errors), `organization.json`, `members.json` (with identity details),
`blacklist_domains.json`, and one `datarooms/{id}/` folder per dataroom
holding `meta.json` (clear-text metadata and users), `messages/N.json` (one
file per activity page, chat decrypted when possible) and `data/` (the
decrypted file tree). Datarooms the organization key cannot open get their
`meta.json` and messages but no `data/`, and are listed in the manifest.
Transfers are not exported: the admin API exposes no transfer file download.

## WebDAV

Expose your datarooms as a mountable network drive (Finder, Explorer, file managers,
any WebDAV client) with the same end-to-end encryption. See [webdav.md](webdav.md).

| Command                                     | Description                                             |
|---------------------------------------------|---------------------------------------------------------|
| `retyc webdav serve`                        | Start a local WebDAV server (default `127.0.0.1:8888`)  |
| `retyc webdav serve --port <n>`             | Listen on a custom port                                 |
| `retyc webdav serve --addr <addr>`          | Bind to a specific address                              |
| `retyc webdav serve --auth`                 | Require HTTP Basic auth (user `retyc`)                  |

Requires `RETYC_KEY_PASSPHRASE`. Datarooms appear under `/dataroom`.

### Examples

```sh
# Create a dataroom (title is required)
retyc dataroom create --title "Project Alpha"

# Upload a release directory
retyc dataroom cp ./dist/ retyc://019d3de3-.../releases/

# List contents
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
