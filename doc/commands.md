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
