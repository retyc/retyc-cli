# MCP Server

`retyc-cli` runs as a **Model Context Protocol (MCP) server**, exposing all Retyc operations as tools to AI agents.

## Quick start

```sh
# Start the MCP server (uses stdio transport)
retyc mcp serve
```

## Client integrations

### Claude Code

```sh
# Use read -s to avoid storing the passphrase in shell history
read -rs RETYC_KEY_PASSPHRASE
claude mcp add --transport stdio retyc --env RETYC_KEY_PASSPHRASE="$RETYC_KEY_PASSPHRASE" -- /path/to/retyc mcp serve
```

### Claude Desktop / Cursor / Windsurf

Add the following to your client's MCP config file:

```json
{
  "mcpServers": {
    "retyc": {
      "command": "retyc",
      "args": [
        "mcp",
        "serve"
      ],
      "env": {
        "RETYC_KEY_PASSPHRASE": "your-key-passphrase"
      }
    }
  }
}
```

| Client                   | Config file                                                       |
|--------------------------|-------------------------------------------------------------------|
| Claude Desktop (macOS)   | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Desktop (Windows) | `%APPDATA%\Claude\claude_desktop_config.json`                     |
| Cursor                   | `~/.cursor/mcp.json`                                              |
| Windsurf                 | `~/.codeium/windsurf/mcp_config.json`                             |

## Environment variables

| Variable               | Required | Description                                                                                    |
|------------------------|----------|------------------------------------------------------------------------------------------------|
| `RETYC_KEY_PASSPHRASE` | Yes      | AGE private key passphrase. Required for encrypted operations (transfers, datarooms).          |
| `RETYC_TOKEN`          | No       | Offline refresh token. If set, bypasses local token storage (useful in isolated environments). |
| `RETYC_CONFIG_DIR`     | No       | Override config directory (default: `.retyc/` in dev mode, `~/.config/retyc/` in prod).        |

Unlocking the private key with the passphrase runs an scrypt that needs ~256 MiB of
working memory. The server resolves each dataroom session once and keeps it in memory for
its whole lifetime, so that cost is paid on the first dataroom operation only (the memory
is handed back to the OS right after). Transfer tools still unlock the key on every call
unless the Linux keyring caches it.

## Authentication in MCP mode

The MCP server operates in two modes:

1. **With token on disk** (default): Reads stored token from config directory (default: `.retyc/` or `~/.config/retyc/`).
   Refreshes automatically if expired.
2. **With `RETYC_TOKEN` env var**: Uses offline refresh token directly, bypassing disk storage.

### Authenticate from the chat (device flow)

You can authenticate without leaving your AI client by asking the agent to log you in:

> *"Log me into Retyc."*

The agent will call `auth_login_start`, which returns a one-time URL. Open it in your browser, complete the login, then
tell the agent to continue. It will poll with `auth_login_poll` until the token is confirmed and saved to disk.

The `auth_login_start` tool short-circuits if a valid token is already stored, so it is safe to call at any time.

### Authenticate via CLI

```sh
retyc auth login
```

Run this before starting the MCP server if you prefer to authenticate outside the agent.

## Example prompts

Once the MCP server is connected, you can ask your AI agent to perform Retyc operations in plain language:

**Transfers**

- *"Send all PDF files in ./reports/ to alice@example.com, expire in 7 days."*
- *"List my last 10 received transfers and show me the file names in the most recent one."*
- *"Download transfer abc123 into ~/Downloads/."*

**Datarooms**

- *"Create a dataroom called 'Project Alpha' and upload the entire ./dist/ directory to it."*
- *"List all files in retyc://019d3de3-.../releases/ and tell me the total size."*
- *"Find all ZIP files in my dataroom and download them to ./archives/."*
- *"Add alice@example.com as an editor to dataroom 019d3de3-…."*

**Automation**

- *"After building the project, upload the binary to the dataroom and send me the web URL."*
- *"Check my quota and warn me if I'm above 80% usage."*

## Tools reference

All tools return structured JSON responses. On error, responses include `error_code` and `message` fields.

Long-running operations (upload/download) emit progress notifications showing bytes transferred and elapsed time.

### Auth

| Tool               | Description                                                                                                                                                    | Parameters                         |
|--------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------|
| `auth_status`      | Check authentication status and token validity. Silently refreshes token if expired.                                                                           | None                               |
| `auth_login_start` | Initiate OIDC device flow. Returns a URL to open in the browser. Short-circuits with `already_authenticated: true` if a valid token is already stored on disk. | None                               |
| `auth_login_poll`  | Poll once for the device flow result. Returns `status: "pending"`, `"slow_down"`, `"expired"`, or `"denied"`. Saves the token to disk when `done` is `true`.   | **device_code**: string (required) |

### User

| Tool          | Description                                                                                          | Parameters |
|---------------|------------------------------------------------------------------------------------------------------|------------|
| `system_info` | Return runtime OS, architecture, home directory, and expected path format of the MCP server process. | None       |
| `user_info`   | Get current user profile: email, name, company, address, plan details, public key.                   | None       |
| `user_quota`  | Get storage and transfer quotas (used / limit).                                                      | None       |

### Transfer

| Tool                | Description                                                                                                | Parameters                                                                                                                                                                                                                                                                                                                                    |
|---------------------|------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `transfer_list`     | List sent or received transfers (default: sent). Returns ID, title, status, recipient count, created date. | **filter**: `"sent"` (default) or `"received"`; **page**: int (default: 1)                                                                                                                                                                                                                                                                    |
| `transfer_info`     | Get full transfer details: title, message, file list with decrypted names and sizes, web URL, expiration.  | **id**: string (required)                                                                                                                                                                                                                                                                                                                     |
| `transfer_send`     | Create and upload a new encrypted transfer. Files are encrypted locally before upload.                     | **files**: array of absolute local file paths (required); **title**: string (optional); **message**: string (optional); **passphrase**: string (optional); **generate_passphrase**: boolean (auto-generate secure passphrase); **to**: array of recipient emails (optional); **expire**: int seconds (default: 3600, set 0 for no expiration) |
| `transfer_download` | Download and decrypt all files from a transfer into a local directory.                                     | **id**: string (required); **output_dir**: string absolute local path (required); **passphrase**: string (only if no user key stored)                                                                                                                                                                                                         |
| `transfer_disable`  | Disable (soft-delete) a transfer. Files cannot be downloaded after.                                        | **id**: string (required)                                                                                                                                                                                                                                                                                                                     |
| `transfer_enable`   | Re-enable a previously disabled transfer.                                                                  | **id**: string (required)                                                                                                                                                                                                                                                                                                                     |

### Dataroom

| Tool                | Description                                                                       | Parameters                                                                                                                            |
|---------------------|-----------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------|
| `dataroom_list`     | List all datarooms. Returns ID, title, created date, file count.                  | None                                                                                                                                  |
| `dataroom_create`   | Create a new end-to-end encrypted dataroom.                                       | **title**: string (required)                                                                                                          |
| `dataroom_info`     | Get dataroom metadata, file statistics, member list with roles.                   | **id**: string (required)                                                                                                             |
| `dataroom_ls`       | List nodes at a path in a dataroom. Supports glob patterns (`*`, `?`, `[...]`).   | **uri**: string in format `retyc://id` or `retyc://id/path` or `retyc://id/*.pdf` (required)                                          |
| `dataroom_upload`   | Upload local files or directories recursively. Encrypted end-to-end.              | **local_paths**: array of absolute paths (required); **remote_uri**: string in format `retyc://id/folder` (required)                  |
| `dataroom_download` | Download and decrypt a file or glob of files from a dataroom.                     | **remote_uri**: string in format `retyc://id/file` or `retyc://id/*.pdf` (required); **local_dir**: string absolute path (required)   |
| `dataroom_mkdir`    | Create a folder in a dataroom. Parent path must exist.                            | **uri**: string in format `retyc://id/path/new-folder` (required)                                                                     |
| `dataroom_rm`       | Delete a node (file or folder) or entire dataroom. Supports glob patterns.        | **uri**: string: `retyc://id` deletes dataroom; `retyc://id/path` deletes node; globs expand (required)                               |
| `dataroom_mv`       | Move or rename a node within the same dataroom.                                   | **src_uri**: string in format `retyc://id/src` (required); **dst_uri**: string in format `retyc://id/dst` (required)                  |
| `dataroom_user_add` | Add a member to a dataroom. Automatically re-encrypts for all members (rekey).    | **dataroom_id**: string (required); **email**: string (required); **role**: `"viewer"` (default), `"editor"`, or `"admin"` (optional) |
| `dataroom_user_rm`  | Remove a member from a dataroom. Automatically re-encrypts for remaining members. | **dataroom_id**: string (required); **user_id**: string (required)                                                                    |

## Client limitations

### Destructive tools in Claude Desktop / Claude.ai

`dataroom_rm` and `dataroom_user_rm` may be refused by Claude Desktop with a message like *"this action must be
performed from the Retyc interface"*. This is **not caused by the MCP `destructiveHint` annotation**, it is a
model-level conservative default applied in the absence of an operator system prompt.

Per the MCP specification, `destructiveHint: true` is a hint for clients to show a confirmation dialog, not a mandate to
refuse. The refusal is a behaviour of the Claude model itself, independent of the annotation. Removing the annotation
would not change anything.

**Behaviour varies by client:**

| Client                     | Observed behaviour                                                                     |
|----------------------------|----------------------------------------------------------------------------------------|
| Claude Desktop / Claude.ai | May refuse destructive actions (conservative model default, no operator system prompt) |
| Claude Code                | Has its own permission system (allowedTools, hooks), model defaults may still apply    |
| Cursor                     | Implements its own confirmation prompts, independently of `destructiveHint`            |
| Windsurf                   | Has been reported to ignore annotations and skip confirmation entirely                 |

### Unlocking destructive actions via the Anthropic API

When calling the Anthropic API directly you act as an operator and control the system prompt. Providing explicit context
unlocks the model's conservative defaults:

```json
{
  "model": "claude-sonnet-4-6",
  "system": "You are an assistant for Retyc. You may delete files and remove users from datarooms when the user explicitly asks.",
  "messages": [
    ...
  ]
}
```

Anthropic grants operator system prompts a higher trust level than tool descriptions or observed content. This is the
only reliable way to adjust these model defaults: no server-side MCP patch can achieve the same effect.
