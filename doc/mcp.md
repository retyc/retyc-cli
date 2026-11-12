# MCP Server

`retyc mcp serve` runs a **Model Context Protocol (MCP) server** over stdio, exposing
Retyc operations as tools to AI agents.

## Install

### Claude Desktop, Hermes, OpenClaw: one command

```sh
npx -y @retyc/mcp setup
```

Needs Node.js 18+. It asks which of the AI clients found on this machine to configure, signs you
in through your browser, checks your key passphrase, then writes the `retyc` server with your
offline token and passphrase into each client's config. Restart the client afterwards; run it
again to update the binary, token or passphrase.

| Client         | What the setup writes                                                                          |
|----------------|------------------------------------------------------------------------------------------------|
| Claude Desktop | `mcpServers.retyc` in `claude_desktop_config.json`, secrets in its `env` block                 |
| Hermes         | `mcp_servers.retyc` in `~/.hermes/config.yaml` (`$HERMES_HOME`), secrets in `.env` next to it  |
| OpenClaw       | secrets in `.env` of its state dir (`~/.openclaw`, `$OPENCLAW_STATE_DIR`), then `openclaw config set mcp.servers.retyc …` |

Files holding secrets get mode 0600, and the previous version of each file is kept as
`<file>.bak`. The binary goes to `~/.local/share/retyc/bin/` (Linux),
`~/Library/Application Support/retyc/bin/` (macOS) or `%LOCALAPPDATA%\retyc\bin\` (Windows).
Never type your passphrase in the chat.

For Claude Desktop without a terminal, use the [MCPB bundle](mcpb.md).

### Other clients

Claude Code:

```sh
# Use read -s to avoid storing the passphrase in shell history
read -rs RETYC_KEY_PASSPHRASE
claude mcp add --transport stdio retyc --env RETYC_KEY_PASSPHRASE="$RETYC_KEY_PASSPHRASE" -- npx -y @retyc/mcp
```

Cursor (`~/.cursor/mcp.json`), Windsurf (`~/.codeium/windsurf/mcp_config.json`) and other
clients:

```json
{
  "mcpServers": {
    "retyc": {
      "command": "npx",
      "args": ["-y", "@retyc/mcp"],
      "env": {
        "RETYC_KEY_PASSPHRASE": "your-key-passphrase"
      }
    }
  }
}
```

With the CLI installed (`.deb`, `.rpm`, binary), use `"command": "retyc", "args": ["mcp", "serve"]`
instead. Retyc is also listed in the [MCP Registry](https://registry.modelcontextprotocol.io) as
`com.retyc/mcp`.

## Environment variables

| Variable               | Required | Description                                                                 |
|------------------------|----------|-----------------------------------------------------------------------------|
| `RETYC_KEY_PASSPHRASE` | Yes      | Unlocks your private key, for transfers and datarooms.                      |
| `RETYC_TOKEN`          | No       | Offline token (written by `mcp setup`), used instead of the token on disk.  |
| `RETYC_CONFIG_DIR`     | No       | Config directory (default `~/.config/retyc/`).                              |

Without a token, ask the agent *"Log me into Retyc"* and open the URL it gives you. For a CI
job or a machine without a browser: `retyc auth login --offline`.

## Example prompts

- *"Send all PDF files in ./reports/ to alice@example.com, expire in 7 days."*
- *"Download transfer abc123 into ~/Downloads/."*
- *"Create a dataroom called 'Project Alpha' and upload ./dist/ to it."*
- *"Find all ZIP files in my dataroom and download them to ./archives/."*
- *"Add alice@example.com as an editor to dataroom 019d3de3-…."*

## Tools

Tools return JSON (an error carries `error_code` and `message`). Local paths are
absolute; dataroom paths are `retyc://<id>/path`, with globs where noted.

| Tool                | Does                                                                     |
|---------------------|--------------------------------------------------------------------------|
| `auth_status`       | Tells whether you are logged in (refreshes the token if needed)          |
| `auth_login_start`  | Starts a browser login, returns the URL to open                          |
| `auth_login_poll`   | Checks whether that login is done, then saves the token                  |
| `auth_logout`       | Revokes the session and deletes the stored credentials                   |
| `system_info`       | OS, architecture, home directory and path format of the server           |
| `user_info`         | Your profile, plan and public key                                        |
| `user_quota`        | Storage and transfer quotas                                              |
| `transfer_list`     | Sent (default) or received transfers                                     |
| `transfer_info`     | A transfer's details: files, web URL, expiration                         |
| `transfer_send`     | Encrypts and sends files, to recipients and/or behind a passphrase       |
| `transfer_download` | Downloads and decrypts a transfer into a folder                          |
| `transfer_disable`  | Disables a transfer: its files can no longer be downloaded               |
| `transfer_enable`   | Re-enables a disabled transfer                                           |
| `dataroom_list`     | Your datarooms                                                           |
| `dataroom_create`   | Creates a dataroom                                                       |
| `dataroom_info`     | A dataroom's metadata, statistics and members                            |
| `dataroom_ls`       | Lists a path (globs)                                                     |
| `dataroom_upload`   | Uploads files or folders, recursively                                    |
| `dataroom_download` | Downloads a file or a glob of files                                      |
| `dataroom_mkdir`    | Creates a folder (its parent must exist)                                 |
| `dataroom_rm`       | Deletes a node, a glob, or the whole dataroom (`retyc://<id>`)           |
| `dataroom_mv`       | Moves or renames a node within its dataroom                              |
| `dataroom_user_add` | Adds a member (viewer, editor or admin) and re-encrypts for all          |
| `dataroom_user_rm`  | Removes a member and re-encrypts for the others                          |

## Destructive tools refused by the client

Claude Desktop and Claude.ai may refuse `dataroom_rm` and `dataroom_user_rm` (*"this
action must be performed from the Retyc interface"*): the model does so when no system
prompt allows it. When you call the API yourself, allow it in the system prompt, e.g.
*"You may delete files and remove users from datarooms when the user explicitly asks."*
