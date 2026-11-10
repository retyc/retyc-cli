# MCP Server

`retyc mcp serve` runs a **Model Context Protocol (MCP) server** over stdio, exposing
Retyc operations as tools to AI agents. For Claude Desktop, the [MCPB bundle](mcpb.md)
needs no terminal.

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
      "args": ["mcp", "serve"],
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

| Variable               | Required | Description                                                                 |
|------------------------|----------|-----------------------------------------------------------------------------|
| `RETYC_KEY_PASSPHRASE` | Yes      | Unlocks your private key, for transfers and datarooms.                      |
| `RETYC_TOKEN`          | No       | Offline refresh token, used instead of the token stored on disk.           |
| `RETYC_CONFIG_DIR`     | No       | Config directory (default `~/.config/retyc/`).                              |

Without a stored login, ask the agent *"Log me into Retyc"* and open the URL it gives you.

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
