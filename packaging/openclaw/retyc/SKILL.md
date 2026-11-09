---
name: retyc
description: Send and receive end-to-end encrypted file transfers and manage secure Retyc datarooms through the Retyc MCP server. Use when the user wants to share files securely, download a Retyc transfer, or work with a Retyc dataroom.
---

# Retyc

Retyc encrypts files on this machine before upload (post-quantum, end to end). This skill uses
the Retyc MCP server, which exposes tools such as `transfer_send`, `transfer_download`,
`dataroom_upload` and `dataroom_ls`.

## Install (once)

If the `retyc` MCP server is not configured, tell the user to run this in a terminal on the
machine where OpenClaw runs:

```sh
npx -y @retyc/mcp setup
```

It signs them in through their browser, checks their key passphrase, stores both secrets in
`~/.openclaw/.env` and registers the `retyc` server (`mcp.servers.retyc`). Then restart the
Gateway.

Manual alternative: put `RETYC_KEY_PASSPHRASE` in `~/.openclaw/.env`, then

```sh
openclaw config set mcp.servers.retyc '{"command":"npx","args":["-y","@retyc/mcp"],"env":{"RETYC_KEY_PASSPHRASE":"${RETYC_KEY_PASSPHRASE}"}}' --strict-json
```

and ask the agent to "log me into Retyc" (it returns a link to open).

## Rules

- **Never ask for the key passphrase in the chat.** It only lives in `~/.openclaw/.env`. If a
  tool reports a missing or wrong passphrase, tell the user to run `npx -y @retyc/mcp setup`
  again.
- If a tool returns `not_authenticated`, call `auth_login_start`, give the user the link, then
  `auth_login_poll` once they have signed in.
- File paths are absolute paths on the machine running OpenClaw. Ask the user for them; do not
  guess.
- Never open, read or summarize the files you upload or download: they are confidential.
- Ask for confirmation before deleting dataroom content or removing a member.
