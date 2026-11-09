# @retyc/mcp

[Retyc](https://retyc.com) MCP server: let your AI agent send and receive end-to-end encrypted
transfers and manage your datarooms. Files are encrypted on your machine before upload.

## Install

```sh
npx -y @retyc/mcp setup
```

The setup signs you in (in your browser), checks your key passphrase, and configures the AI
clients it finds on your machine: Claude Desktop, Hermes, OpenClaw.

Other clients run the server with `npx -y @retyc/mcp`, with your key passphrase in the
`RETYC_KEY_PASSPHRASE` environment variable. See the
[MCP documentation](https://github.com/retyc/retyc-cli/blob/master/doc/mcp.md).

## Platforms

Linux (x64, arm64), macOS (x64, arm64), Windows (x64). The binary of your platform is installed
as an optional dependency: do not install with `--omit=optional`.
