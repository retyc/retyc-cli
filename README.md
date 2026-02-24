# retyc-cli

> Official command-line interface for [RETYC](https://retyc.com) - send and manage file transfers directly from your terminal.

[![CI](https://github.com/retyc/retyc-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/retyc/retyc-cli/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.24-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Release](https://img.shields.io/github/v/release/retyc/retyc-cli)](https://github.com/retyc/retyc-cli/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

![demo](.media/demo.gif)

---

## What is RETYC?

[RETYC](https://retyc.com) is a European sovereign file-sharing platform with end-to-end post-quantum encryption. Data stays in Europe, GDPR-compliant by design.

`retyc-cli` lets you integrate RETYC transfers into your scripts, pipelines and workflows - no browser required.

---

## Installation

### Pre-compiled binaries (recommended)

Download the binary for your platform from the [latest release](https://github.com/retyc/retyc-cli/releases/latest).

### With `go install`

```sh
go install -tags prod github.com/retyc/retyc-cli@latest
```

### From source

```sh
git clone https://github.com/retyc/retyc-cli.git
cd retyc-cli
go build -tags prod -ldflags "-X github.com/retyc/retyc-cli/cmd.Version=$(git describe --tags --always)" -o retyc .
```

---

## Quick start

```sh
# 1. Authenticate (opens a browser tab, no password stored)
retyc auth login

# 2. Send a file
retyc transfer create report.pdf

# 3. List your transfers
retyc transfer ls

# 4. Download a transfer
retyc transfer download <transfer-id>
```

---

## Commands

### Auth

| Command | Description |
|---|---|
| `retyc auth login` | Authenticate via OIDC device flow |
| `retyc auth status` | Check authentication status (silently refreshes token) |
| `retyc auth logout` | Sign out |

### Transfer

| Command | Description |
|---|---|
| `retyc transfer create <file>` | Create and send a new transfer |
| `retyc transfer info <id>` | Get transfer details |
| `retyc transfer ls` | List sent and received transfers |
| `retyc transfer download <id>` | Download a transfer |
| `retyc transfer enable <id>` | Enable a transfer |
| `retyc transfer disable <id>` | Disable a transfer |

---

## Configuration

Credentials and config are stored in a platform-specific directory:

| Build | Config directory |
|---|---|
| Production (`-tags prod`) | `~/.config/retyc/` (XDG Base Dir) |
| Development (default) | `.retyc/` in the current directory |

Override at any time:

```sh
export RETYC_CONFIG_DIR=/path/to/config
```

Create `config.yaml` to override defaults:

```yaml
api:
  base_url: https://api.retyc.com
```

### Global flags

| Flag | Short | Description |
|---|---|---|
| `--config <file>` | | Use a specific config file |
| `--insecure` | `-k` | Skip TLS certificate verification |
| `--debug` | | Enable debug mode |

---

## Security

- **Authentication**: OIDC device flow - no password ever stored locally
- **File data + metadata**: end to end encrypted with [AGE](https://github.com/FiloSottile/age) post-quantum hybrid keys
- **Private key caching** (Linux only): the decrypted AGE identity in the kernel session keyring (never written to disk). It is scoped to the current terminal session, isolated from other users and sessions, and automatically wiped after a configurable TTL (default: 60sec).
- **Transport**: TLS enforced by default

---

## Roadmap

### Transfer
| Feature | Status |
|---|---|
| Create | ✅ |
| Info | ✅ |
| List (inbox / sent) | ✅ |
| Download | ✅ |
| Enable/Disable | ✅ |

### Dataroom
| Feature | Status |
|---|---|
| Create / Info / List | 🔜 |
| User management | 🔜 |
| File management (CRUD + versions) | 🔜 |

### Organization
| Feature | Status |
|---|---|
| User management (invitations, roles) | 🔜 |

---

## Development

```sh
# Run in dev mode
go run . --help

# Run tests
go test -race ./...

# Production build
go build -tags prod -ldflags "-X github.com/retyc/retyc-cli/cmd.Version=v0.1.0" -o retyc .
```

---

## License

[MIT](LICENSE) - © RETYC / TripleStack SAS
