# retyc-cli

> Official command-line interface for the [RETYC](https://retyc.com) platform — manage transfers, datarooms and your organization directly from your terminal.

[![CI](https://github.com/retyc/retyc-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/retyc/retyc-cli/actions/workflows/ci.yml)
![Go](https://img.shields.io/badge/go-1.24-00ADD8?logo=go&logoColor=white)
![Status](https://img.shields.io/badge/status-experimental-orange)

---

> [WARNING]
> **Experimental — pre-release software.**
> `retyc-cli` is under active development. APIs, configuration formats and command interfaces may change without notice until the first stable release (`v1.0.0`). Do not use in production.

---

## Overview

`retyc-cli` lets you interact with the [RETYC](https://retyc.com) platform from your terminal. It authenticates via **OIDC device flow** (no password stored), communicates with the RETYC REST API, and stores credentials securely using **AGE encryption**.

## Requirements

- Go 1.24+ (for building from source)
- A RETYC account — [retyc.com](https://retyc.com)

## Installation

### From source

```bash
git clone https://github.com/retyc/retyc-cli.git
cd retyc-cli
go build -tags prod -ldflags "-X github.com/retyc/retyc-cli/cmd.Version=$(git describe --tags --always)" -o retyc .
```

### With `go install`

```bash
go install -tags prod github.com/retyc/retyc-cli@latest
```

## Quick start

```bash
# Authenticate — opens a browser URL and waits
retyc auth login

# Check authentication status (silently refreshes an expired token)
retyc auth status

# Sign out
retyc auth logout
```

## Configuration

The CLI looks for a configuration file and stores credentials in a platform-specific directory.

| Build | Config directory |
|---|---|
| Production (`-tags prod`) | `~/.config/retyc/` (XDG Base Dir) |
| Development (default) | `.retyc/` in the current directory |

Override at any time with the `RETYC_CONFIG_DIR` environment variable.

### Config file

Create `config.yaml` in your config directory to override defaults:

```yaml
api:
  base_url: https://retyc-api.dev
```

### Global flags

| Flag | Short | Description |
|---|---|---|
| `--config <file>` | | Use a specific config file |
| `--insecure` | `-k` | Skip TLS certificate verification (self-signed certs) |

## Roadmap

### Auth

| Feature | Status |
|---|---|
| Login via OIDC device flow | ✅ |
| Logout | ✅ |
| Silent token refresh | ✅ |

### Transfer

| Feature | Status |
|---|---|
| Create | ✅ |
| Info | ✅ |
| List (inbox / sent) | ✅ |
| Download | ✅ |

### Dataroom

| Feature | Status |
|---|---|
| Create | ❌ |
| Info | ❌ |
| List | ❌ |
| User management (add, delete, grants) | ❌ |
| Delete | ❌ |
| File management (CRUD + versions) | ❌ |

### Organization

| Feature | Status |
|---|---|
| User management (invitations, delete, grants) | ❌ |

### Misc

| Feature | Status |
|---|---|
| API / Auth status | ❌ |

## Development

```bash
# Run in dev mode (config stored in .retyc/ of the current directory)
go run . --help

# Run tests
go test -race ./...

# Production build with version
go build -tags prod -ldflags "-X github.com/retyc/retyc-cli/cmd.Version=v0.1.0" -o retyc .
```

## License

See [LICENSE](./LICENSE).
