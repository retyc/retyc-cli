# Configuration

**Most people have nothing to configure.** Run `retyc auth login` and start
using the CLI; the defaults talk to `https://api.retyc.com`.

When you do need to change something, two commands show where you stand:

```sh
retyc config show   # effective value of every setting, secrets masked
retyc config path   # config directory, config file loaded, token file
```

## Where settings live

Settings come from a `config.yaml` file in the config directory, or from
environment variables. The config directory also holds your login token
(`token.json`).

| System  | Config directory                        |
|---------|-----------------------------------------|
| Linux   | `~/.config/retyc/`                      |
| macOS   | `~/Library/Application Support/retyc/`  |
| Windows | `%AppData%\retyc\`                      |
| Docker  | `/home/retyc/.config/retyc/` (mount a volume, see [Docker](docker.md)) |

- `RETYC_CONFIG_DIR=/some/path` moves the whole directory: config **and** token.
- `--config /some/file.yaml` reads another config file, but the token stays in
  the default directory.

An environment variable wins over `config.yaml`, which wins over the default.

## Common tasks

### Use another API endpoint

```yaml
# config.yaml
api:
  base_url: https://api.example.com
```

or, for a single command: `RETYC_API_BASE_URL=https://api.example.com retyc transfer ls`.

### Run without prompts (CI, scripts, MCP)

Set `RETYC_TOKEN` (an offline token from `retyc auth login --offline`) and
`RETYC_KEY_PASSPHRASE`, and pass `-y` to commands that ask for confirmation.
See [CI / CD](ci-cd.md). The MCP server and the Claude Desktop bundle use the
same two variables, see [MCP](mcp.md).

### Behind a corporate proxy

The CLI follows the usual curl and OpenSSL conventions:

```sh
export HTTPS_PROXY=http://user:password@proxy.corp.example:3128
export NO_PROXY=localhost,127.0.0.1,.internal.example
```

- `HTTPS_PROXY` covers every Retyc endpoint; `HTTP_PROXY` covers plain `http://`.
  Lower-case names work too. Schemes: `http://`, `https://`, `socks5://`.
- `NO_PROXY` takes hosts, domains (`.corp.example`) and CIDRs.
- `ALL_PROXY` is **not** supported.

If the proxy inspects TLS, point the CLI at its CA:

```sh
export SSL_CERT_FILE=/etc/ssl/corp/proxy-ca.pem   # a PEM bundle
# or SSL_CERT_DIR=/etc/ssl/corp                   # a directory of PEM files (several: ":" on Unix, ";" on Windows)
```

These CAs are **added** to the system ones, so public certificates keep
working. A missing or empty bundle stops the command at startup with a clear
message. Add `--debug` to see which proxy and which CAs each request uses
(proxy credentials are redacted).

### Administer the organization

`retyc admin` commands authenticate with an organization API key, separately
from `retyc auth login`:

```yaml
# config.yaml
admin:
  api_key: ryc_...                          # created from the dashboard
  private_key_file: /path/to/organization.key
```

- `api_key` is required by every `retyc admin` command.
- `private_key_file` is only needed to decrypt content or rekey
  (`admin dataroom nodes/download/rekey/user rm`, `admin transfer rekey`).
  It holds one post-quantum AGE identity (`AGE-SECRET-KEY-PQ-1...`), as
  downloaded from the dashboard or produced by `age-keygen`; comment lines are
  ignored. Legacy `AGE-SECRET-KEY-1...` keys are rejected. The file is never
  sent to the API nor cached.

### Tune the key cache (Linux)

After you type your key passphrase, the unlocked key is cached in the Linux
kernel keyring for 60 seconds, shared by the commands of the same terminal
session. Change or disable it:

```yaml
# config.yaml
keyring:
  enabled: true
  ttl: 300   # seconds
```

The cache does not exist on macOS and Windows, nor inside Docker.

## Reference

### Settings

| Setting | `config.yaml` key | Environment variable | Default |
|---|---|---|---|
| API endpoint | `api.base_url` | `RETYC_API_BASE_URL` | `https://api.retyc.com` |
| Key cache | `keyring.enabled` | `RETYC_KEYRING_ENABLED` | `true` (Linux only) |
| Key cache lifetime, seconds | `keyring.ttl` | `RETYC_KEYRING_TTL` | `60` |
| Organization API key | `admin.api_key` | `RETYC_ADMIN_API_KEY` | — |
| Organization private key file | `admin.private_key_file` | `RETYC_ADMIN_PRIVATE_KEY_FILE` | — |
| Admin API endpoint | `admin.base_url` | `RETYC_ADMIN_BASE_URL` | API endpoint + `/v1` |
| WebDAV metrics and probes listener | `webdav.metrics.addr` | `RETYC_WEBDAV_METRICS_ADDR` | — (disabled), see [WebDAV](webdav.md#metrics-and-probes) |
| WebDAV runtime metrics (`go_*`, `process_*`) | `webdav.metrics.runtime` | `RETYC_WEBDAV_METRICS_RUNTIME` | `true` |
| WebDAV constant metric labels | `webdav.metrics.labels` (list of `key=value`) | `RETYC_WEBDAV_METRICS_LABELS` (space-separated) | — |
| Config directory | — | `RETYC_CONFIG_DIR` | see [above](#where-settings-live) |
| Offline token | *secret, environment only* | `RETYC_TOKEN` | stored login |
| Key passphrase | *secret, environment only* | `RETYC_KEY_PASSPHRASE` | prompted |
| WebDAV password | *secret, environment only* | `RETYC_WEBDAV_PASSWORD` | generated at startup |

Environment variables must carry the `RETYC_` prefix; an empty variable counts
as unset. Proxy and CA variables (`HTTPS_PROXY`, `SSL_CERT_FILE`, ...) are the
standard ones, [see above](#behind-a-corporate-proxy).

### Global flags

| Flag | Description |
|---|---|
| `--config <file>` | Read another config file (the token stays in the config directory) |
| `--debug`, `-d` | Print every HTTP request and its response to stderr, with the proxy and CAs in use |
| `--json` | Results as JSON on stdout, errors as `{"error": "..."}` on stderr (see [JSON output](commands.md#json-output)) |

## Troubleshooting

- **A setting seems ignored:** `retyc config show` prints the value actually
  used. Check that the variable has the `RETYC_` prefix.
- **`config.yaml` seems ignored:** `retyc config path` says which file was
  loaded, or why an existing one was not (YAML syntax error, unreadable path).
  The CLI keeps running on defaults in that case. `--debug` prints the same
  reason on any command.
- **TLS or proxy errors:** rerun with `--debug`.

## Development builds

Binaries built without `-tags prod` (`go build .`, `go run .`) are meant for
working on the CLI itself and behave differently:

- config directory is `.retyc/` in the current directory;
- the default API endpoint is the development one;
- `--insecure` / `-k`, `insecure: true` in `config.yaml` or `RETYC_INSECURE`
  skip TLS certificate verification. Release binaries have no such option;
- `RETYC_TRACE`, set to any non-empty value, prints timing instrumentation to
  stderr, one line per traced operation (used by `scripts/webdav-bench.sh`).
  It works in release binaries too, but is only useful for performance work.
