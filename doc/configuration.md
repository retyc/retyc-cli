# Configuration

**Most people have nothing to configure**: run `retyc auth login`, the defaults talk to
`https://api.retyc.com`.

```sh
retyc config show   # effective value of every setting, secrets masked
retyc config path   # config directory, config file loaded, token file
```

## Where settings live

The config directory holds `config.yaml` and your login token (`token.json`):

| System  | Config directory                                                       |
|---------|------------------------------------------------------------------------|
| Linux   | `~/.config/retyc/`                                                     |
| macOS   | `~/Library/Application Support/retyc/`                                 |
| Windows | `%AppData%\retyc\`                                                     |
| Docker  | `/home/retyc/.config/retyc/` (mount a volume, see [Docker](docker.md)) |

`RETYC_CONFIG_DIR` moves the whole directory; `--config file.yaml` reads another config
file but keeps the token in place. [`config.example.yaml`](../config.example.yaml) lists
every key with its default.

Precedence: flag > environment variable > [environment file](#environment-file) >
`config.yaml` > default. Variables need the `RETYC_` prefix; an empty one counts as unset.

## Common tasks

### Use another API endpoint (Retyc On-Premise)

```yaml
api:
  base_url: https://api.example.com
```

or `RETYC_API_BASE_URL=https://api.example.com` for a single command.

### Run without prompts (CI, scripts, MCP)

Set `RETYC_TOKEN` (from `retyc auth login --offline`) and `RETYC_KEY_PASSPHRASE`, and pass
`-y` to commands that ask for confirmation. See [CI / CD](ci-cd.md) and [MCP](mcp.md).

### Environment file

A service started without a terminal reads its secrets from a file given by `--env-file`
or `RETYC_ENV_FILE`. [`retyc.env.example`](../retyc.env.example) lists every variable.

```sh
# /etc/retyc/env    (chmod 600, owned by the user the service runs as)
RETYC_TOKEN=eyJhbGciOi...
RETYC_KEY_PASSPHRASE="correct horse battery staple"
```

```ini
# /etc/systemd/system/retyc-mount.service
[Service]
Environment = RETYC_ENV_FILE=/etc/retyc/env
ExecStart = /usr/local/bin/retyc fs mount retyc://019d3de3-... /mnt/dataroom
Restart = on-failure
RestartPreventExitStatus = 77 78
```

- One `NAME=value` per line (`export` accepted, `#` comments). Quotes are optional and
  nothing is expanded (`$HOME` stays `$HOME`).
- `RETYC_*` names only (not `RETYC_ENV_FILE` itself); `HTTPS_PROXY` and the like are refused.
- The real environment wins, even with an empty value.
- On Linux and macOS the file must be mode `0600`. A missing, too open or malformed file
  stops the command with exit code `78`; the message never quotes the line.

### Behind a corporate proxy

```sh
export HTTPS_PROXY=http://user:password@proxy.corp.example:3128
export NO_PROXY=localhost,127.0.0.1,.internal.example
export SSL_CERT_FILE=/etc/ssl/corp/proxy-ca.pem   # or SSL_CERT_DIR, if the proxy inspects TLS
```

`HTTP_PROXY`, lower-case names, `http://`, `https://` and `socks5://` proxies work;
`ALL_PROXY` does not. The CAs are **added** to the system ones. `--debug` shows the proxy
and CAs each request uses (credentials redacted).

### Administer the organization

`retyc admin` commands use an organization API key, not your login:

```yaml
admin:
  api_key: ryc_...                              # required by every admin command
  private_key_file: /path/to/organization.key   # to decrypt content or rekey
```

The key file holds one post-quantum AGE identity (`AGE-SECRET-KEY-PQ-1...`); it is never
sent nor cached.

### Key cache (Linux)

The unlocked key is cached in the kernel keyring for 60 seconds, shared by the commands of
the same terminal session. Not available on macOS, Windows, nor in Docker.

```yaml
keyring:
  enabled: true
  ttl: 300   # seconds
```

### Parallel requests

Listings come 100 nodes per page, files in 8 MB chunks; both are fetched several at a
time (1 to 32, default 4). Everything shares one HTTP/2 connection: a higher value hides
latency but does not multiply bandwidth, and loads the server more.

```yaml
api:
  concurrency:
    list: 4
    upload: 4
    download: 4   # a download holds up to twice this many 8 MB chunks in memory
```

### Acknowledge uploads before they are stored

`api.unsafe_write: true` (or `--unsafe-write` on `fs mount` and `fs webdav serve`) makes the API answer as soon as it has
received a chunk and store it in the background: much faster on small files. **The cost is
durability**: a background store that fails is never reported, and the file can no longer
be downloaded ("chunk missing on the server"). Keep the default for archives and one-shot
uploads; consider it for an interactive mount.

### When the API rate-limits you

The API limits requests per IP address, shared by every `retyc` process behind it. The
CLI waits the pause asked for (`Retry-After`) and sends again; one line on stderr reports
it:

```
API rate limit: throttled from 10:42:07 to 10:42:08 (1.02s), 12 refusal(s), 12 request(s) held back
```

A request gives up after `api.retry.max_attempts` attempts or `api.retry.max_wait` of
waiting. `retyc fs webdav serve` then answers its own client `429`.

## Settings

| Setting                                          | `config.yaml` key                  | Environment variable                     | Default                    |
|--------------------------------------------------|------------------------------------|------------------------------------------|----------------------------|
| API endpoint                                     | `api.base_url`                     | `RETYC_API_BASE_URL`                     | `https://api.retyc.com`    |
| Listing pages fetched at once                    | `api.concurrency.list`             | `RETYC_API_CONCURRENCY_LIST`             | `4`                        |
| Chunks uploaded at once per file¹                | `api.concurrency.upload`           | `RETYC_API_CONCURRENCY_UPLOAD`           | `4`                        |
| Chunks downloaded at once per file               | `api.concurrency.download`         | `RETYC_API_CONCURRENCY_DOWNLOAD`         | `4`                        |
| Acknowledge uploads before they are stored       | `api.unsafe_write`                 | `RETYC_API_UNSAFE_WRITE`                 | `false`                    |
| Longest wait on a rate-limited request           | `api.retry.max_wait`               | `RETYC_API_RETRY_MAX_WAIT`               | `30s` (`1s` to `10m`)      |
| Attempts at a rate-limited request               | `api.retry.max_attempts`           | `RETYC_API_RETRY_MAX_ATTEMPTS`           | `10` (1 to 100)            |
| Key cache                                        | `keyring.enabled`                  | `RETYC_KEYRING_ENABLED`                  | `true` (Linux only)        |
| Key cache lifetime, seconds                      | `keyring.ttl`                      | `RETYC_KEYRING_TTL`                      | `60`                       |
| Organization API key                             | `admin.api_key`                    | `RETYC_ADMIN_API_KEY`                    | —                          |
| Organization private key file                    | `admin.private_key_file`           | `RETYC_ADMIN_PRIVATE_KEY_FILE`           | —                          |
| Admin API endpoint                               | `admin.base_url`                   | `RETYC_ADMIN_BASE_URL`                   | API endpoint + `/v1`       |
| Listing cache lifetime                           | `cache.ttl`                        | `RETYC_CACHE_TTL`                        | `1m`                       |
| Expired listings served while refreshed (WebDAV) | `cache.max_stale`                  | `RETYC_CACHE_MAX_STALE`                  | `5m` (`0`: off)            |
| Missing names cache lifetime                     | `cache.negative_ttl`               | `RETYC_CACHE_NEGATIVE_TTL`               | `1s` (`0`: off)            |
| Listing cache store: `memory` or `redis`         | `cache.store`                      | `RETYC_CACHE_STORE`                      | `memory`                   |
| Redis URL, password included (secret)            | `cache.redis.url`                  | `RETYC_CACHE_REDIS_URL`                  | —                          |
| Store names encrypted in Redis                   | `cache.redis.high_confidentiality` | `RETYC_CACHE_REDIS_HIGH_CONFIDENTIALITY` | `false`                    |
| WebDAV bind address                              | `webdav.addr`                      | `RETYC_WEBDAV_ADDR`                      | `127.0.0.1:8888`           |
| `fs mount` options²                              | `mount.entry_ttl`                  | `RETYC_MOUNT_ENTRY_TTL`                  | `0` (`cache.ttl` / 2)      |
|                                                  | `mount.attr_ttl`                   | `RETYC_MOUNT_ATTR_TTL`                   | `0` (`cache.ttl` / 2)      |
|                                                  | `mount.kernel_cache`               | `RETYC_MOUNT_KERNEL_CACHE`               | `true`                     |
|                                                  | `mount.readdir_plus`               | `RETYC_MOUNT_READDIR_PLUS`               | `false`                    |
|                                                  | `mount.spool_dir`                  | `RETYC_MOUNT_SPOOL_DIR`                  | system temp dir            |
|                                                  | `mount.allow_other`                | `RETYC_MOUNT_ALLOW_OTHER`                | `false`                    |
|                                                  | `mount.uid`                        | `RETYC_MOUNT_UID`                        | `-1` (the command's)       |
|                                                  | `mount.gid`                        | `RETYC_MOUNT_GID`                        | `-1` (the command's)       |
|                                                  | `mount.file_mode`                  | `RETYC_MOUNT_FILE_MODE`                  | `"0644"` (quoted in YAML)  |
|                                                  | `mount.dir_mode`                   | `RETYC_MOUNT_DIR_MODE`                   | `"0755"` (quoted in YAML)  |
|                                                  | `mount.read_only`                  | `RETYC_MOUNT_READ_ONLY`                  | `false`                    |
|                                                  | `mount.drain_timeout`              | `RETYC_MOUNT_DRAIN_TIMEOUT`              | `5m`                       |
|                                                  | `mount.mirror_locks`               | `RETYC_MOUNT_MIRROR_LOCKS`               | `false`                    |
|                                                  | `mount.background_delete`          | `RETYC_MOUNT_BACKGROUND_DELETE`          | `false`                    |
|                                                  | `mount.warmup`                     | `RETYC_MOUNT_WARMUP`                     | `false`                    |
|                                                  | `mount.warmup_depth`               | `RETYC_MOUNT_WARMUP_DEPTH`               | `0` (all)                  |
|                                                  | `mount.local_files`                | `RETYC_MOUNT_LOCAL_FILES` (spaces)       | `.*.swp .*.swx *~ 4913`    |
|                                                  | `mount.metrics.addr`               | `RETYC_MOUNT_METRICS_ADDR`               | — (off)                    |
|                                                  | `mount.metrics.labels`             | `RETYC_MOUNT_METRICS_LABELS` (spaces)    | —                          |
| Config directory                                 | —                                  | `RETYC_CONFIG_DIR`                       | see [above](#where-settings-live) |
| Environment file                                 | — (`--env-file`)                   | `RETYC_ENV_FILE`                         | —                          |
| Offline token                                    | *secret, environment only*         | `RETYC_TOKEN`                            | stored login               |
| Key passphrase                                   | *secret, environment only*         | `RETYC_KEY_PASSPHRASE`                   | prompted                   |
| WebDAV password                                  | *secret, environment only*         | `RETYC_WEBDAV_PASSWORD`                  | generated at startup       |
| Machine account directory³                       | —                                  | `RETYC_MACHINE_DIR`                      | — (user account)           |
| Machine account client ID                        | —                                  | `RETYC_CLIENT_ID`                        | from `machine.json`        |
| Machine account token endpoint                   | —                                  | `RETYC_TOKEN_ENDPOINT`                   | from `machine.json`        |
| Machine account signing key file                 | —                                  | `RETYC_CLIENT_KEY_FILE`                  | `$RETYC_MACHINE_DIR/client.key` |
| Machine account AGE key file                     | —                                  | `RETYC_AGE_KEY_FILE`                     | `$RETYC_MACHINE_DIR/age.key` |

1. Also the files `fs mount` and `fs webdav serve` upload at once, and the background
   deletes of `fs mount`.
2. Described in [RetycFS options](retycfs.md#options). Durations need a unit (`90s`, `2m`).
3. Holds `machine.json`, `client.key`, `age.key`; exclusive of `RETYC_TOKEN` and
   `RETYC_KEY_PASSPHRASE`. The files must be `0600` or `0440` (a Kubernetes Secret with
   `defaultMode: 0440` works); otherwise exit code 78.

## Global flags

| Flag                | Description                                                                     |
|---------------------|---------------------------------------------------------------------------------|
| `--config <file>`   | Read another config file                                                        |
| `--env-file <file>` | Read `RETYC_*` variables from a file, see [Environment file](#environment-file) |
| `--debug`, `-d`     | Print every HTTP request and response to stderr                                 |
| `--json`            | Machine-readable output, see [JSON output](commands.md#json-output)             |

## Tracing (OpenTelemetry)

Only `retyc fs mount` traces ([spans](retycfs.md#traces)), and only when the environment
sets an OTLP endpoint: there is no flag nor config key.

```sh
OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318 retyc fs mount --all ~/dr
```

The standard `OTEL_*` variables apply (`OTEL_EXPORTER_OTLP_PROTOCOL`: `http/protobuf` or
`grpc`, `OTEL_SDK_DISABLED`, `OTEL_SERVICE_NAME` defaulting to `retycfs`, samplers,
headers, TLS), and `TRACEPARENT` / `TRACESTATE` parent the startup span. Spans never carry
names, titles, bodies, headers nor error messages. `--debug` may print the endpoint and
a malformed `OTEL_EXPORTER_OTLP_HEADERS`: keep tokens out of the endpoint, and `--debug`
off when the headers carry one. `scripts/start-jaeger.sh` runs a local Jaeger
(UI on `http://localhost:16686`).

## Troubleshooting

- **A setting seems ignored**: `retyc config show` prints the value used; check the
  `RETYC_` prefix.
- **`config.yaml` seems ignored**: `retyc config path` says which file was loaded, or why
  not (YAML error, unreadable path).
- **TLS or proxy errors**: rerun with `--debug`.

## Development builds

Binaries built without `-tags prod` (`go build .`) use `.retyc/` in the current directory
and the development API. `--insecure` / `-k`, `insecure: true` or `RETYC_INSECURE` skip TLS
verification; release binaries have no such option.
