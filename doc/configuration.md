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

| System  | Config directory                                                       |
|---------|------------------------------------------------------------------------|
| Linux   | `~/.config/retyc/`                                                     |
| macOS   | `~/Library/Application Support/retyc/`                                 |
| Windows | `%AppData%\retyc\`                                                     |
| Docker  | `/home/retyc/.config/retyc/` (mount a volume, see [Docker](docker.md)) |

- `RETYC_CONFIG_DIR=/some/path` moves the whole directory: config **and** token.
- `--config /some/file.yaml` reads another config file, but the token stays in
  the default directory.

[`config.example.yaml`](../config.example.yaml) lists every `config.yaml` key
with its default value and a short comment: copy it to start a config file, and
keep only the lines you change.

An environment variable wins over `config.yaml`, which wins over the default.
Variables can also come from an [environment file](#keep-the-secrets-in-an-environment-file-boot-mounts-systemd-csi)
(`--env-file`), which the real environment wins over.

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

### Keep the secrets in an environment file (boot mounts, systemd, CSI)

A service that starts without a terminal reads its secrets from a file,
designated with `--env-file` or `RETYC_ENV_FILE` (the flag wins). It works on
every system and for every command.
[`retyc.env.example`](../retyc.env.example) lists every variable with its
default value, commented out: copy it and uncomment what you set.

```sh
# /etc/retyc/env    (chmod 600, owned by the user the service runs as)
# The offline token and the passphrase of the key
RETYC_TOKEN=eyJhbGciOi...
RETYC_KEY_PASSPHRASE="correct horse battery staple"
RETYC_API_BASE_URL=https://api.example.com
```

```bash
retyc --env-file /etc/retyc/env fs mount retyc://019d3de3-... /mnt/dataroom
retyc --env-file /etc/retyc/env fs webdav serve
```

```ini
# /etc/systemd/system/retyc-mount.service
[Service]
Environment = RETYC_ENV_FILE=/etc/retyc/env
ExecStart = /usr/local/bin/retyc fs mount retyc://019d3de3-... /mnt/dataroom
Restart = on-failure
RestartPreventExitStatus = 77 78
```

The same file also works as a systemd `EnvironmentFile=/etc/retyc/env`, as long
as its values need no quotes; `--env-file` has the advantage of being the same
on every system and of refusing a file other users can read.

- **Format**: one `NAME=value` per line; `export NAME=value` is accepted; blank
  lines and lines starting with `#` are ignored. A value is the rest of the
  line, or the content of a pair of single or double quotes (use them for a
  value with leading or trailing spaces; a comment may follow the closing
  quote). Nothing is expanded: `$HOME` stays `$HOME`. Between double quotes
  `\"` and `\\` stand for `"` and `\`; an unquoted value keeps its `#`.
- **Only `RETYC_*` variables** are accepted, all of them: the secrets and any
  setting of the [reference](#settings), `RETYC_CONFIG_DIR` included. Any
  other name (`HTTPS_PROXY`, `SSL_CERT_FILE`, ...) is an error, and so is
  `RETYC_ENV_FILE` itself.
- **The environment wins**: a variable the process already has, even empty, is
  not replaced by the file. Then come `config.yaml` and the defaults, as usual.
- **Permissions**: on Linux and macOS the file must not be accessible by group
  or others (`chmod 600`), or the command refuses to start. Windows is not
  checked: protect the file with its ACL.
- A file that is missing, unreadable, too open or malformed stops the command
  with exit code `78` (configuration), like a missing passphrase. The message
  gives the line number and never the content of the line. `retyc version`,
  `retyc config path` and `retyc config show` still run and print a warning.
- `retyc config path` shows the file in use and the names of the variables it
  brought; `retyc config show` lists their effective values like any
  environment value, secrets masked.

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

### Tune parallel requests

A large folder is listed 100 nodes per page, and files are transferred in
8 MB chunks. After the first page, pages and chunks are requested several at
a time:

```yaml
# config.yaml
api:
  concurrency:
    list: 4       # listing pages fetched at once
    upload: 4     # chunks uploaded at once, per file
    download: 4   # chunks downloaded at once, per file
```

Every value must be between 1 and 32. All requests share a single HTTP/2 connection
to the API, so a higher value mostly saves waiting on latency: it speeds up
the listing of large folders (`dataroom ls`, `webdav serve`) but does not
multiply the bandwidth of a transfer, and it puts more load on the server.
A download holds up to twice `download` decrypted chunks in memory
(8 MB each).

### Acknowledge uploads before they are stored

By default every upload is acknowledged once the API has stored it. With
`unsafe_write`, the API answers as soon as it has received a chunk and stores
it in the object store in the background, which removes that store from every
upload's latency — on small files, most of it:

```yaml
# config.yaml
api:
  unsafe_write: true
```

or `RETYC_API_UNSAFE_WRITE=true`, or `--unsafe-write` on `retyc fs webdav serve` and
`retyc fs mount`.

The cost is durability: a background store that fails (the object store
unreachable, the API worker killed) is never reported. The upload has
succeeded, the file is listed with its full size, and yet one of its chunks is
missing, so the file can no longer be downloaded. Keep the default for archives
and anything uploaded once (`dataroom cp`, the MCP server); consider it for an
interactive WebDAV mount, where latency matters and a file is usually still at
hand. The API ignores the setting above its own size limit, or when too many
chunks are already being stored in the background.

A download meeting such a chunk retries it twice within a second (it may still
be on its way to the store), then fails with "chunk missing on the server: the
file version is incomplete or corrupted".

### When the API rate-limits you

The API accepts a bounded number of requests per second from one IP address,
shared by everything behind that address: every `retyc` process of a machine,
of an office, of a Kubernetes node. Above it, a request is refused with
`429 Too Many Requests` before it reaches the API. The CLI handles that by
itself: it stops sending for the pause the server asks for (`Retry-After`,
one second in practice), then sends the refused requests again. A command is
slowed down, not failed, and one line on stderr reports each pause:

```
API rate limit: throttled from 10:42:07 to 10:42:08 (1.02s), 12 refusal(s), 12 request(s) held back
```

A request gives up, with `API rate limit, gave up after 30s (10 attempts)`,
once it has been sent `max_attempts` times or would be held back for more than
`max_wait` in total:

```yaml
# config.yaml
api:
  retry:
    max_wait: 30s      # with a unit; 1s to 10m
    max_attempts: 10   # 1 to 100
```

With `max_attempts: 1` a refused request is not sent again and fails at once,
but the CLI still observes the pause: the requests that follow wait for it.
`max_wait` is also the longest a single refusal keeps all the requests of the
process waiting, whatever pause the server asks for. The line on stderr is
printed by the first request that succeeds after a pause, so a command whose
last request gives up prints its error only.

`retyc fs webdav serve` then answers its own client `429` with `Retry-After`.

## Reference

### Settings

| Setting                                                                                                                                                                            | `config.yaml` key                             | Environment variable                                              | Default                                                                                 |
|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------|-------------------------------------------------------------------|-----------------------------------------------------------------------------------------|
| API endpoint                                                                                                                                                                       | `api.base_url`                                | `RETYC_API_BASE_URL`                                              | `https://api.retyc.com`                                                                 |
| Listing pages fetched at once                                                                                                                                                      | `api.concurrency.list`                        | `RETYC_API_CONCURRENCY_LIST`                                      | `4`, see [below](#tune-parallel-requests)                                               |
| Chunks uploaded at once per file; also the files `fs mount` and `fs webdav serve` upload at once, all files together, and the deletes `fs mount --background-delete` sends at once | `api.concurrency.upload`                      | `RETYC_API_CONCURRENCY_UPLOAD`                                    | `4`                                                                                     |
| Chunks downloaded at once per file                                                                                                                                                 | `api.concurrency.download`                    | `RETYC_API_CONCURRENCY_DOWNLOAD`                                  | `4`                                                                                     |
| Acknowledge uploads before they are stored                                                                                                                                         | `api.unsafe_write`                            | `RETYC_API_UNSAFE_WRITE`                                          | `false`, see [below](#acknowledge-uploads-before-they-are-stored)                       |
| Longest wait on a rate-limited request (duration with a unit)                                                                                                                      | `api.retry.max_wait`                          | `RETYC_API_RETRY_MAX_WAIT`                                        | `30s` (`1s` to `10m`), see [below](#when-the-api-rate-limits-you)                       |
| Attempts at a rate-limited request                                                                                                                                                 | `api.retry.max_attempts`                      | `RETYC_API_RETRY_MAX_ATTEMPTS`                                    | `10` (`1`: a refused request is not sent again)                                         |
| Key cache                                                                                                                                                                          | `keyring.enabled`                             | `RETYC_KEYRING_ENABLED`                                           | `true` (Linux only)                                                                     |
| Key cache lifetime, seconds                                                                                                                                                        | `keyring.ttl`                                 | `RETYC_KEYRING_TTL`                                               | `60`                                                                                    |
| Organization API key                                                                                                                                                               | `admin.api_key`                               | `RETYC_ADMIN_API_KEY`                                             | —                                                                                       |
| Organization private key file                                                                                                                                                      | `admin.private_key_file`                      | `RETYC_ADMIN_PRIVATE_KEY_FILE`                                    | —                                                                                       |
| Admin API endpoint                                                                                                                                                                 | `admin.base_url`                              | `RETYC_ADMIN_BASE_URL`                                            | API endpoint + `/v1`                                                                    |
| Listing cache lifetime of `fs webdav serve` and `fs mount` (duration with a unit: `90s`, `2m`)                                                                                     | `cache.ttl`                                   | `RETYC_CACHE_TTL`                                                 | `1m`, see [RetycFS](retycfs.md#freshness)                                               |
| Expired listings served while refreshed (duration with a unit); **`fs webdav serve` only**, `fs mount` never serves an expired listing                                             | `cache.max_stale`                             | `RETYC_CACHE_MAX_STALE`                                           | `5m` (`0` disables)                                                                     |
| How long a name found missing is answered missing, `fs webdav serve` and `fs mount` (duration with a unit)                                                                         | `cache.negative_ttl`                          | `RETYC_CACHE_NEGATIVE_TTL`                                        | `1s` (`0` disables)                                                                     |
| Where `fs webdav serve` and `fs mount` keep listings and names looked up: `memory`, or `redis` to share them between instances                                                     | `cache.store`                                 | `RETYC_CACHE_STORE`                                               | `memory`, see [Shared metadata cache](retycfs.md#shared-metadata-cache-redis)           |
| Redis of `cache.store: redis`: a `redis://` or `rediss://` URL, **password included** (a secret: masked by `config show`, never logged)                                            | `cache.redis.url`                             | `RETYC_CACHE_REDIS_URL`                                           | — (required with `redis`)                                                               |
| Store in Redis the encrypted names the API sent, never the decrypted ones                                                                                                          | `cache.redis.high_confidentiality`            | `RETYC_CACHE_REDIS_HIGH_CONFIDENTIALITY`                          | `false`                                                                                 |
| WebDAV bind address                                                                                                                                                                | `webdav.addr`                                 | `RETYC_WEBDAV_ADDR`                                               | `127.0.0.1:8888`                                                                        |
| `fs mount`: how long the kernel keeps a name (duration with a unit)                                                                                                                | `mount.entry_ttl`                             | `RETYC_MOUNT_ENTRY_TTL`                                           | `0`: follows `cache.ttl`, see [RetycFS](retycfs.md#options)                             |
| `fs mount`: how long the kernel keeps the attributes of a file (duration with a unit)                                                                                              | `mount.attr_ttl`                              | `RETYC_MOUNT_ATTR_TTL`                                            | `0`: follows `cache.ttl`                                                                |
| `fs mount`: the kernel keeps what it read of a file between two opens                                                                                                              | `mount.kernel_cache`                          | `RETYC_MOUNT_KERNEL_CACHE`                                        | `true`                                                                                  |
| `fs mount`: a listing carries the attributes of its entries (FUSE READDIRPLUS): fewer requests to the mount, one inode held per entry listed                                       | `mount.readdir_plus`                          | `RETYC_MOUNT_READDIR_PLUS`                                        | `false`                                                                                 |
| `fs mount`: directory of the files being written, until they are sent                                                                                                              | `mount.spool_dir`                             | `RETYC_MOUNT_SPOOL_DIR`                                           | — (the system's temporary directory)                                                    |
| `fs mount`: let other users into the mount (`-o allow_other`)                                                                                                                      | `mount.allow_other`                           | `RETYC_MOUNT_ALLOW_OTHER`                                         | `false`                                                                                 |
| `fs mount`: user the files are presented as owned by                                                                                                                               | `mount.uid`                                   | `RETYC_MOUNT_UID`                                                 | `-1` (the user running the command)                                                     |
| `fs mount`: group the files are presented as owned by                                                                                                                              | `mount.gid`                                   | `RETYC_MOUNT_GID`                                                 | `-1` (the group running the command)                                                    |
| `fs mount`: permissions of a file that has none stored (octal, **quoted** in YAML)                                                                                                 | `mount.file_mode`                             | `RETYC_MOUNT_FILE_MODE`                                           | `"0644"`                                                                                |
| `fs mount`: permissions of a folder that has none stored (octal, **quoted** in YAML)                                                                                               | `mount.dir_mode`                              | `RETYC_MOUNT_DIR_MODE`                                            | `"0755"`                                                                                |
| `fs mount`: mount read-only                                                                                                                                                        | `mount.read_only`                             | `RETYC_MOUNT_READ_ONLY`                                           | `false`                                                                                 |
| `fs mount`: how long the files being sent are waited for when the mount is stopped (duration with a unit)                                                                          | `mount.drain_timeout`                         | `RETYC_MOUNT_DRAIN_TIMEOUT`                                       | `5m` (`0`: not at all)                                                                  |
| `fs mount`: take an API lock on a file while it is open for writing                                                                                                                | `mount.mirror_locks`                          | `RETYC_MOUNT_MIRROR_LOCKS`                                        | `false`, see [RetycFS](retycfs.md#locks)                                                |
| `fs mount`: answer the removal of a file at once and delete it at the API in the background                                                                                        | `mount.background_delete`                     | `RETYC_MOUNT_BACKGROUND_DELETE`                                   | `false`, see [RetycFS](retycfs.md#deleting-in-the-background)                           |
| `fs mount`: name patterns of the files kept local and never sent (editor swap and backup files)                                                                                    | `mount.local_files` (list of glob patterns)   | `RETYC_MOUNT_LOCAL_FILES` (space-separated; `none`: no such file) | `.*.swp`, `.*.swx`, `*~`, `4913`, see [RetycFS](retycfs.md#local-files)                 |
| `fs mount`: metrics and probes listener                                                                                                                                            | `mount.metrics.addr`                          | `RETYC_MOUNT_METRICS_ADDR`                                        | — (disabled), see [RetycFS](retycfs.md#metrics-and-probes)                              |
| `fs mount`: constant metric labels                                                                                                                                                 | `mount.metrics.labels` (list of `key=value`)  | `RETYC_MOUNT_METRICS_LABELS` (space-separated)                    | —                                                                                       |
| Config directory                                                                                                                                                                   | —                                             | `RETYC_CONFIG_DIR`                                                | see [above](#where-settings-live)                                                       |
| Environment file                                                                                                                                                                   | — (`--env-file`)                              | `RETYC_ENV_FILE`                                                  | — (none), see [above](#keep-the-secrets-in-an-environment-file-boot-mounts-systemd-csi) |
| Offline token                                                                                                                                                                      | *secret, environment only*                    | `RETYC_TOKEN`                                                     | stored login                                                                            |
| Key passphrase                                                                                                                                                                     | *secret, environment only*                    | `RETYC_KEY_PASSPHRASE`                                            | prompted                                                                                |
| WebDAV password                                                                                                                                                                    | *secret, environment only*                    | `RETYC_WEBDAV_PASSWORD`                                           | generated at startup                                                                    |
| Machine account: enrollment directory (`machine.json`, `client.key`, `age.key`); exclusive of `RETYC_TOKEN` and `RETYC_KEY_PASSPHRASE` | — | `RETYC_MACHINE_DIR` | — (user account) |
| Machine account: client ID (overrides `machine.json`) | — | `RETYC_CLIENT_ID` | from `machine.json` |
| Machine account: token endpoint (overrides `machine.json`) | — | `RETYC_TOKEN_ENDPOINT` | from `machine.json` |
| Machine account: signing key file | — | `RETYC_CLIENT_KEY_FILE` | `$RETYC_MACHINE_DIR/client.key` |
| Machine account: AGE key file | — | `RETYC_AGE_KEY_FILE` | `$RETYC_MACHINE_DIR/age.key` |

Machine account files must not be accessible to others (`0600` or `0440`;
symlinks are followed, so a mounted Kubernetes Secret with `defaultMode: 0440`
works). A missing variable or a bad mode exits with code 78.

Environment variables must carry the `RETYC_` prefix; an empty variable counts
as unset. Proxy and CA variables (`HTTPS_PROXY`, `SSL_CERT_FILE`, ...) are the
standard ones, [see above](#behind-a-corporate-proxy).

`webdav.cache.ttl` and `webdav.cache.max_stale` (`RETYC_WEBDAV_CACHE_TTL`,
`RETYC_WEBDAV_CACHE_MAX_STALE`) no longer exist: they are `cache.ttl` and
`cache.max_stale`. A config file or an environment that still carries one is
refused by every command, with the name of the replacement.

### Global flags

| Flag                | Description                                                                                                                                                                  |
|---------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--config <file>`   | Read another config file (the token stays in the config directory)                                                                                                           |
| `--env-file <file>` | Read `RETYC_*` variables from a file of mode `0600`; the environment wins over it (see [environment file](#keep-the-secrets-in-an-environment-file-boot-mounts-systemd-csi)) |
| `--debug`, `-d`     | Print every HTTP request and its response to stderr, with the proxy and CAs in use                                                                                           |
| `--json`            | Results as JSON on stdout, errors as `{"error": "..."}` on stderr (see [JSON output](commands.md#json-output))                                                               |

## Tracing (OpenTelemetry)

`retyc fs mount` can export traces to an OpenTelemetry collector over OTLP; no
other command traces (see [RetycFS](retycfs.md#traces) for the spans). It is off
unless an endpoint is set, and only the environment can turn it on: there is
no flag and no `config.yaml` key, so a workstation never exports anything by
accident.

```sh
OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318 retyc fs mount --all ~/dr
OTEL_EXPORTER_OTLP_PROTOCOL=grpc OTEL_EXPORTER_OTLP_ENDPOINT=collector:4317 retyc fs mount --all ~/dr
```

| Variable                                                            | Meaning                                                                                                                                             |
|---------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | Collector endpoint. Unset = tracing off (the OTel default of `localhost:4318` is deliberately not applied).                                         |
| `OTEL_EXPORTER_OTLP_PROTOCOL`, `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` | `http/protobuf` (default) or `grpc`. Another value disables tracing with a message under `--debug`.                                                 |
| `OTEL_SDK_DISABLED`                                                 | `true` turns tracing off even with an endpoint.                                                                                                     |
| `TRACEPARENT`, `TRACESTATE`                                         | W3C trace context of the caller; the startup span of the mount becomes its child, each operation is then a new trace. |
| `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES`                     | Resource; `service.name` defaults to `retycfs`, `service.version` is the CLI version.                                                                |
| `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG`                    | Sampling, e.g. `parentbased_traceidratio` / `0.1` for a busy mount.                                                                         |
| Other `OTEL_EXPORTER_OTLP_*`                                        | Headers, TLS certificate, compression, timeout: standard OTLP exporter settings.                                                                    |

Under `--debug`, exporter failures are printed to stderr and may include the
collector URL, and a malformed `OTEL_EXPORTER_OTLP_HEADERS` is echoed by the
SDK's own logger, so do not put credentials in the endpoint and keep
`--debug` off a shared terminal when the headers carry a token.

For a local look, `scripts/start-jaeger.sh` runs Jaeger with OTLP on
`4318` (HTTP) and `4317` (gRPC) and the UI on `http://localhost:16686`.

Traces are flushed at the unmount with a 2 s bound; a collector that is down never
fails the mount. Spans carry methods, status codes, sizes, counts, durations,
normalized API routes and identifiers. They never carry file or folder names,
dataroom titles, request bodies, headers or error messages:
those are what the end-to-end encryption protects.

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
