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

or `RETYC_API_UNSAFE_WRITE=true`, or `retyc webdav serve --unsafe-write`.

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

## Reference

### Settings

| Setting | `config.yaml` key | Environment variable | Default |
|---|---|---|---|
| API endpoint | `api.base_url` | `RETYC_API_BASE_URL` | `https://api.retyc.com` |
| Listing pages fetched at once | `api.concurrency.list` | `RETYC_API_CONCURRENCY_LIST` | `4`, see [below](#tune-parallel-requests) |
| Chunks uploaded at once per file | `api.concurrency.upload` | `RETYC_API_CONCURRENCY_UPLOAD` | `4` |
| Chunks downloaded at once per file | `api.concurrency.download` | `RETYC_API_CONCURRENCY_DOWNLOAD` | `4` |
| Acknowledge uploads before they are stored | `api.unsafe_write` | `RETYC_API_UNSAFE_WRITE` | `false`, see [below](#acknowledge-uploads-before-they-are-stored) |
| Key cache | `keyring.enabled` | `RETYC_KEYRING_ENABLED` | `true` (Linux only) |
| Key cache lifetime, seconds | `keyring.ttl` | `RETYC_KEYRING_TTL` | `60` |
| Organization API key | `admin.api_key` | `RETYC_ADMIN_API_KEY` | — |
| Organization private key file | `admin.private_key_file` | `RETYC_ADMIN_PRIVATE_KEY_FILE` | — |
| Admin API endpoint | `admin.base_url` | `RETYC_ADMIN_BASE_URL` | API endpoint + `/v1` |
| WebDAV bind address | `webdav.addr` | `RETYC_WEBDAV_ADDR` | `127.0.0.1:8888` |
| WebDAV listing cache lifetime (duration with a unit: `90s`, `2m`) | `webdav.cache.ttl` | `RETYC_WEBDAV_CACHE_TTL` | `1m`, see [WebDAV](webdav.md#caching) |
| WebDAV expired listings served while refreshed (duration with a unit) | `webdav.cache.max_stale` | `RETYC_WEBDAV_CACHE_MAX_STALE` | `5m` (`0` disables) |
| WebDAV metrics and probes listener | `webdav.metrics.addr` | `RETYC_WEBDAV_METRICS_ADDR` | — (disabled), see [WebDAV](webdav.md#metrics-probes-and-traces) |
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

## Tracing (OpenTelemetry)

The CLI can export traces to an OpenTelemetry collector over OTLP. It is off
unless an endpoint is set, and only the environment can turn it on: there is
no flag and no `config.yaml` key, so a workstation never exports anything by
accident.

```sh
OTEL_EXPORTER_OTLP_ENDPOINT=http://collector:4318 retyc dataroom ls
OTEL_EXPORTER_OTLP_PROTOCOL=grpc OTEL_EXPORTER_OTLP_ENDPOINT=collector:4317 retyc dataroom ls
```

| Variable | Meaning |
|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | Collector endpoint. Unset = tracing off (the OTel default of `localhost:4318` is deliberately not applied). |
| `OTEL_EXPORTER_OTLP_PROTOCOL`, `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` | `http/protobuf` (default) or `grpc`. Another value disables tracing with a message under `--debug`. |
| `OTEL_SDK_DISABLED` | `true` turns tracing off even with an endpoint. |
| `TRACEPARENT`, `TRACESTATE` | W3C trace context of the caller; the command span becomes its child. For `webdav serve` only the startup span is, each request is then a new trace. |
| `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES` | Resource; `service.name` defaults to `retyc-cli`, `service.version` is the CLI version. |
| `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG` | Sampling, e.g. `parentbased_traceidratio` / `0.1` for a busy WebDAV server. |
| Other `OTEL_EXPORTER_OTLP_*` | Headers, TLS certificate, compression, timeout: standard OTLP exporter settings. |

Under `--debug`, exporter failures are printed to stderr and may include the
collector URL, and a malformed `OTEL_EXPORTER_OTLP_HEADERS` is echoed by the
SDK's own logger, so do not put credentials in the endpoint and keep
`--debug` off a shared terminal when the headers carry a token.

For a local look, `scripts/start-jaeger.sh` runs Jaeger with OTLP on
`4318` (HTTP) and `4317` (gRPC) and the UI on `http://localhost:16686`.

Traces are flushed at exit with a 2 s bound; a collector that is down never
fails a command. Spans carry methods, status codes, sizes, counts, durations,
normalized API routes and identifiers. They never carry file or folder names,
dataroom titles, command arguments, request bodies, headers or error messages:
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
