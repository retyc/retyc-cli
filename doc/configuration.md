# Configuration

Credentials and config are stored in a platform-specific directory:

| Build                     | Config directory                   |
|---------------------------|------------------------------------|
| Production (`-tags prod`) | `~/.config/retyc/` (XDG Base Dir)  |
| Development (default)     | `.retyc/` in the current directory |

Override at any time:

```sh
export RETYC_CONFIG_DIR=/path/to/config
```

## Environment variables

Every configuration key is settable from the environment: the key `a.b` is read
from `RETYC_A_B`. The `RETYC_` prefix is mandatory — an unprefixed variable is
ignored.

Precedence is **flag > environment > config file > built-in default**. An empty
variable counts as unset, not as an empty value.

| Variable | Config key | Description |
|---|---|---|
| `RETYC_API_BASE_URL` | `api.base_url` | REST API base URL |
| `RETYC_INSECURE` | `insecure` | Skip TLS verification *(dev builds only)* |
| `RETYC_KEYRING_ENABLED` | `keyring.enabled` | Cache the decrypted AGE identity in the kernel keyring |
| `RETYC_KEYRING_TTL` | `keyring.ttl` | Keyring cache lifetime, in seconds |
| `RETYC_ADMIN_API_KEY` | `admin.api_key` | Organization API key for `retyc admin` (see below) |
| `RETYC_ADMIN_PRIVATE_KEY_FILE` | `admin.private_key_file` | Path to the organization private key file (see below) |
| `RETYC_ADMIN_BASE_URL` | `admin.base_url` | Admin API base URL |

These four have **no config key on purpose** — they carry secrets, or are read
before the config file is located, and must never be written to disk in clear
text:

| Variable | Description |
|---|---|
| `RETYC_CONFIG_DIR` | Override the config directory |
| `RETYC_TOKEN` | Offline refresh token (bypasses disk credentials — see [CI / CD](ci-cd.md)) |
| `RETYC_KEY_PASSPHRASE` | AGE key passphrase (bypasses the interactive prompt — see [CI / CD](ci-cd.md)) |
| `RETYC_WEBDAV_PASSWORD` | Basic-auth password for `retyc webdav serve --auth` (see [WebDAV](webdav.md)) |

The following follow the usual OpenSSL and curl conventions and are therefore
not prefixed:

| Variable | Description |
|---|---|
| `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` | Proxy settings (see [Proxy and custom CAs](#proxy-and-custom-cas)) |
| `SSL_CERT_FILE` / `SSL_CERT_DIR` | Additional trusted root CAs (see [Proxy and custom CAs](#proxy-and-custom-cas)) |

Inspect what the CLI actually resolved with:

```sh
retyc config show      # effective value of every key, secrets masked
retyc config path      # config directory, config file and token file in use
```

## Proxy and custom CAs

The CLI follows the usual OpenSSL and curl conventions — no RETYC-specific
variable is involved.

### Proxy

| Variable      | Description                                                                     |
|---------------|-----------------------------------------------------------------------------------|
| `HTTPS_PROXY` | Proxy used for `https://` requests, which is what every RETYC endpoint uses      |
| `HTTP_PROXY`  | Proxy used for plain `http://` requests                                          |
| `NO_PROXY`    | Comma-separated hosts, domains (`.corp.example`) or CIDRs that bypass the proxy  |

Lower-case variants (`https_proxy`, ...) work too. Supported schemes are
`http://`, `https://` and `socks5://`, and credentials can be embedded in the
URL:

```sh
export HTTPS_PROXY=http://user:password@proxy.corp.example:3128
export NO_PROXY=localhost,127.0.0.1,.internal.example
```

`ALL_PROXY` is **not** supported — the Go standard library ignores it.

### Custom root CAs

A TLS-inspecting proxy presents certificates signed by a private CA. Point
`SSL_CERT_FILE` at that CA bundle, or `SSL_CERT_DIR` at a directory of PEM
files (several directories can be listed, separated by `:` on Unix and `;` on
Windows):

```sh
export SSL_CERT_FILE=/etc/ssl/corp/proxy-ca.pem
```

These CAs are **added** to the system trust store, not substituted for it, so
publicly signed certificates keep validating. Files in `SSL_CERT_DIR` that
hold no certificate are ignored, as OpenSSL does.

The bundle is loaded and validated when the command starts, so a missing file
or one holding no certificate fails immediately with a clear message rather
than as a TLS error in the middle of a transfer. Commands that open no
connection (`retyc version`, `retyc mcp manifest`) are exempt.

Use `--debug` to see which proxy each request goes through (credentials are
redacted) and where the root CAs came from:

```
TLS roots: system + SSL_CERT_FILE=/etc/ssl/corp/proxy-ca.pem
> GET https://api.retyc.com/login/config/public (via proxy http://user:xxxxx@proxy.corp.example:3128)
```

As a last resort, `--insecure` / `-k` skips certificate verification entirely.

## config.yaml

Create `config.yaml` in the config directory to override defaults:

```yaml
api:
  base_url: https://api.retyc.com

keyring:
  enabled: true   # cache the decrypted AGE identity in the Linux kernel keyring
  ttl: 60         # cache lifetime, in seconds

insecure: true    # dev builds only — skip TLS verification persistently
```

`--config <file>` selects the config **file** only. The credentials directory is
unchanged, so `token.json` is still read from and written to the default config
directory — use `RETYC_CONFIG_DIR` to move both.

## Admin (organization API)

`retyc admin` commands administer the organization through the public API
and authenticate separately from the regular `retyc auth login` OIDC flow.

```yaml
admin:
  api_key: ryc_...                              # organization API key
  private_key_file: /path/to/organization.key     # organization AGE identity
  base_url: https://api.retyc.com/v1            # optional, defaults to <api.base_url>/v1
```

| Key / variable                                          | Description                                                                 |
|-----------------------------------------------------------|-------------------------------------------------------------------------------|
| `admin.api_key` / `RETYC_ADMIN_API_KEY`                   | Organization API key (`ryc_...`), created from the dashboard. Required by every `retyc admin` command. |
| `admin.private_key_file` / `RETYC_ADMIN_PRIVATE_KEY_FILE` | Path to the organization private key file. Only required by commands that decrypt content or rekey (`admin dataroom nodes/download/rekey/user rm`, `admin transfer rekey`). |
| `admin.base_url`                                          | Admin API base URL. Defaults to `<api.base_url>` with `/v1` appended.        |

The private key file holds a single AGE post-quantum identity
(`AGE-SECRET-KEY-PQ-1...`), in the same plain-text format produced by
`age-keygen` or downloaded from the dashboard. Blank lines and lines starting
with `#` are ignored, so the standard `age-keygen`-generated file — with its
`# created:` / `# public key:` comment header — can be used as-is. A legacy
X25519 identity (`AGE-SECRET-KEY-1...`) is rejected: only post-quantum keys
are supported. This file never leaves the local machine — it is not sent to
the API and is not cached in the keyring.

## Global flags

| Flag              | Short | Description                                                                                                           |
|-------------------|-------|-----------------------------------------------------------------------------------------------------------------------|
| `--config <file>` |       | Use a specific config file (does **not** move `token.json` — see above)                                               |
| `--insecure`      | `-k`  | Skip TLS certificate verification *(dev builds only — can be set persistently via `insecure: true` in `config.yaml`)* |
| `--debug`         | `-d`  | Print every HTTP request and its raw response to stderr, along with the proxy and root CAs in use                     |
| `--json`          |       | Print results as JSON on stdout, errors as `{"error": "..."}` on stderr (see [JSON output](commands.md#json-output))  |
