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

| Variable               | Description                                                                 |
|------------------------|-----------------------------------------------------------------------------|
| `RETYC_CONFIG_DIR`         | Override the config directory                                               |
| `RETYC_TOKEN`              | Offline refresh token (bypasses disk credentials — see [CI / CD](ci-cd.md)) |
| `RETYC_KEY_PASSPHRASE`     | AGE key passphrase (bypasses interactive prompt — see [CI / CD](ci-cd.md))  |
| `RETYC_ADMIN_API_KEY`      | Organization API key for `retyc admin` commands (see below)                |
| `RETYC_ADMIN_PRIVATE_KEY_FILE` | Path to the organization private key file (see below)          |

## config.yaml

Create `config.yaml` in the config directory to override defaults:

```yaml
api:
  base_url: https://api.retyc.com

insecure: true  # dev builds only — skip TLS verification persistently
```

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
| `--config <file>` |       | Use a specific config file                                                                                            |
| `--insecure`      | `-k`  | Skip TLS certificate verification *(dev builds only — can be set persistently via `insecure: true` in `config.yaml`)* |
| `--debug`         |       | Enable debug mode                                                                                                     |
| `--json`          |       | Print results as JSON on stdout, errors as `{"error": "..."}` on stderr (see [JSON output](commands.md#json-output))  |
