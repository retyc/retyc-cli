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
| `RETYC_CONFIG_DIR`     | Override the config directory                                               |
| `RETYC_TOKEN`          | Offline refresh token (bypasses disk credentials — see [CI / CD](ci-cd.md)) |
| `RETYC_KEY_PASSPHRASE` | AGE key passphrase (bypasses interactive prompt — see [CI / CD](ci-cd.md))  |

## config.yaml

Create `config.yaml` in the config directory to override defaults:

```yaml
api:
  base_url: https://api.retyc.com

insecure: true  # dev builds only — skip TLS verification persistently
```

## Global flags

| Flag              | Short | Description                                                                                                           |
|-------------------|-------|-----------------------------------------------------------------------------------------------------------------------|
| `--config <file>` |       | Use a specific config file                                                                                            |
| `--insecure`      | `-k`  | Skip TLS certificate verification *(dev builds only — can be set persistently via `insecure: true` in `config.yaml`)* |
| `--debug`         |       | Enable debug mode                                                                                                     |
