# CI / CD

`retyc-cli` can run fully non-interactively for authentication and key-unlock flows in pipelines. Set the following
environment variables to avoid credential and key passphrase prompts:

| Variable               | Description                                                                           |
|------------------------|---------------------------------------------------------------------------------------|
| `RETYC_TOKEN`          | Offline refresh token used instead of reading credentials from disk                   |
| `RETYC_KEY_PASSPHRASE` | Passphrase for your AGE private key, used instead of an interactive passphrase prompt |

> **Note:** Other interactive prompts (for example, transfer confirmation unless you pass `-y`) may still appear and
> must be disabled using the appropriate CLI flags when running in CI.

## Setup (one-time, on your machine)

```sh
# Authenticate and print an offline token
retyc auth login --offline
```

Copy the printed token and store it as a secret in your CI provider alongside your key passphrase.

## Usage in a pipeline

```sh
export RETYC_TOKEN=<offline_token>
export RETYC_KEY_PASSPHRASE=<key_passphrase>

# Send build artifacts
retyc transfer create -y --title "Release v1.2.3" ./dist/app.tar.gz

# Download a transfer
retyc transfer download -y <transfer-id>
```

The offline token is a long-lived refresh token. At each invocation the CLI exchanges it for a short-lived access
token — nothing is written to disk.
