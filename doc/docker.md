# Docker

Config and tokens are persisted in a named volume. The `-it` flags are required for interactive prompts (device flow, passphrase).

```sh
# Authenticate
docker run -it --rm -v retyc-config:/home/retyc/.config/retyc retyc/retyc-cli:latest auth login

# Send / list / download (mount current directory for file access)
docker run -it --rm \
  -v retyc-config:/home/retyc/.config/retyc \
  -v "$(pwd)":/data \
  retyc/retyc-cli:latest transfer create /data/report.pdf
```

> **Tip:** `alias retyc='docker run -it --rm -v retyc-config:/home/retyc/.config/retyc -v "$(pwd)":/data retyc/retyc-cli:latest'`

> **Note:** kernel keyring caching is not available in Docker (blocked by the default seccomp profile). The passphrase will be prompted on each invocation.

## Images

```sh
# Docker Hub
docker pull retyc/retyc-cli:latest
# GitHub Container Registry
docker pull ghcr.io/retyc/retyc-cli:latest
```
