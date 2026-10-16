# Docker

Config and tokens are persisted in a named volume. The `-it` flags are required for interactive prompts (device flow,
passphrase).

```sh
# Authenticate
docker run -it --rm -v retyc-config:/home/retyc/.config/retyc retyc/retyc-cli:latest auth login

# Send / list / download (mount current directory for file access)
docker run -it --rm \
  -v retyc-config:/home/retyc/.config/retyc \
  -v "$(pwd)":/data \
  retyc/retyc-cli:latest transfer create /data/report.pdf
```

> **Tip:**
`alias retyc='docker run -it --rm -v retyc-config:/home/retyc/.config/retyc -v "$(pwd)":/data retyc/retyc-cli:latest'`

> **Note:** kernel keyring caching is not available in Docker (blocked by the default seccomp profile). The passphrase
> will be prompted on each invocation.

## Mounting a dataroom from the container

`retyc fs mount` needs `/dev/fuse`, `CAP_SYS_ADMIN` and root (`--user 0`): the image has
no `fusermount3` helper, root mounts without it. See
[RetycFS: containers](retycfs.md#containers).

## Behind a proxy

Proxy and CA settings are read from the environment (see
[Configuration](configuration.md#behind-a-corporate-proxy)). The image is built
`FROM scratch`, so a custom CA bundle has to be mounted into the container:

```sh
docker run -it --rm \
  -e HTTPS_PROXY -e NO_PROXY \
  -e SSL_CERT_FILE=/etc/ssl/corp-ca.pem \
  -v /etc/ssl/corp/proxy-ca.pem:/etc/ssl/corp-ca.pem:ro \
  -v retyc-config:/home/retyc/.config/retyc \
  retyc/retyc-cli:latest auth login
```

## Images

```sh
# Docker Hub
docker pull retyc/retyc-cli:latest
# GitHub Container Registry
docker pull ghcr.io/retyc/retyc-cli:latest
```

| Tag            | Content                                                                                    |
|----------------|--------------------------------------------------------------------------------------------|
| `latest`       | Latest stable release                                                                      |
| `vX.Y.Z`       | That release; pre-releases (`vX.Y.Z-rc1`, `-beta1`) are published under their own tag only |
| `master`       | Head of the `master` branch, not released — for testing only                               |
| `commit-<sha>` | One-off build of a single commit, GitHub Container Registry only — for testing only        |

## Dev image

`ghcr.io/retyc/retyc-cli-dev` is built without the `prod` tag (dev API default,
`--insecure` available), for `linux/amd64` only and on GitHub Container Registry only.
Tags: `master` (head of the branch) and `commit-<sha>` (manual run). Locally:
`docker build --build-arg BUILD_TAGS= --build-arg VERSION=v0.0.0-dev .`
