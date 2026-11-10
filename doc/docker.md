# Docker

Config and token live in a named volume; `-it` is needed for the prompts (login, passphrase).

```sh
# Authenticate
docker run -it --rm -v retyc-config:/home/retyc/.config/retyc retyc/retyc-cli:latest auth login

# Send / list / download (mount current directory for file access)
docker run -it --rm \
  -v retyc-config:/home/retyc/.config/retyc \
  -v "$(pwd)":/data \
  retyc/retyc-cli:latest transfer create /data/report.pdf
```

Tip: `alias retyc='docker run -it --rm -v retyc-config:/home/retyc/.config/retyc -v "$(pwd)":/data retyc/retyc-cli:latest'`.
There is no key cache in Docker: the passphrase is asked at each run.

## Mounting a dataroom from the container

See [RetycFS: containers](retycfs.md#containers) (root, `/dev/fuse`, `CAP_SYS_ADMIN`).

## Behind a proxy

The image is `FROM scratch`: mount a custom CA bundle into it (see
[Configuration](configuration.md#behind-a-corporate-proxy)).

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

Images (except the dev one) are signed with [cosign](https://docs.sigstore.dev/), SBOM and
provenance included:

```sh
cosign verify \
  --certificate-identity 'https://github.com/retyc/retyc-cli/.github/workflows/_docker.yml@refs/tags/vX.Y.Z' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  retyc/retyc-cli:vX.Y.Z
```

## Dev image

`ghcr.io/retyc/retyc-cli-dev` is built without the `prod` tag (dev API default,
`--insecure` available), for `linux/amd64` only and on GitHub Container Registry only.
Tags: `vX.Y.Z` (each release, pre-releases included, never `latest`), `master` (head of
the branch) and `commit-<sha>` (manual run). Locally:
`docker build --build-arg BUILD_TAGS= --build-arg VERSION=v0.0.0-dev .`
