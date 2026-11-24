# CI / CD

Once, on your machine, get an offline token and store it as a CI secret with your key
passphrase:

```sh
retyc auth login --offline
```

In the pipeline:

```sh
export RETYC_TOKEN=<offline_token>
export RETYC_KEY_PASSPHRASE=<key_passphrase>

retyc transfer create -y --title "Release v1.2.3" ./dist/app.tar.gz
retyc transfer download -y <transfer-id>
```

Pass `-y` to commands that ask for confirmation. The token is exchanged for a short-lived
access token at each run; nothing is written to disk.

## Releasing retyc-cli (maintainers)

The repository holds two Go modules: the CLI and `github.com/retyc/retyc-cli/core`
(`core/`, the library an rclone backend imports). The CLI's `go.mod` replaces the core
with `./core`. A release needs only the `vX.Y.Z` tag: `release.yml` tags the same commit
`core/vX.Y.Z` (the core always follows the CLI's version). `core/v*` tags start no workflow,
and build versions only come from `v*` tags. From v2 on, Go requires the core's module path
to end in `/v2` (`core/go.mod` and every import).
