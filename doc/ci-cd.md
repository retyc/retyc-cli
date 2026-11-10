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
