# WebDAV Server

`retyc-cli` runs as a local **WebDAV server** that exposes your Retyc datarooms as a
mountable network drive. Browse, open, upload, rename and delete dataroom files from
Finder, Windows Explorer, your file manager, or any WebDAV client — with the same
end-to-end post-quantum encryption as the rest of the CLI.

Files are encrypted and decrypted **locally** by the CLI. The Retyc servers never see
plaintext; only your machine holds the decrypted data while the server is running.

## Quick start

```sh
# The key passphrase is required (never prompted in server mode)
read -rs RETYC_KEY_PASSPHRASE
export RETYC_KEY_PASSPHRASE

# Start the server on localhost:8888
retyc webdav serve
```

Then mount `http://localhost:8888` in your WebDAV client. Your datarooms appear under
the `/dataroom` folder.

## Requirements

- You must be authenticated first: `retyc auth login`.
- `RETYC_KEY_PASSPHRASE` **must** be set — the server never prompts interactively.
  It is used to unlock your AGE identity for decrypting/encrypting file contents.

## Command

```
retyc webdav serve [flags]
```

| Flag           | Short | Default     | Description                                                        |
|----------------|-------|-------------|--------------------------------------------------------------------|
| `--port`       | `-p`  | `8888`      | Port to listen on                                                  |
| `--addr`       |       | `127.0.0.1` | Address to bind (`127.0.0.1` = local only)                         |
| `--auth`       |       | `false`     | Require HTTP Basic authentication                                  |

### Environment variables

| Variable                | Required        | Description                                                        |
|-------------------------|-----------------|--------------------------------------------------------------------|
| `RETYC_KEY_PASSPHRASE`  | yes             | Passphrase that unlocks your AGE identity (no interactive prompt)  |
| `RETYC_WEBDAV_PASSWORD` | with `--auth`   | Basic-auth password. If unset while `--auth` is on, one is generated and printed at startup |

## Layout

The server exposes a virtual filesystem:

```
/
└── dataroom/
    ├── Project Alpha/        ← one folder per dataroom (its title)
    │   ├── report.pdf
    │   └── contracts/
    │       └── nda.pdf
    └── Release v2/
        └── dist/
            └── retyc
```

- Each dataroom appears as a folder named after its **title**.
- If two datarooms share the same title, the second gets a numeric suffix
  (`Project Alpha`, `Project Alpha (2)`, …). The mapping is stable across refreshes,
  so a bookmarked path always points to the same dataroom.
- The `/dataroom` prefix namespaces the tree; other element types may be added at the
  root in the future.

## Supported operations

| Action              | WebDAV method | Notes                                                     |
|---------------------|---------------|-----------------------------------------------------------|
| List / browse       | `PROPFIND`    | Names, sizes and MIME types are decrypted on the fly      |
| Read / download     | `GET`         | Streamed and decrypted locally; supports range requests   |
| Upload / overwrite  | `PUT`         | Encrypted locally, then chunked to the dataroom           |
| Create folder       | `MKCOL`       | `mkdir` inside a dataroom                                  |
| Delete              | `DELETE`      | Removes a node (or a folder and its contents)             |
| Rename / move       | `MOVE`        | Within the **same** dataroom only                         |
| Copy                | `COPY`        | **Not supported** — the dataroom API has no server-side copy (returns `501`) |

Notes and limitations:

- **Move is intra-dataroom only.** Moving a node from one dataroom to another is
  rejected. To relocate across datarooms, download then upload.
- **Copy is unavailable.** Many clients implement a drag-copy as `COPY`; if yours fails,
  download the file and re-upload it instead.
- **Uploading an existing name** creates a new **version** of that node rather than a
  duplicate.
- **File names containing `/`** cannot be represented as a single path component and are
  skipped from listings (a warning is printed to stderr).
- Listings and dataroom sessions are cached briefly (30 s / 30 min respectively);
  mutations made through the server invalidate the relevant cache immediately, but
  changes made elsewhere (web app, another client) may take up to a minute to appear.

## Authentication (`--auth`)

By default the server binds to `127.0.0.1` and serves **without** HTTP authentication —
appropriate for a local-only mount. Anyone able to reach the port can read your
decrypted dataroom contents, so if you bind to a non-loopback address you should enable
`--auth`. A warning is printed when you bind to a public interface without it.

```sh
# Generate a random password (printed once at startup)
retyc webdav serve --auth

# Or provide your own
RETYC_WEBDAV_PASSWORD='choose-a-strong-password' retyc webdav serve --auth
```

- Username is always `retyc`.
- Credentials are compared in constant time.
- Startup prints the credentials to stderr (either the generated password, or a note
  that the password came from `RETYC_WEBDAV_PASSWORD`).

## Mounting

### macOS (Finder)

Finder → **Go → Connect to Server…** (`⌘K`) → enter `http://localhost:8888` →
**Connect**. With `--auth`, use username `retyc` and your password.

### Windows (Explorer)

**This PC → Map network drive… → Folder:** `http://localhost:8888` → **Finish**.
> Windows may refuse Basic auth over plain HTTP by default. For a local mount, run
> without `--auth`, or place the server behind an HTTPS reverse proxy.

### Linux — GNOME Files (Nautilus)

**Other Locations → Connect to Server:** `dav://localhost:8888` → **Connect**.

### Linux — command line (`davfs2`)

```sh
sudo mount -t davfs http://localhost:8888 /mnt/retyc
```

### Generic clients

Any client (Cyberduck, rclone, `cadaver`, …) can connect to `http://localhost:8888`.

```sh
# rclone example
rclone config create retyc webdav url http://localhost:8888 vendor other
rclone ls retyc:/dataroom
```

## Lifecycle & auth expiry

- The server keeps your access token warm by refreshing it in the background.
- If the **refresh token expires**, the server shuts down gracefully (draining any
  in-flight uploads) and exits with a message. Run `retyc auth login` and restart it.
- `Ctrl-C` (SIGINT) or SIGTERM triggers a graceful shutdown: in-flight uploads finish,
  temporary files are cleaned up, and any orphaned node from a failed upload is removed.

## Security notes

- File **contents and metadata** (names, MIME types, sizes) are encrypted end-to-end;
  the server decrypts them only in memory / temporary files on your machine.
- The WebDAV protocol itself is **plaintext HTTP**. Keep the bind address on
  `127.0.0.1` for local use. If you must expose it on a network, put it behind an
  HTTPS-terminating reverse proxy **and** enable `--auth`.
- `RETYC_KEY_PASSPHRASE` and `RETYC_WEBDAV_PASSWORD` are read from the environment —
  prefer `read -rs` over inline assignment to keep them out of your shell history.

## Example session

```sh
read -rs RETYC_KEY_PASSPHRASE
export RETYC_KEY_PASSPHRASE

# Local, authenticated server on a custom port
RETYC_WEBDAV_PASSWORD='s3cret' retyc webdav serve --port 9000 --auth
# → WebDAV server listening on http://127.0.0.1:9000
# → WebDAV auth enabled: user "retyc", password from RETYC_WEBDAV_PASSWORD

# In another terminal / your file manager:
#   mount http://localhost:9000  (user retyc / s3cret)
#   open  /dataroom/Project Alpha/report.pdf
```
