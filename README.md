# RPM-Serve

This is a dumb project that only exists because I couldn't find it elsewhere.

Given a folder of RPM packages, this serves over http a repository for dnf to install these packages. Including the http index pages for manual browsing.

This exists purely because some vendors (aws) refuse to provide respositories and instead want us to manually load their trust-me-bro rpm files.

The usecase is that this runs in a container, you mount in your RPM folder as read-only.
You also provide a gpg key, and the server signs the packages with it on the fly (if you want).

## Running

CI (`.github/workflows/container.yml`) publishes images to `ghcr.io/<owner>/rpm-server`. Each image is tagged with the `Cargo.toml` version and `sha-<commit>`, and pushes to `main` also update `latest`. To release, bump the version in `Cargo.toml` and push a matching `v<version>` tag.

To build the image locally:

```sh
podman build --format docker -t rpm-server -f Containerfile .

# Unsigned: packages are served exactly as they are on disk.
podman run -d -p 8080:8080 -v ./rpms:/srv/rpms:ro,Z rpm-server

# Signed: repomd.xml and every package are signed with your key.
# key.asc and passphrase.txt: see "Creating a signing key" below.
podman secret create rpm-key key.asc
podman secret create rpm-key-pass passphrase.txt
podman run -d -p 8080:8080 -v ./rpms:/srv/rpms:ro,Z \
  --secret rpm-key,uid=65532,mode=0400 --secret rpm-key-pass,uid=65532,mode=0400 \
  -e RPM_SERVER_GPG_KEY=/run/secrets/rpm-key \
  -e RPM_SERVER_GPG_PASSPHRASE_FILE=/run/secrets/rpm-key-pass \
  rpm-server
```

The container runs as uid 65532, so the mounted RPMs must be world-readable.

The repository root contains:

- `static/`: the RPMs from the mounted folder, keeping its subfolder layout
- `downloaded/`: RPMs fetched from online sources (see below)
- `repodata/`: the generated metadata
- `RPM-GPG-KEY` and `<repo-id>.repo`

`GET /healthz` returns `200 ok packages=N revision=R`, or `503` with the error if the last rescan failed (for example, the package folder became unreadable). The image runs `rpm-server --healthcheck` against it every 30 seconds, with a 5-minute start period so a long initial scan doesn't count as a failure. Check the status with `podman healthcheck run <container>` or `podman ps`. `--format docker` is needed because OCI-format images have no `HEALTHCHECK`.

New, changed or removed RPMs are noticed via inotify and served about 2 seconds after writes stop. inotify doesn't see changes made by other hosts on NFS/SMB mounts; those are picked up by the hourly full rescan (`RPM_SERVER_RESCAN_INTERVAL`).

### Creating a signing key

If you already have a key, export it with `gpg --armor --export-secret-keys KEYID > key.asc` and put its passphrase in `passphrase.txt`. Otherwise create a dedicated one:

```sh
# Use a separate keyring so the repo key stays out of your personal one.
export GNUPGHOME="$PWD/repo-gnupg"
mkdir -m 700 "$GNUPGHOME"

# The first line of this file is the key passphrase.
# Write it with an editor instead to keep it out of your shell history.
printf '%s\n' 'choose-a-passphrase' > passphrase.txt
chmod 600 passphrase.txt

# RSA 4096, signing only, no expiry. RSA is verifiable on every client, including EL7 / Amazon Linux 2.
gpg --batch --pinentry-mode loopback --passphrase-file passphrase.txt \
  --quick-gen-key 'My Repo Signing Key <repo@example.com>' rsa4096 sign never

# Export the secret key for rpm-server.
gpg --batch --pinentry-mode loopback --passphrase-file passphrase.txt \
  --armor --export-secret-keys repo@example.com > key.asc
chmod 600 key.asc
```

Drop the `--batch --pinentry-mode loopback --passphrase-file passphrase.txt` options to be prompted for the passphrase instead.

You don't need to export the public key. The server derives it from `key.asc` and serves it at `/RPM-GPG-KEY`.

Back up `key.asc`, the passphrase, and the revocation certificate gpg writes to `$GNUPGHOME/openpgp-revocs.d/`. Clients only trust the key they imported, so if you replace the key, every client has to import the new one.

### Online sources

Some vendors publish an RPM at a fixed "latest" URL; others attach RPMs to GitHub releases. List the URLs in a file, one per line (`#` starts a comment):

```text
# AWS Session Manager plugin
https://s3.amazonaws.com/session-manager-downloads/plugin/latest/linux_64bit/session-manager-plugin.rpm

# GitHub CLI: every .rpm attached to the latest release
https://github.com/cli/cli
```

A GitHub project URL (`https://github.com/<owner>/<repo>`, optionally ending in `.git`, `/releases` or `/releases/latest`) is resolved on each run to the release marked "Latest" on GitHub (drafts and pre-releases are skipped). All of its `.rpm` assets are then downloaded, every architecture included; dnf installs the one matching the client. Any other URL, including a direct link to a release asset, is downloaded as a single RPM.

Give the server that file and a writable folder:

```sh
podman run -d -p 8080:8080 -v ./rpms:/srv/rpms:ro,Z \
  -v ./sources.list:/etc/rpm-server/sources.list:ro,Z \
  -v rpm-downloads:/var/lib/rpm-server:U \
  -e RPM_SERVER_SOURCES_FILE=/etc/rpm-server/sources.list \
  -e RPM_SERVER_DOWNLOAD_DIR=/var/lib/rpm-server \
  rpm-server
```

`:U` gives the container user ownership of the volume so it can write there.

How downloads work:

- **Schedule:** every URL is fetched at startup and then every 24 hours (`RPM_SERVER_UPDATE_INTERVAL`). The sources file is re-read on each run.
- **Change check:** content is compared by SHA-256 against the last download from that URL. The server also sends the ETag back, so an unchanged file usually isn't downloaded again.
- **Storage:** changed content is checked to be a valid RPM and saved as `name-version-release.arch.rpm`. Older versions are kept, so clients can still downgrade.
- **Serving:** downloaded packages appear under `/downloaded/` and in the repo metadata (signed like the others when a key is configured). They show up as soon as a download finishes, without waiting for the next rescan.
- **Failures:** if a download fails or isn't an RPM, a warning is logged and the stored files stay as they were.
- **GitHub rate limit:** release lookups use the GitHub API, which allows 60 unauthenticated requests per hour per IP. That is plenty for a daily refresh, but a shared NAT address can exhaust it. Set `RPM_SERVER_GITHUB_TOKEN` (or `RPM_SERVER_GITHUB_TOKEN_FILE`) to a token; for public repositories it needs no scopes. The token is only sent to the API, never to the asset download hosts.

### Client setup

```sh
curl -o /etc/yum.repos.d/rpm-server.repo http://HOST:8080/rpm-server.repo
dnf install <package>
```

The `.repo` file enables `gpgcheck`/`repo_gpgcheck` and points `gpgkey` at `/RPM-GPG-KEY` when a key is configured.

## Configuration

Every flag (see `rpm-server --help`) has an environment variable:

| Variable                                                       | Default        | Meaning                                                                                       |
| -------------------------------------------------------------- | -------------- | --------------------------------------------------------------------------------------------- |
| `RPM_SERVER_DIR`                                               | `/srv/rpms`    | Folder of `.rpm` files, searched recursively and served under `/static/`                      |
| `RPM_SERVER_LISTEN`                                            | `0.0.0.0:8080` | Listen address                                                                                |
| `RPM_SERVER_GPG_KEY`                                           |                | ASCII-armored secret key; enables signing                                                     |
| `RPM_SERVER_GPG_PASSPHRASE` / `RPM_SERVER_GPG_PASSPHRASE_FILE` |                | Key passphrase                                                                                |
| `RPM_SERVER_NO_PACKAGE_SIGNING`                                | `false`        | Keep the vendor's package signatures; only sign `repomd.xml`                                  |
| `RPM_SERVER_RESCAN_INTERVAL`                                   | `3600`         | Seconds between full folder rescans (`0` disables); a fallback for changes the watcher misses |
| `RPM_SERVER_REPO_ID`                                           | `rpm-server`   | Repo id and name of the served `<id>.repo` file                                               |
| `RPM_SERVER_BASE_URL`                                          | from `Host`    | Public URL written into the `.repo` file                                                      |
| `RPM_SERVER_SOURCES_FILE`                                      |                | File of RPM or GitHub project URLs to download (needs a download folder)                      |
| `RPM_SERVER_DOWNLOAD_DIR`                                      |                | Writable folder for downloads, served under `/downloaded/`; must not overlap `RPM_SERVER_DIR` |
| `RPM_SERVER_UPDATE_INTERVAL`                                   | `86400`        | Seconds between source downloads                                                              |
| `RPM_SERVER_GITHUB_TOKEN` / `RPM_SERVER_GITHUB_TOKEN_FILE`     |                | Optional GitHub token for release lookups (raises the API rate limit)                         |
| `RUST_LOG`                                                     | `info`         | Log filter (`tower_http=debug` logs requests)                                                 |

Ed25519 and RSA keys both work on EL9 / AL2023 / Fedora. Use RSA for EL7 / Amazon Linux 2 clients.

## Testing

`cargo test` runs the unit tests and `tests/dnf_container.rs`. That test serves a repo from the test process and installs from it with dnf5 (Fedora) and dnf4 (Amazon Linux 2023) running in `podman --network=host` containers, so podman and access to the image registries are required.
