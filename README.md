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
podman build -t rpm-server -f Containerfile .

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

### Client setup

```sh
curl -o /etc/yum.repos.d/rpm-server.repo http://HOST:8080/rpm-server.repo
dnf install <package>
```

The `.repo` file enables `gpgcheck`/`repo_gpgcheck` and points `gpgkey` at `/RPM-GPG-KEY` when a key is configured.

## Configuration

Every flag (see `rpm-server --help`) has an environment variable:

| Variable                                                       | Default        | Meaning                                                      |
| -------------------------------------------------------------- | -------------- | ------------------------------------------------------------ |
| `RPM_SERVER_DIR`                                               | `/srv/rpms`    | Folder of `.rpm` files, searched recursively                 |
| `RPM_SERVER_LISTEN`                                            | `0.0.0.0:8080` | Listen address                                               |
| `RPM_SERVER_GPG_KEY`                                           |                | ASCII-armored secret key; enables signing                    |
| `RPM_SERVER_GPG_PASSPHRASE` / `RPM_SERVER_GPG_PASSPHRASE_FILE` |                | Key passphrase                                               |
| `RPM_SERVER_NO_PACKAGE_SIGNING`                                | `false`        | Keep the vendor's package signatures; only sign `repomd.xml` |
| `RPM_SERVER_RESCAN_INTERVAL`                                   | `30`           | Seconds between folder rescans (`0` disables)                |
| `RPM_SERVER_REPO_ID`                                           | `rpm-server`   | Repo id and name of the served `<id>.repo` file              |
| `RPM_SERVER_BASE_URL`                                          | from `Host`    | Public URL written into the `.repo` file                     |
| `RUST_LOG`                                                     | `info`         | Log filter (`tower_http=debug` logs requests)                |

Ed25519 and RSA keys both work on EL9 / AL2023 / Fedora. Use RSA for EL7 / Amazon Linux 2 clients.

## Testing

`cargo test` runs the unit tests and `tests/dnf_container.rs`. That test serves a repo from the test process and installs from it with dnf5 (Fedora) and dnf4 (Amazon Linux 2023) running in `podman --network=host` containers, so podman and access to the image registries are required.
