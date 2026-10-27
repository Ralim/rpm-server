//! Command line / environment configuration.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;

use crate::signing::RepoSigner;

/// Serve a folder of RPM packages as a dnf repository.
///
/// Every option can also be set through the environment variable shown.
#[derive(Debug, Parser)]
#[command(version, about)]
pub struct Config {
    /// Directory containing the .rpm files (searched recursively).
    #[arg(long, env = "RPM_SERVER_DIR", default_value = "/srv/rpms")]
    pub dir: PathBuf,

    /// Address to listen on.
    #[arg(long, env = "RPM_SERVER_LISTEN", default_value = "0.0.0.0:8080")]
    pub listen: SocketAddr,

    /// ASCII-armored OpenPGP secret key. Enables signing of repomd.xml and,
    /// unless --no-package-signing is given, of every served package.
    #[arg(long, env = "RPM_SERVER_GPG_KEY")]
    pub gpg_key: Option<PathBuf>,

    /// Passphrase for the secret key.
    #[arg(
        long,
        env = "RPM_SERVER_GPG_PASSPHRASE",
        hide_env_values = true,
        conflicts_with = "gpg_passphrase_file"
    )]
    pub gpg_passphrase: Option<String>,

    /// File containing the passphrase for the secret key.
    #[arg(long, env = "RPM_SERVER_GPG_PASSPHRASE_FILE")]
    pub gpg_passphrase_file: Option<PathBuf>,

    /// Serve packages with their original signatures; only sign repomd.xml.
    #[arg(long, env = "RPM_SERVER_NO_PACKAGE_SIGNING")]
    pub no_package_signing: bool,

    /// Seconds between full folder rescans; 0 disables them. Changes are
    /// normally picked up immediately via filesystem watching; this is the
    /// fallback for filesystems where that does not work (e.g. NFS).
    #[arg(long, env = "RPM_SERVER_RESCAN_INTERVAL", default_value_t = 3600)]
    pub rescan_interval: u64,

    /// Repository id used in the generated `<id>.repo` file.
    #[arg(long, env = "RPM_SERVER_REPO_ID", default_value = "rpm-server", value_parser = parse_repo_id)]
    pub repo_id: String,

    /// Public base URL for the generated .repo file (default: from request headers).
    #[arg(long, env = "RPM_SERVER_BASE_URL")]
    pub base_url: Option<String>,

    /// File listing URLs of RPMs to download, one per line (`#` comments allowed).
    #[arg(long, env = "RPM_SERVER_SOURCES_FILE", requires = "download_dir")]
    pub sources_file: Option<PathBuf>,

    /// Writable folder for downloaded RPMs, served under /downloaded/.
    /// Must not be inside --dir.
    #[arg(long, env = "RPM_SERVER_DOWNLOAD_DIR")]
    pub download_dir: Option<PathBuf>,

    /// Seconds between source downloads (they also run at startup).
    #[arg(long, env = "RPM_SERVER_UPDATE_INTERVAL", default_value_t = 86400, value_parser = clap::value_parser!(u64).range(1..))]
    pub update_interval: u64,

    /// GitHub token for looking up releases of GitHub sources (raises the
    /// API rate limit; no scopes needed for public repositories).
    #[arg(
        long,
        env = "RPM_SERVER_GITHUB_TOKEN",
        hide_env_values = true,
        conflicts_with = "github_token_file"
    )]
    pub github_token: Option<String>,

    /// File containing the GitHub token.
    #[arg(long, env = "RPM_SERVER_GITHUB_TOKEN_FILE")]
    pub github_token_file: Option<PathBuf>,

    /// Query the health endpoint of the server on --listen and exit
    /// (0 healthy, 1 unhealthy) instead of starting a server.
    #[arg(long)]
    pub healthcheck: bool,
}

fn parse_repo_id(s: &str) -> Result<String, String> {
    let valid = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'));
    if valid {
        Ok(s.to_owned())
    } else {
        Err("repo id may only contain ASCII letters, digits, '-', '_', '.' and ':'".into())
    }
}

impl Config {
    /// The GitHub token from `--github-token` or `--github-token-file`.
    pub fn github_token(&self) -> Result<Option<String>> {
        if let Some(path) = &self.github_token_file {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("reading GitHub token file {}", path.display()))?;
            return Ok(Some(raw.trim().to_owned()));
        }
        Ok(self.github_token.clone())
    }
    fn passphrase(&self) -> Result<Option<String>> {
        if let Some(path) = &self.gpg_passphrase_file {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("reading passphrase file {}", path.display()))?;
            return Ok(Some(raw.trim_end_matches(['\r', '\n']).to_owned()));
        }
        Ok(self.gpg_passphrase.clone())
    }

    /// Loads the signing key, if one is configured.
    pub fn load_signer(&self) -> Result<Option<Arc<RepoSigner>>> {
        let Some(path) = &self.gpg_key else {
            return Ok(None);
        };
        let asc = std::fs::read_to_string(path)
            .with_context(|| format!("reading signing key {}", path.display()))?;
        let signer = RepoSigner::from_armored(&asc, self.passphrase()?, !self.no_package_signing)
            .with_context(|| format!("loading signing key {}", path.display()))?;
        Ok(Some(Arc::new(signer)))
    }

    /// Creates the download folder and checks it does not overlap `dir`,
    /// which would list its packages twice.
    pub fn prepare_download_dir(&self) -> Result<Option<PathBuf>> {
        let Some(download) = &self.download_dir else {
            return Ok(None);
        };
        std::fs::create_dir_all(download)
            .with_context(|| format!("creating download folder {}", download.display()))?;
        let download = download
            .canonicalize()
            .with_context(|| format!("resolving {}", download.display()))?;
        let dir = self
            .dir
            .canonicalize()
            .with_context(|| format!("resolving {}", self.dir.display()))?;
        if download.starts_with(&dir) || dir.starts_with(&download) {
            anyhow::bail!(
                "download folder {} must not overlap the package folder {}",
                download.display(),
                dir.display()
            );
        }
        Ok(Some(download))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::generate_secret_key;

    #[test]
    fn defaults() {
        let c = Config::try_parse_from(["rpm-server"]).unwrap();
        assert_eq!(c.dir, PathBuf::from("/srv/rpms"));
        assert_eq!(c.listen.port(), 8080);
        assert_eq!(c.rescan_interval, 3600);
        assert_eq!(c.repo_id, "rpm-server");
        assert_eq!(c.update_interval, 86400);
        assert!(c.load_signer().unwrap().is_none());
        assert!(c.prepare_download_dir().unwrap().is_none());
    }

    #[test]
    fn github_token_sources() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("token");
        std::fs::write(&file, "ghp_abc\n").unwrap();
        let c = Config::try_parse_from([
            "rpm-server".as_ref(),
            "--github-token-file".as_ref(),
            file.as_os_str(),
        ])
        .unwrap();
        assert_eq!(c.github_token().unwrap().as_deref(), Some("ghp_abc"));

        let c = Config::try_parse_from(["rpm-server", "--github-token", "ghp_x"]).unwrap();
        assert_eq!(c.github_token().unwrap().as_deref(), Some("ghp_x"));
        assert!(
            Config::try_parse_from([
                "rpm-server",
                "--github-token",
                "a",
                "--github-token-file",
                "/x"
            ])
            .is_err()
        );
    }

    #[test]
    fn sources_file_requires_download_dir() {
        assert!(Config::try_parse_from(["rpm-server", "--sources-file", "/x"]).is_err());
        assert!(
            Config::try_parse_from(["rpm-server", "--sources-file", "/x", "--download-dir", "/y"])
                .is_ok()
        );
        assert!(Config::try_parse_from(["rpm-server", "--update-interval", "0"]).is_err());
    }

    #[test]
    fn download_dir_must_not_overlap() {
        let tmp = tempfile::tempdir().unwrap();
        let main = tmp.path().join("rpms");
        std::fs::create_dir(&main).unwrap();
        let parse = |download: &std::path::Path| {
            Config::try_parse_from([
                "rpm-server".as_ref(),
                "--dir".as_ref(),
                main.as_os_str(),
                "--download-dir".as_ref(),
                download.as_os_str(),
            ])
            .unwrap()
        };
        assert!(parse(&main.join("online")).prepare_download_dir().is_err());
        assert!(parse(tmp.path()).prepare_download_dir().is_err());
        let ok = parse(&tmp.path().join("downloads"))
            .prepare_download_dir()
            .unwrap();
        assert!(ok.unwrap().is_dir());
    }

    #[test]
    fn repo_id_validation() {
        assert!(Config::try_parse_from(["rpm-server", "--repo-id", "aws-tools_1.0"]).is_ok());
        assert!(Config::try_parse_from(["rpm-server", "--repo-id", "bad id"]).is_err());
        assert!(Config::try_parse_from(["rpm-server", "--repo-id", "bad]"]).is_err());
    }

    #[test]
    fn passphrase_options_conflict() {
        let r = Config::try_parse_from([
            "rpm-server",
            "--gpg-passphrase",
            "a",
            "--gpg-passphrase-file",
            "/x",
        ]);
        assert!(r.is_err());
    }

    #[test]
    fn loads_key_with_passphrase_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("key.asc");
        let pass = dir.path().join("pass");
        std::fs::write(
            &key,
            generate_secret_key("T <t@example.invalid>", Some("s3cret")).unwrap(),
        )
        .unwrap();
        std::fs::write(&pass, "s3cret\n").unwrap();
        let c = Config::try_parse_from([
            "rpm-server".as_ref(),
            "--gpg-key".as_ref(),
            key.as_os_str(),
            "--gpg-passphrase-file".as_ref(),
            pass.as_os_str(),
            "--no-package-signing".as_ref(),
        ])
        .unwrap();
        let signer = c.load_signer().unwrap().unwrap();
        assert!(!signer.signs_packages());

        let c =
            Config::try_parse_from(["rpm-server".as_ref(), "--gpg-key".as_ref(), key.as_os_str()])
                .unwrap();
        assert!(c.load_signer().is_err(), "missing passphrase must fail");
    }
}
