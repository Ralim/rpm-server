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

    /// Seconds between directory rescans; 0 disables rescanning.
    #[arg(long, env = "RPM_SERVER_RESCAN_INTERVAL", default_value_t = 30)]
    pub rescan_interval: u64,

    /// Repository id used in the generated `<id>.repo` file.
    #[arg(long, env = "RPM_SERVER_REPO_ID", default_value = "rpm-server", value_parser = parse_repo_id)]
    pub repo_id: String,

    /// Public base URL for the generated .repo file (default: from request headers).
    #[arg(long, env = "RPM_SERVER_BASE_URL")]
    pub base_url: Option<String>,
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
        assert_eq!(c.rescan_interval, 30);
        assert_eq!(c.repo_id, "rpm-server");
        assert!(c.load_signer().unwrap().is_none());
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
