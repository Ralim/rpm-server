//! Keeps a writable folder in sync with RPMs published at fixed URLs
//! (e.g. a vendor's "latest" download link).
//!
//! Each URL is fetched; if the content hash differs from the last stored
//! copy, the package header is read and the file is stored as
//! `name-version-release.arch.rpm`. Previous versions are kept.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::{StatusCode, Url, header};
use rpm::PackageMetadata;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

/// Path under which the download folder appears in the repository.
pub const URL_PREFIX: &str = "downloaded";
/// Per-URL state (hash, stored file, ETag); hidden so the scanner skips it.
const STATE_DIR: &str = ".sources";
const MAX_DOWNLOAD_BYTES: u64 = 4 << 30;

/// Parses a sources file: one http(s) URL per line, `#` comments and blank
/// lines ignored. Invalid lines are logged and skipped.
pub fn parse_sources(text: &str) -> Vec<Url> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|line| match Url::parse(line) {
            Ok(url) if matches!(url.scheme(), "http" | "https") => Some(url),
            Ok(_) => {
                warn!(line, "ignoring source with unsupported URL scheme");
                None
            }
            Err(err) => {
                warn!(line, %err, "ignoring invalid source URL");
                None
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceState {
    sha256: String,
    file: String,
    etag: Option<String>,
}

impl SourceState {
    fn parse(text: &str) -> Option<Self> {
        let get = |key: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
                .map(str::to_owned)
        };
        Some(Self {
            sha256: get("sha256")?,
            file: get("file")?,
            etag: get("etag"),
        })
    }

    fn render(&self, url: &Url) -> String {
        let mut out = format!("url={url}\nsha256={}\nfile={}\n", self.sha256, self.file);
        if let Some(etag) = &self.etag {
            out.push_str(&format!("etag={etag}\n"));
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The stored copy already matches the URL's content.
    Unchanged { file: String },
    /// New content was stored.
    Updated { file: String, nevra: String },
}

/// Reads the package header and returns (`name-version-release.arch.rpm`, NEVRA).
fn stored_name(path: &Path) -> Result<(String, String)> {
    let m = PackageMetadata::open(path).context("downloaded file is not a valid RPM")?;
    let arch = if m.is_source_package() {
        "src"
    } else {
        m.get_arch()?
    };
    let (name, version, release) = (m.get_name()?, m.get_version()?, m.get_release()?);
    let file = format!("{name}-{version}-{release}.{arch}.rpm");
    if file.starts_with('.') || file.contains(['/', '\\', '\0']) || file.len() > 255 {
        bail!("refusing unsafe file name derived from package header: {file:?}");
    }
    let nevra = match m.get_epoch() {
        Ok(epoch) if epoch > 0 => format!("{name}-{epoch}:{version}-{release}.{arch}"),
        _ => format!("{name}-{version}-{release}.{arch}"),
    };
    Ok((file, nevra))
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = std::io::Read::read(&mut file, &mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Downloads configured sources into a folder.
pub struct Updater {
    client: reqwest::Client,
    sources_file: PathBuf,
    dir: PathBuf,
}

impl Updater {
    pub fn new(sources_file: PathBuf, dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(dir.join(STATE_DIR))
            .with_context(|| format!("creating download folder {}", dir.display()))?;
        // Already installed when several updaters exist in one process (tests).
        let _ = rustls::crypto::ring::default_provider().install_default();
        let roots = webpki_root_certs::TLS_SERVER_ROOT_CERTS
            .iter()
            .map(|c| reqwest::Certificate::from_der(c.as_ref()))
            .collect::<reqwest::Result<Vec<_>>>()?;
        let client = reqwest::Client::builder()
            .user_agent(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION")
            ))
            .connect_timeout(Duration::from_secs(30))
            .read_timeout(Duration::from_secs(120))
            .tls_certs_only(roots)
            .build()
            .context("building HTTP client")?;
        Ok(Self {
            client,
            sources_file,
            dir,
        })
    }

    fn state_path(&self, url: &Url) -> PathBuf {
        let key = hex::encode(Sha256::digest(url.as_str().as_bytes()));
        self.dir.join(STATE_DIR).join(key)
    }

    async fn write_state(&self, url: &Url, state: &SourceState) -> Result<()> {
        let path = self.state_path(url);
        let tmp = path.with_extension("tmp");
        tokio::fs::write(&tmp, state.render(url)).await?;
        tokio::fs::rename(&tmp, &path).await?;
        Ok(())
    }

    /// Fetches every URL in the sources file (re-read on each call).
    /// Returns whether any new package was stored.
    pub async fn update_all(&self) -> bool {
        let text = match tokio::fs::read_to_string(&self.sources_file).await {
            Ok(t) => t,
            Err(err) => {
                warn!(file = %self.sources_file.display(), %err, "cannot read sources file");
                return false;
            }
        };
        let mut changed = false;
        for url in parse_sources(&text) {
            match self.update(&url).await {
                Ok(Outcome::Updated { file, nevra }) => {
                    info!(%url, file, nevra, "stored new package from source");
                    changed = true;
                }
                Ok(Outcome::Unchanged { file }) => info!(%url, file, "source unchanged"),
                Err(err) => warn!(%url, "source update failed: {err:#}"),
            }
        }
        changed
    }

    /// Fetches one URL and stores its content if it changed.
    pub async fn update(&self, url: &Url) -> Result<Outcome> {
        let previous = tokio::fs::read_to_string(self.state_path(url))
            .await
            .ok()
            .and_then(|t| SourceState::parse(&t))
            .filter(|s| self.dir.join(&s.file).is_file());

        let mut request = self.client.get(url.clone());
        if let Some(etag) = previous.as_ref().and_then(|s| s.etag.as_deref()) {
            request = request.header(header::IF_NONE_MATCH, etag);
        }
        let response = request.send().await.context("request failed")?;
        if response.status() == StatusCode::NOT_MODIFIED {
            return match previous {
                Some(s) => Ok(Outcome::Unchanged { file: s.file }),
                None => bail!("server answered 304 without a conditional request"),
            };
        }
        let mut response = response.error_for_status()?;
        let etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        if response
            .content_length()
            .is_some_and(|len| len > MAX_DOWNLOAD_BYTES)
        {
            bail!("download exceeds {MAX_DOWNLOAD_BYTES} bytes");
        }

        // Hidden name: the scanner ignores it while it is being written.
        let tmp = tempfile::Builder::new()
            .prefix(".download-")
            .suffix(".part")
            .tempfile_in(&self.dir)?;
        let mut file = tokio::fs::File::from_std(tmp.reopen()?);
        let mut hasher = Sha256::new();
        let mut size = 0u64;
        while let Some(chunk) = response.chunk().await.context("reading response body")? {
            size += chunk.len() as u64;
            if size > MAX_DOWNLOAD_BYTES {
                bail!("download exceeds {MAX_DOWNLOAD_BYTES} bytes");
            }
            hasher.update(&chunk);
            file.write_all(&chunk).await?;
        }
        file.sync_all().await?;
        drop(file);
        let sha256 = hex::encode(hasher.finalize());

        if let Some(prev) = previous.filter(|p| p.sha256 == sha256) {
            let file = prev.file.clone();
            self.write_state(url, &SourceState { etag, ..prev }).await?;
            return Ok(Outcome::Unchanged { file });
        }

        let dir = self.dir.clone();
        let expected = sha256.clone();
        let outcome = tokio::task::spawn_blocking(move || -> Result<Outcome> {
            let (file, nevra) = stored_name(tmp.path())?;
            let target = dir.join(&file);
            if target.is_file() {
                if sha256_file(&target)? == expected {
                    return Ok(Outcome::Unchanged { file });
                }
                warn!(file, "replacing stored package that has different content");
            }
            std::fs::set_permissions(
                tmp.path(),
                std::os::unix::fs::PermissionsExt::from_mode(0o644),
            )?;
            tmp.persist(&target)
                .with_context(|| format!("storing {}", target.display()))?;
            Ok(Outcome::Updated { file, nevra })
        })
        .await??;

        let file = match &outcome {
            Outcome::Unchanged { file } | Outcome::Updated { file, .. } => file.clone(),
        };
        self.write_state(url, &SourceState { sha256, file, etag })
            .await?;
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;
    use axum::Router;
    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::response::{IntoResponse, Response};
    use axum::routing::get;
    use std::sync::{Arc, Mutex};

    /// What the fake origin serves, and what it saw.
    #[derive(Default)]
    struct Origin {
        status: u16,
        body: Vec<u8>,
        etag: Option<String>,
        conditional_hits: usize,
    }

    async fn origin_handler(State(o): State<Arc<Mutex<Origin>>>, headers: HeaderMap) -> Response {
        let mut o = o.lock().unwrap();
        if let (Some(etag), Some(inm)) = (&o.etag, headers.get(header::IF_NONE_MATCH))
            && inm.as_bytes() == etag.as_bytes()
        {
            o.conditional_hits += 1;
            return StatusCode::NOT_MODIFIED.into_response();
        }
        let mut resp = (StatusCode::from_u16(o.status).unwrap(), o.body.clone()).into_response();
        if let Some(etag) = &o.etag {
            resp.headers_mut()
                .insert(header::ETAG, etag.parse().unwrap());
        }
        resp
    }

    async fn start_origin(origin: Arc<Mutex<Origin>>) -> Url {
        let app = Router::new()
            .route("/pkg/latest.rpm", get(origin_handler))
            .with_state(origin);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Url::parse(&format!("http://{addr}/pkg/latest.rpm")).unwrap()
    }

    fn files(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|n| n != STATE_DIR)
            .collect();
        names.sort();
        names
    }

    #[test]
    fn sources_file_parsing() {
        let urls = parse_sources(
            "# vendor packages\n\n  https://example.com/a.rpm  \nftp://example.com/b.rpm\nnot a url\nhttp://example.com/c.rpm\n",
        );
        let urls: Vec<_> = urls.iter().map(Url::as_str).collect();
        assert_eq!(
            urls,
            ["https://example.com/a.rpm", "http://example.com/c.rpm"]
        );
    }

    #[test]
    fn state_round_trip() {
        let url = Url::parse("https://example.com/a.rpm").unwrap();
        let s = SourceState {
            sha256: "ab".into(),
            file: "a-1-1.noarch.rpm".into(),
            etag: Some("\"x=y\"".into()),
        };
        assert_eq!(SourceState::parse(&s.render(&url)), Some(s.clone()));
        let no_etag = SourceState { etag: None, ..s };
        assert_eq!(SourceState::parse(&no_etag.render(&url)), Some(no_etag));
        assert_eq!(SourceState::parse("file=x\n"), None);
    }

    #[test]
    fn stored_name_from_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x");
        std::fs::write(&path, testutil::build_rpm("vendor-tool", "1.2.3", &[])).unwrap();
        let (file, nevra) = stored_name(&path).unwrap();
        assert_eq!(file, "vendor-tool-1.2.3-1.noarch.rpm");
        assert_eq!(nevra, "vendor-tool-1.2.3-1.noarch");

        std::fs::write(&path, b"<html>not found</html>").unwrap();
        assert!(stored_name(&path).is_err());
    }

    #[tokio::test]
    async fn update_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let v1 = testutil::build_rpm("vendor-tool", "1.0", &[]);
        let v2 = testutil::build_rpm("vendor-tool", "2.0", &[]);
        let origin = Arc::new(Mutex::new(Origin {
            status: 200,
            body: v1.clone(),
            etag: Some("\"v1\"".into()),
            ..Default::default()
        }));
        let url = start_origin(origin.clone()).await;
        let updater = Updater::new(dir.path().join("sources"), dir.path().to_owned()).unwrap();

        // First fetch stores the package under its NEVRA-derived name.
        let out = updater.update(&url).await.unwrap();
        assert_eq!(
            out,
            Outcome::Updated {
                file: "vendor-tool-1.0-1.noarch.rpm".into(),
                nevra: "vendor-tool-1.0-1.noarch".into()
            }
        );
        let stored = dir.path().join("vendor-tool-1.0-1.noarch.rpm");
        assert_eq!(std::fs::read(&stored).unwrap(), v1);
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&stored).unwrap().permissions(),
        );
        assert_eq!(mode & 0o777, 0o644);

        // Same ETag: answered with 304, nothing downloaded.
        let out = updater.update(&url).await.unwrap();
        assert!(matches!(out, Outcome::Unchanged { .. }));
        assert_eq!(origin.lock().unwrap().conditional_hits, 1);

        // New ETag but identical bytes: detected by hash.
        origin.lock().unwrap().etag = Some("\"v1-again\"".into());
        let out = updater.update(&url).await.unwrap();
        assert!(matches!(out, Outcome::Unchanged { .. }));

        // New content: stored alongside the old version.
        {
            let mut o = origin.lock().unwrap();
            o.body = v2.clone();
            o.etag = None;
        }
        let out = updater.update(&url).await.unwrap();
        assert!(
            matches!(out, Outcome::Updated { ref file, .. } if file == "vendor-tool-2.0-1.noarch.rpm")
        );
        assert_eq!(
            files(dir.path()),
            [
                "vendor-tool-1.0-1.noarch.rpm",
                "vendor-tool-2.0-1.noarch.rpm"
            ]
        );

        // Errors and non-RPM content leave the folder untouched.
        origin.lock().unwrap().status = 404;
        assert!(updater.update(&url).await.is_err());
        {
            let mut o = origin.lock().unwrap();
            o.status = 200;
            o.body = b"<html>oops</html>".to_vec();
        }
        assert!(updater.update(&url).await.is_err());
        assert_eq!(
            files(dir.path()),
            [
                "vendor-tool-1.0-1.noarch.rpm",
                "vendor-tool-2.0-1.noarch.rpm"
            ]
        );

        // A deleted stored copy is downloaded again.
        origin.lock().unwrap().body = v2.clone();
        std::fs::remove_file(dir.path().join("vendor-tool-2.0-1.noarch.rpm")).unwrap();
        let out = updater.update(&url).await.unwrap();
        assert!(matches!(out, Outcome::Updated { .. }));
    }

    #[tokio::test]
    async fn update_all_reads_sources_file() {
        let dir = tempfile::tempdir().unwrap();
        let downloads = dir.path().join("downloads");
        let origin = Arc::new(Mutex::new(Origin {
            status: 200,
            body: testutil::build_rpm("vendor-tool", "1.0", &[]),
            ..Default::default()
        }));
        let url = start_origin(origin).await;
        let sources = dir.path().join("sources.list");
        std::fs::write(
            &sources,
            format!("# test\n{url}\nhttp://127.0.0.1:1/unreachable.rpm\n"),
        )
        .unwrap();

        let updater = Updater::new(sources.clone(), downloads.clone()).unwrap();
        assert!(updater.update_all().await, "first run stores the package");
        assert!(!updater.update_all().await, "second run finds nothing new");
        assert_eq!(files(&downloads), ["vendor-tool-1.0-1.noarch.rpm"]);

        std::fs::remove_file(&sources).unwrap();
        assert!(
            !updater.update_all().await,
            "missing sources file is not fatal"
        );
    }
}
