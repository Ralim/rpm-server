//! HTTP layer: serves packages, generated metadata, the public key, a
//! ready-made `.repo` file and HTML directory listings.

use std::fmt::Write as _;
use std::io::{self, Cursor, SeekFrom};
use std::sync::{Arc, RwLock};

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use bytes::Bytes;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;
use tower_http::trace::TraceLayer;
use tracing::warn;

use crate::package::RpmEntry;
use crate::repo::{DirItem, Entry, KEY_PATH, Repo};

const RPM_CONTENT_TYPE: &str = "application/x-rpm";
const STREAM_CHUNK: usize = 64 * 1024;

/// Characters left unescaped in a single path segment of an href.
const PATH_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b'+');

/// Shared server state; the repository snapshot is swapped atomically on rescan.
#[derive(Debug)]
pub struct AppState {
    repo: RwLock<Arc<Repo>>,
    /// Error from the most recent rescan, if it failed.
    scan_error: RwLock<Option<String>>,
    repo_id: String,
    base_url: Option<String>,
}

impl AppState {
    /// `repo_id` names the section and file of the served `.repo` config.
    /// `base_url` overrides the URL derived from request headers.
    pub fn new(repo: Repo, repo_id: String, base_url: Option<String>) -> Arc<Self> {
        Arc::new(Self {
            repo: RwLock::new(Arc::new(repo)),
            scan_error: RwLock::new(None),
            repo_id,
            base_url: base_url.map(|u| u.trim_end_matches('/').to_owned()),
        })
    }

    pub fn repo(&self) -> Arc<Repo> {
        self.repo.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set_repo(&self, repo: Repo) {
        *self.repo.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(repo);
    }

    /// Records the outcome of a rescan; a failure makes `/healthz` report unhealthy.
    pub fn set_scan_error(&self, error: Option<String>) {
        *self.scan_error.write().unwrap_or_else(|e| e.into_inner()) = error;
    }

    fn scan_error(&self) -> Option<String> {
        self.scan_error
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn repo_file_name(&self) -> String {
        format!("{}.repo", self.repo_id)
    }
}

/// Path of the health endpoint.
pub const HEALTH_PATH: &str = "/healthz";

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(HEALTH_PATH, get(health))
        .route("/", get(handle))
        .route("/{*path}", get(handle))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// 200 while the last rescan succeeded, 503 if it failed (e.g. the package
/// folder became unreadable).
async fn health(State(state): State<Arc<AppState>>) -> Response {
    let headers = [
        (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
        (header::CACHE_CONTROL, "no-store"),
    ];
    match state.scan_error() {
        None => {
            let repo = state.repo();
            let body = format!(
                "ok packages={} revision={}\n",
                repo.package_count, repo.revision
            );
            (StatusCode::OK, headers, body).into_response()
        }
        Some(err) => {
            let body = format!("unhealthy: last rescan failed: {err}\n");
            (StatusCode::SERVICE_UNAVAILABLE, headers, body).into_response()
        }
    }
}

async fn handle(State(state): State<Arc<AppState>>, headers: HeaderMap, uri: Uri) -> Response {
    let Ok(decoded) = percent_decode_str(uri.path()).decode_utf8() else {
        return (StatusCode::BAD_REQUEST, "invalid path encoding\n").into_response();
    };
    let path = decoded.trim_start_matches('/');
    let repo = state.repo();

    if path == state.repo_file_name() {
        return repo_file(&state, &repo, &headers);
    }
    if path.is_empty() || path.ends_with('/') {
        return match repo.list_dir(path) {
            Some(items) => index_page(&state, path, &items),
            None => not_found(),
        };
    }
    match repo.get(path) {
        Some(Entry::Rpm(e)) => serve_rpm(e, &headers).await,
        Some(Entry::Static {
            bytes,
            content_type,
        }) => serve_static(path, bytes.clone(), content_type, &headers),
        None if repo.is_dir(path) => {
            Redirect::permanent(&format!("{}/", uri.path())).into_response()
        }
        None => not_found(),
    }
}

fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "not found\n").into_response()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ByteRange {
    Full,
    /// `start..end` (end exclusive).
    Partial(u64, u64),
    Unsatisfiable,
}

/// Parses a single-range `Range` header. Multi-range and malformed headers
/// are ignored, as RFC 9110 permits, and the full content is sent.
fn parse_range(headers: &HeaderMap, len: u64, etag: Option<&str>) -> ByteRange {
    let Some(value) = headers.get(header::RANGE).and_then(|v| v.to_str().ok()) else {
        return ByteRange::Full;
    };
    if let Some(if_range) = headers.get(header::IF_RANGE)
        && etag.is_none_or(|tag| if_range.as_bytes() != tag.as_bytes())
    {
        return ByteRange::Full;
    }
    let Some(spec) = value.trim().strip_prefix("bytes=") else {
        return ByteRange::Full;
    };
    if spec.contains(',') {
        return ByteRange::Full;
    }
    let Some((first, last)) = spec.split_once('-') else {
        return ByteRange::Full;
    };
    let (first, last) = (first.trim(), last.trim());
    if first.is_empty() {
        return match last.parse::<u64>() {
            Ok(0) => ByteRange::Unsatisfiable,
            Ok(_) if len == 0 => ByteRange::Unsatisfiable,
            Ok(n) => ByteRange::Partial(len - n.min(len), len),
            Err(_) => ByteRange::Full,
        };
    }
    let Ok(start) = first.parse::<u64>() else {
        return ByteRange::Full;
    };
    let end = if last.is_empty() {
        len
    } else {
        match last.parse::<u64>() {
            Ok(e) if e >= start => e.saturating_add(1).min(len),
            _ => return ByteRange::Full,
        }
    };
    if start >= len {
        ByteRange::Unsatisfiable
    } else {
        ByteRange::Partial(start, end)
    }
}

fn base_headers(content_type: &str, etag: Option<&str>) -> HeaderMap {
    let mut h = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(content_type) {
        h.insert(header::CONTENT_TYPE, v);
    }
    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if let Some(tag) = etag.and_then(|t| HeaderValue::from_str(t).ok()) {
        h.insert(header::ETAG, tag);
    }
    h
}

/// Resolves the range into (status, start, end), adding `Content-Range` to
/// `out`. Returns `None` when the range is unsatisfiable.
fn range_status(
    headers: &HeaderMap,
    out: &mut HeaderMap,
    len: u64,
    etag: Option<&str>,
) -> Option<(StatusCode, u64, u64)> {
    let (content_range, result) = match parse_range(headers, len, etag) {
        ByteRange::Full => return Some((StatusCode::OK, 0, len)),
        ByteRange::Partial(start, end) => (
            format!("bytes {start}-{}/{len}", end - 1),
            Some((StatusCode::PARTIAL_CONTENT, start, end)),
        ),
        ByteRange::Unsatisfiable => (format!("bytes */{len}"), None),
    };
    out.insert(
        header::CONTENT_RANGE,
        HeaderValue::from_str(&content_range).expect("ascii"),
    );
    result
}

fn serve_static(path: &str, bytes: Bytes, content_type: &str, req: &HeaderMap) -> Response {
    let mut headers = base_headers(content_type, None);
    if path.starts_with("repodata/repomd.xml") {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    }
    let Some((status, start, end)) = range_status(req, &mut headers, bytes.len() as u64, None)
    else {
        return (StatusCode::RANGE_NOT_SATISFIABLE, headers).into_response();
    };
    let body = bytes.slice(start as usize..end as usize);
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
    (status, headers, body).into_response()
}

/// Opens the source file and returns a reader over served bytes `start..end`,
/// or `None` if the file changed since it was scanned.
async fn open_rpm(
    e: &RpmEntry,
    start: u64,
    end: u64,
) -> io::Result<Option<impl tokio::io::AsyncRead + use<>>> {
    let mut file = tokio::fs::File::open(&e.abs_path).await?;
    let meta = file.metadata().await?;
    if meta.len() != e.file_size || meta.modified().ok() != Some(e.mtime) {
        return Ok(None);
    }
    let prefix_len = e.prefix.len() as u64;
    let prefix = if start < prefix_len {
        e.prefix.slice(start as usize..end.min(prefix_len) as usize)
    } else {
        Bytes::new()
    };
    let file_len = (end - start) - prefix.len() as u64;
    file.seek(SeekFrom::Start(
        e.body_offset + start.saturating_sub(prefix_len),
    ))
    .await?;
    Ok(Some(Cursor::new(prefix).chain(file.take(file_len))))
}

async fn serve_rpm(e: &RpmEntry, req: &HeaderMap) -> Response {
    let etag = format!("\"{}\"", e.sha256);
    let mut headers = base_headers(RPM_CONTENT_TYPE, Some(&etag));
    let Some((status, start, end)) = range_status(req, &mut headers, e.size, Some(&etag)) else {
        return (StatusCode::RANGE_NOT_SATISFIABLE, headers).into_response();
    };
    match open_rpm(e, start, end).await {
        Ok(Some(reader)) => {
            headers.insert(header::CONTENT_LENGTH, HeaderValue::from(end - start));
            let body = Body::from_stream(ReaderStream::with_capacity(reader, STREAM_CHUNK));
            (status, headers, body).into_response()
        }
        Ok(None) => {
            warn!(path = %e.rel_path, "package changed on disk; waiting for rescan");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::RETRY_AFTER, "30")],
                "package changed on disk, retry later\n",
            )
                .into_response()
        }
        Err(err) => {
            warn!(path = %e.rel_path, %err, "failed to open package");
            not_found()
        }
    }
}

/// External base URL of the repository, without a trailing slash.
fn base_url(state: &AppState, req: &HeaderMap) -> String {
    if let Some(url) = &state.base_url {
        return url.clone();
    }
    let header_str = |name: &str| req.get(name).and_then(|v| v.to_str().ok());
    let proto = header_str("x-forwarded-proto").unwrap_or("http");
    let host = header_str("x-forwarded-host")
        .or_else(|| header_str("host"))
        .unwrap_or("localhost");
    format!("{proto}://{host}")
}

fn repo_file(state: &AppState, repo: &Repo, req: &HeaderMap) -> Response {
    let base = base_url(state, req);
    let id = &state.repo_id;
    let mut body = format!(
        "[{id}]\nname={id}\nbaseurl={base}/\nenabled=1\ngpgcheck={}\nrepo_gpgcheck={}\n",
        u8::from(repo.signs_packages),
        u8::from(repo.signs_repo),
    );
    if repo.signs_repo {
        let _ = writeln!(body, "gpgkey={base}/{KEY_PATH}");
    }
    body.push_str("skip_if_unavailable=False\nmetadata_expire=300\n");
    ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], body).into_response()
}

fn encode_segment(s: &str) -> String {
    utf8_percent_encode(s, PATH_SEGMENT).to_string()
}

fn human_size(size: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = size as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{size} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn index_page(state: &AppState, dir: &str, items: &[DirItem]) -> Response {
    use html_escape::{encode_double_quoted_attribute as attr, encode_text as text};

    let title = format!("Index of /{dir}");
    let mut html = format!(
        "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>{t}</title>\n\
         <style>body{{font-family:sans-serif;margin:2em}}td,th{{padding:.2em 1em;text-align:left}}\
         td.size{{text-align:right}}</style></head>\n<body><h1>{t}</h1>\n\
         <table><tr><th>Name</th><th>Size</th><th>Package</th></tr>\n",
        t = text(&title)
    );
    if !dir.is_empty() {
        html.push_str("<tr><td><a href=\"../\">../</a></td><td></td><td></td></tr>\n");
    }
    for item in items {
        let (href, name, size, package) = match item {
            DirItem::Dir(d) => (
                format!("{}/", encode_segment(d)),
                format!("{d}/"),
                String::new(),
                String::new(),
            ),
            DirItem::File { name, entry } => {
                let package = match entry {
                    Entry::Rpm(e) => format!("{} \u{2014} {}", e.info.nevra(), e.info.summary),
                    Entry::Static { .. } => String::new(),
                };
                (
                    encode_segment(name),
                    name.clone(),
                    human_size(entry.size()),
                    package,
                )
            }
        };
        let _ = writeln!(
            html,
            "<tr><td><a href=\"{}\">{}</a></td><td class=\"size\">{}</td><td>{}</td></tr>",
            attr(&href),
            text(&name),
            text(&size),
            text(&package)
        );
    }
    html.push_str("</table>\n");
    if dir.is_empty() {
        let repo_file = state.repo_file_name();
        let _ = writeln!(
            html,
            "<p>dnf configuration: <a href=\"{}\">{}</a></p>",
            attr(&encode_segment(&repo_file)),
            text(&repo_file)
        );
    }
    html.push_str("</body></html>\n");
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::Scanner;
    use crate::testutil;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    struct Fixture {
        _dir: tempfile::TempDir,
        state: Arc<AppState>,
        original: Vec<u8>,
    }

    fn fixture(signed: bool) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("sub dir")).unwrap();
        let original = testutil::build_rpm("demo", "1.0", &[]);
        std::fs::write(dir.path().join("sub dir/demo++.rpm"), &original).unwrap();
        let signer = signed.then(testutil::signer);
        let repo = Scanner::new(dir.path().to_owned(), signer)
            .scan()
            .unwrap()
            .unwrap();
        Fixture {
            _dir: dir,
            state: AppState::new(repo, "local".into(), None),
            original,
        }
    }

    async fn get(
        state: &Arc<AppState>,
        uri: &str,
        headers: &[(&str, &str)],
    ) -> (StatusCode, HeaderMap, Bytes) {
        let mut req = Request::builder().uri(uri);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let resp = router(state.clone())
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, headers, body)
    }

    const RPM_URI: &str = "/sub%20dir/demo%2B%2B.rpm";

    #[test]
    fn range_parsing() {
        let h = |v: &str| {
            let mut m = HeaderMap::new();
            m.insert(header::RANGE, HeaderValue::from_str(v).unwrap());
            m
        };
        assert_eq!(parse_range(&HeaderMap::new(), 10, None), ByteRange::Full);
        assert_eq!(
            parse_range(&h("bytes=0-4"), 10, None),
            ByteRange::Partial(0, 5)
        );
        assert_eq!(
            parse_range(&h("bytes=5-"), 10, None),
            ByteRange::Partial(5, 10)
        );
        assert_eq!(
            parse_range(&h("bytes=-3"), 10, None),
            ByteRange::Partial(7, 10)
        );
        assert_eq!(
            parse_range(&h("bytes=-30"), 10, None),
            ByteRange::Partial(0, 10)
        );
        assert_eq!(
            parse_range(&h("bytes=2-100"), 10, None),
            ByteRange::Partial(2, 10)
        );
        assert_eq!(
            parse_range(&h("bytes=10-"), 10, None),
            ByteRange::Unsatisfiable
        );
        assert_eq!(
            parse_range(&h("bytes=-0"), 10, None),
            ByteRange::Unsatisfiable
        );
        assert_eq!(parse_range(&h("bytes=5-2"), 10, None), ByteRange::Full);
        assert_eq!(parse_range(&h("bytes=0-1,4-5"), 10, None), ByteRange::Full);
        assert_eq!(parse_range(&h("items=0-1"), 10, None), ByteRange::Full);

        let mut m = h("bytes=0-1");
        m.insert(header::IF_RANGE, HeaderValue::from_static("\"abc\""));
        assert_eq!(
            parse_range(&m, 10, Some("\"abc\"")),
            ByteRange::Partial(0, 2)
        );
        assert_eq!(parse_range(&m, 10, Some("\"other\"")), ByteRange::Full);
        assert_eq!(parse_range(&m, 10, None), ByteRange::Full);
    }

    #[test]
    fn sizes() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(2048), "2.0 KiB");
        assert_eq!(human_size(5 * 1024 * 1024), "5.0 MiB");
    }

    #[tokio::test]
    async fn serves_unsigned_package_verbatim() {
        let f = fixture(false);
        let (status, headers, body) = get(&f.state, RPM_URI, &[]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_ref(), f.original.as_slice());
        assert_eq!(headers[header::CONTENT_TYPE], RPM_CONTENT_TYPE);
        assert_eq!(
            headers[header::CONTENT_LENGTH],
            f.original.len().to_string().as_str()
        );
        assert_eq!(headers[header::ACCEPT_RANGES], "bytes");

        assert_eq!(
            get(&f.state, "/RPM-GPG-KEY", &[]).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get(&f.state, "/repodata/repomd.xml.asc", &[]).await.0,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn serves_signed_package_matching_metadata() {
        let f = fixture(true);
        let repo = f.state.repo();
        let Some(Entry::Rpm(entry)) = repo.get("sub dir/demo++.rpm") else {
            panic!("package missing");
        };
        let (status, _, body) = get(&f.state, RPM_URI, &[]).await;
        assert_eq!(status, StatusCode::OK);
        assert_ne!(body.as_ref(), f.original.as_slice());
        assert_eq!(body.len() as u64, entry.size);
        assert_eq!(hex::encode(Sha256::digest(&body)), entry.sha256);

        let pkg = rpm::Package::parse(&mut Cursor::new(&body)).unwrap();
        let signer = testutil::signer();
        let verifier =
            rpm::signature::pgp::Verifier::from_asc_bytes(signer.public_key_armored().as_bytes())
                .unwrap();
        pkg.verify_signature(verifier).unwrap();
        pkg.verify_digests().unwrap();

        let (status, _, key) = get(&f.state, "/RPM-GPG-KEY", &[]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(key.as_ref(), signer.public_key_armored().as_bytes());
        assert_eq!(
            get(&f.state, "/repodata/repomd.xml.asc", &[]).await.0,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn range_requests_span_prefix_and_payload() {
        let f = fixture(true);
        let (_, _, full) = get(&f.state, RPM_URI, &[]).await;
        let prefix_len = match f.state.repo().get("sub dir/demo++.rpm") {
            Some(Entry::Rpm(e)) => e.prefix.len(),
            _ => unreachable!(),
        };
        for (start, end) in [
            (0, 10),
            (prefix_len - 5, prefix_len + 5),
            (prefix_len + 1, full.len() - 1),
        ] {
            let range = format!("bytes={start}-{}", end - 1);
            let (status, headers, body) = get(&f.state, RPM_URI, &[("range", &range)]).await;
            assert_eq!(status, StatusCode::PARTIAL_CONTENT);
            assert_eq!(body.as_ref(), &full[start..end], "range {range}");
            assert_eq!(
                headers[header::CONTENT_RANGE],
                format!("bytes {start}-{}/{}", end - 1, full.len()).as_str()
            );
        }
        let (status, _, body) = get(&f.state, RPM_URI, &[("range", "bytes=-4")]).await;
        assert_eq!(status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(body.as_ref(), &full[full.len() - 4..]);

        let past_end = format!("bytes={}-", full.len());
        let (status, headers, _) = get(&f.state, RPM_URI, &[("range", &past_end)]).await;
        assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            headers[header::CONTENT_RANGE],
            format!("bytes */{}", full.len()).as_str()
        );

        let (status, _, body) =
            get(&f.state, "/repodata/repomd.xml", &[("range", "bytes=0-4")]).await;
        assert_eq!(status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(body.as_ref(), b"<?xml");
    }

    #[tokio::test]
    async fn index_pages_and_redirects() {
        let f = fixture(false);
        let (status, headers, body) = get(&f.state, "/", &[]).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            headers[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains(r#"<a href="sub%20dir/">sub dir/</a>"#));
        assert!(html.contains(r#"<a href="repodata/">repodata/</a>"#));
        assert!(html.contains(r#"<a href="local.repo">local.repo</a>"#));
        assert!(!html.contains(r#"href="../""#));

        let (status, _, body) = get(&f.state, "/sub%20dir/", &[]).await;
        assert_eq!(status, StatusCode::OK);
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains(r#"<a href="demo++.rpm">demo++.rpm</a>"#));
        assert!(html.contains("demo-1.0-1.noarch \u{2014} A test package"));
        assert!(html.contains(r#"href="../""#));

        let (status, headers, _) = get(&f.state, "/sub%20dir", &[]).await;
        assert_eq!(status, StatusCode::PERMANENT_REDIRECT);
        assert_eq!(headers[header::LOCATION], "/sub%20dir/");

        assert_eq!(
            get(&f.state, "/missing/", &[]).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get(&f.state, "/missing.rpm", &[]).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get(&f.state, "/../etc/passwd", &[]).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get(&f.state, "/%2e%2e/etc/passwd", &[]).await.0,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn repo_file_reflects_signing() {
        let f = fixture(false);
        let (status, _, body) =
            get(&f.state, "/local.repo", &[("host", "example.test:8080")]).await;
        assert_eq!(status, StatusCode::OK);
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.starts_with("[local]\n"));
        assert!(text.contains("baseurl=http://example.test:8080/\n"));
        assert!(text.contains("gpgcheck=0\n") && text.contains("repo_gpgcheck=0\n"));
        assert!(!text.contains("gpgkey="));

        let f = fixture(true);
        let headers = [
            ("host", "internal"),
            ("x-forwarded-proto", "https"),
            ("x-forwarded-host", "repo.example"),
        ];
        let (_, _, body) = get(&f.state, "/local.repo", &headers).await;
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("baseurl=https://repo.example/\n"));
        assert!(text.contains("gpgcheck=1\n") && text.contains("repo_gpgcheck=1\n"));
        assert!(text.contains("gpgkey=https://repo.example/RPM-GPG-KEY\n"));
    }

    #[tokio::test]
    async fn health_endpoint() {
        let f = fixture(false);
        let (status, headers, body) = get(&f.state, "/healthz", &[]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert!(
            std::str::from_utf8(&body)
                .unwrap()
                .starts_with("ok packages=1 revision=")
        );

        f.state.set_scan_error(Some("disk on fire".into()));
        let (status, _, body) = get(&f.state, "/healthz", &[]).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(std::str::from_utf8(&body).unwrap().contains("disk on fire"));

        f.state.set_scan_error(None);
        assert_eq!(get(&f.state, "/healthz", &[]).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn stale_package_is_not_served() {
        let f = fixture(false);
        let path = match f.state.repo().get("sub dir/demo++.rpm") {
            Some(Entry::Rpm(e)) => e.abs_path.clone(),
            _ => unreachable!(),
        };
        std::fs::write(&path, b"replaced").unwrap();
        assert_eq!(
            get(&f.state, RPM_URI, &[]).await.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
