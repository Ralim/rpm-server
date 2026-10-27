//! Scanning the package directory and the resulting immutable repository
//! snapshot that the HTTP layer serves from.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use bytes::Bytes;
use tracing::{info, warn};

use crate::package::RpmEntry;
use crate::repodata;
use crate::signing::RepoSigner;

/// Path of the armored public key, relative to the repository root.
pub const KEY_PATH: &str = "RPM-GPG-KEY";
/// Top-level directory holding generated metadata; skipped when scanning.
const REPODATA_DIR: &str = "repodata";
const MAX_DEPTH: usize = 32;

#[derive(Debug, Clone)]
pub enum Entry {
    Rpm(Arc<RpmEntry>),
    Static {
        bytes: Bytes,
        content_type: &'static str,
    },
}

impl Entry {
    pub fn size(&self) -> u64 {
        match self {
            Entry::Rpm(e) => e.size,
            Entry::Static { bytes, .. } => bytes.len() as u64,
        }
    }
}

#[derive(Debug, Clone)]
pub enum DirItem {
    Dir(String),
    File { name: String, entry: Entry },
}

/// An immutable view of the repository: every servable path and its content.
#[derive(Debug)]
pub struct Repo {
    entries: BTreeMap<String, Entry>,
    pub package_count: usize,
    pub revision: u64,
    pub signs_repo: bool,
    pub signs_packages: bool,
}

impl Repo {
    pub fn build(
        mut packages: Vec<Arc<RpmEntry>>,
        signer: Option<&RepoSigner>,
        revision: u64,
    ) -> Result<Self> {
        packages.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
        let mut entries = BTreeMap::new();
        for f in repodata::generate(&packages, signer, revision)? {
            entries.insert(
                f.path,
                Entry::Static {
                    bytes: f.bytes,
                    content_type: f.content_type,
                },
            );
        }
        if let Some(s) = signer {
            entries.insert(
                KEY_PATH.to_owned(),
                Entry::Static {
                    bytes: Bytes::from(s.public_key_armored().to_owned()),
                    content_type: "application/pgp-keys",
                },
            );
        }
        let package_count = packages.len();
        for p in packages {
            entries.insert(p.rel_path.clone(), Entry::Rpm(p));
        }
        Ok(Self {
            entries,
            package_count,
            revision,
            signs_repo: signer.is_some(),
            signs_packages: signer.is_some_and(|s| s.signs_packages()),
        })
    }

    /// Looks up a file by its path relative to the root (no leading `/`).
    pub fn get(&self, path: &str) -> Option<&Entry> {
        self.entries.get(path)
    }

    /// Whether `dir` (relative, without trailing `/`) contains any entries.
    pub fn is_dir(&self, dir: &str) -> bool {
        dir.is_empty() || self.list_dir(&format!("{dir}/")).is_some()
    }

    /// Lists a directory given as `""` (root) or `"a/b/"`.
    pub fn list_dir(&self, dir: &str) -> Option<Vec<DirItem>> {
        let mut dirs = BTreeMap::new();
        let mut files = Vec::new();
        for (path, entry) in self
            .entries
            .range(dir.to_owned()..)
            .take_while(|(p, _)| p.starts_with(dir))
        {
            let rest = &path[dir.len()..];
            match rest.split_once('/') {
                Some((sub, _)) => {
                    dirs.insert(sub.to_owned(), ());
                }
                None => files.push(DirItem::File {
                    name: rest.to_owned(),
                    entry: entry.clone(),
                }),
            }
        }
        if dir.is_empty() || !dirs.is_empty() || !files.is_empty() {
            Some(dirs.into_keys().map(DirItem::Dir).chain(files).collect())
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileStamp {
    rel: String,
    abs: PathBuf,
    size: u64,
    mtime: SystemTime,
}

/// Recursively collects `.rpm` files under `dir`, whose repository path is
/// `rel`. Hidden entries and, at the repository root, `reserved` names are
/// skipped.
fn walk(
    dir: &Path,
    rel: &str,
    depth: usize,
    reserved: &[&str],
    out: &mut Vec<FileStamp>,
) -> Result<()> {
    let read = fs::read_dir(dir).with_context(|| format!("reading directory {}", dir.display()))?;
    for item in read {
        let item = item?;
        let Some(name) = item.file_name().to_str().map(str::to_owned) else {
            warn!(path = %item.path().display(), "skipping non UTF-8 file name");
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        if rel.is_empty() && reserved.contains(&name.as_str()) {
            warn!(path = %item.path().display(), "skipping entry with a reserved name");
            continue;
        }
        let child_rel = if rel.is_empty() {
            name.clone()
        } else {
            format!("{rel}/{name}")
        };
        // Follows symlinks, so linked files and directories are included.
        let meta = match fs::metadata(item.path()) {
            Ok(m) => m,
            Err(err) => {
                warn!(path = %item.path().display(), %err, "skipping unreadable entry");
                continue;
            }
        };
        if meta.is_dir() {
            if depth >= MAX_DEPTH {
                warn!(path = %item.path().display(), "maximum directory depth reached");
                continue;
            }
            if let Err(err) = walk(&item.path(), &child_rel, depth + 1, &[], out) {
                warn!(path = %item.path().display(), %err, "skipping directory");
            }
        } else if meta.is_file() && name.ends_with(".rpm") {
            out.push(FileStamp {
                rel: child_rel,
                abs: item.path(),
                size: meta.len(),
                mtime: meta.modified().unwrap_or(UNIX_EPOCH),
            });
        }
    }
    Ok(())
}

/// Loads `stamps` using all available cores; failures are logged and skipped.
fn load_parallel(stamps: &[&FileStamp], signer: Option<&RepoSigner>) -> Vec<Arc<RpmEntry>> {
    let workers = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .min(stamps.len().max(1));
    let next = AtomicUsize::new(0);
    let loaded = Mutex::new(Vec::with_capacity(stamps.len()));
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                while let Some(stamp) = stamps.get(next.fetch_add(1, Ordering::Relaxed)) {
                    match RpmEntry::load(&stamp.abs, stamp.rel.clone(), signer) {
                        Ok(e) => {
                            info!(path = %stamp.rel, nevra = %e.info.nevra(), "loaded package");
                            loaded.lock().unwrap().push(Arc::new(e));
                        }
                        Err(err) => warn!(path = %stamp.rel, "skipping package: {err:#}"),
                    }
                }
            });
        }
    });
    loaded.into_inner().unwrap()
}

/// Tracks the package directories and rebuilds the [`Repo`] when they change.
/// Unchanged packages (same path, size and mtime) are not re-read.
pub struct Scanner {
    root: PathBuf,
    /// Additional folders served under a fixed top-level directory name.
    extra_roots: Vec<(String, PathBuf)>,
    signer: Option<Arc<RepoSigner>>,
    cache: HashMap<String, Arc<RpmEntry>>,
    last: Option<Vec<FileStamp>>,
}

impl Scanner {
    pub fn new(root: PathBuf, signer: Option<Arc<RepoSigner>>) -> Self {
        Self {
            root,
            extra_roots: Vec::new(),
            signer,
            cache: HashMap::new(),
            last: None,
        }
    }

    /// Serves the packages in `dir` under `/<name>/`. A same-named entry at
    /// the top of the main folder is then ignored.
    pub fn with_extra_root(mut self, name: &str, dir: PathBuf) -> Self {
        self.extra_roots.push((name.to_owned(), dir));
        self
    }

    /// Returns a new snapshot, or `None` if nothing changed since the last scan.
    pub fn scan(&mut self) -> Result<Option<Repo>> {
        let mut reserved = vec![REPODATA_DIR];
        reserved.extend(self.extra_roots.iter().map(|(name, _)| name.as_str()));
        let mut stamps = Vec::new();
        walk(&self.root, "", 0, &reserved, &mut stamps)?;
        for (name, dir) in &self.extra_roots {
            if let Err(err) = walk(dir, name, 1, &[], &mut stamps) {
                warn!(dir = %dir.display(), "skipping folder: {err:#}");
            }
        }
        stamps.sort_by(|a, b| a.rel.cmp(&b.rel));
        if self.last.as_ref() == Some(&stamps) {
            return Ok(None);
        }

        let mut packages = Vec::with_capacity(stamps.len());
        let mut to_load = Vec::new();
        for stamp in &stamps {
            match self
                .cache
                .get(&stamp.rel)
                .filter(|e| e.file_size == stamp.size && e.mtime == stamp.mtime)
            {
                Some(e) => packages.push(e.clone()),
                None => to_load.push(stamp),
            }
        }
        packages.extend(load_parallel(&to_load, self.signer.as_deref()));

        self.cache = packages
            .iter()
            .map(|p| (p.rel_path.clone(), p.clone()))
            .collect();
        self.last = Some(stamps);

        let revision = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let repo = Repo::build(packages, self.signer.as_deref(), revision)?;
        info!(
            packages = repo.package_count,
            revision = repo.revision,
            "repository metadata generated"
        );
        Ok(Some(repo))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;

    fn names(items: &[DirItem]) -> Vec<String> {
        items
            .iter()
            .map(|i| match i {
                DirItem::Dir(d) => format!("{d}/"),
                DirItem::File { name, .. } => name.clone(),
            })
            .collect()
    }

    #[test]
    fn scan_layout_and_change_detection() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("nested/deeper")).unwrap();
        fs::create_dir_all(root.join("repodata")).unwrap();
        fs::create_dir_all(root.join(".hidden")).unwrap();
        fs::write(root.join("a.rpm"), testutil::build_rpm("a", "1", &[])).unwrap();
        fs::write(
            root.join("nested/deeper/b.rpm"),
            testutil::build_rpm("b", "1", &[]),
        )
        .unwrap();
        fs::write(
            root.join("repodata/ignored.rpm"),
            testutil::build_rpm("c", "1", &[]),
        )
        .unwrap();
        fs::write(
            root.join(".hidden/ignored.rpm"),
            testutil::build_rpm("d", "1", &[]),
        )
        .unwrap();
        fs::write(root.join("broken.rpm"), b"not an rpm").unwrap();
        fs::write(root.join("notes.txt"), b"ignored").unwrap();

        let mut scanner = Scanner::new(root.to_owned(), None);
        let repo = scanner.scan().unwrap().expect("first scan yields a repo");
        assert_eq!(repo.package_count, 2);
        assert!(!repo.signs_repo);
        assert!(repo.get(KEY_PATH).is_none());
        assert!(matches!(repo.get("a.rpm"), Some(Entry::Rpm(_))));
        assert!(matches!(
            repo.get("nested/deeper/b.rpm"),
            Some(Entry::Rpm(_))
        ));
        assert!(repo.get("repodata/ignored.rpm").is_none());
        assert!(repo.get("repodata/repomd.xml").is_some());

        assert_eq!(
            names(&repo.list_dir("").unwrap()),
            ["nested/", "repodata/", "a.rpm"]
        );
        assert_eq!(names(&repo.list_dir("nested/").unwrap()), ["deeper/"]);
        assert!(repo.list_dir("missing/").is_none());
        assert!(repo.is_dir("nested"));
        assert!(repo.is_dir("nested/deeper"));
        assert!(!repo.is_dir("nest"));
        assert!(!repo.is_dir("a.rpm"));

        assert!(scanner.scan().unwrap().is_none(), "unchanged directory");

        fs::remove_file(root.join("a.rpm")).unwrap();
        fs::write(root.join("c.rpm"), testutil::build_rpm("c", "2", &[])).unwrap();
        let repo = scanner.scan().unwrap().expect("changed directory");
        assert_eq!(repo.package_count, 2);
        assert!(repo.get("a.rpm").is_none());
        assert!(repo.get("c.rpm").is_some());
    }

    #[test]
    fn signed_repo_has_key_and_signature() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.rpm"), testutil::build_rpm("a", "1", &[])).unwrap();
        let signer = testutil::signer();
        let mut scanner = Scanner::new(dir.path().to_owned(), Some(signer.clone()));
        let repo = scanner.scan().unwrap().unwrap();
        assert!(repo.signs_repo && repo.signs_packages);
        match repo.get(KEY_PATH) {
            Some(Entry::Static { bytes, .. }) => {
                assert_eq!(bytes.as_ref(), signer.public_key_armored().as_bytes());
            }
            other => panic!("unexpected key entry: {other:?}"),
        }
        assert!(repo.get("repodata/repomd.xml.asc").is_some());
        match repo.get("a.rpm") {
            Some(Entry::Rpm(e)) => assert!(!e.prefix.is_empty()),
            other => panic!("unexpected package entry: {other:?}"),
        }
    }

    #[test]
    fn extra_root_is_served_under_its_name() {
        let main = tempfile::tempdir().unwrap();
        let extra = tempfile::tempdir().unwrap();
        fs::create_dir_all(main.path().join("downloaded")).unwrap();
        fs::write(
            main.path().join("a.rpm"),
            testutil::build_rpm("a", "1", &[]),
        )
        .unwrap();
        fs::write(
            main.path().join("downloaded/shadowed.rpm"),
            testutil::build_rpm("s", "1", &[]),
        )
        .unwrap();
        fs::write(
            extra.path().join("b.rpm"),
            testutil::build_rpm("b", "1", &[]),
        )
        .unwrap();
        fs::write(extra.path().join(".download-x.part"), b"partial").unwrap();

        let mut scanner = Scanner::new(main.path().to_owned(), None)
            .with_extra_root("downloaded", extra.path().to_owned());
        let repo = scanner.scan().unwrap().unwrap();
        assert_eq!(repo.package_count, 2);
        assert!(repo.get("a.rpm").is_some());
        assert!(repo.get("downloaded/b.rpm").is_some());
        assert!(repo.get("downloaded/shadowed.rpm").is_none());
        assert_eq!(names(&repo.list_dir("downloaded/").unwrap()), ["b.rpm"]);

        fs::write(
            extra.path().join("c.rpm"),
            testutil::build_rpm("c", "1", &[]),
        )
        .unwrap();
        let repo = scanner.scan().unwrap().expect("extra root change detected");
        assert!(repo.get("downloaded/c.rpm").is_some());

        // A missing extra folder is skipped rather than failing the scan.
        let mut scanner = Scanner::new(main.path().to_owned(), None)
            .with_extra_root("downloaded", PathBuf::from("/nonexistent/rpm-server-test"));
        assert_eq!(scanner.scan().unwrap().unwrap().package_count, 1);
    }

    #[test]
    fn missing_root_is_an_error() {
        let mut scanner = Scanner::new(PathBuf::from("/nonexistent/rpm-server-test"), None);
        assert!(scanner.scan().is_err());
    }
}
