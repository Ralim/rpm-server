//! Converts `.deb` packages in a folder to RPMs stored next to them
//! (`tool_1.0_amd64.deb` gives `tool_1.0_amd64.rpm`). The scanner then
//! serves the `.rpm` files like any others, and a restart does not convert
//! them again. The `.deb` files themselves are never served.

pub(crate) mod archive;
mod control;
#[cfg(test)]
pub(crate) mod testutil;
mod to_rpm;

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, ErrorKind, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use tracing::{info, warn};

use crate::repo::{FileStamp, walk};

/// Path under which the deb folder (its converted RPMs) appears in the
/// repository.
pub const URL_PREFIX: &str = "deb";
/// Limit on the total size of a package's files, which are held in memory
/// while the RPM is built. Matches the download size limit for online
/// sources.
const MAX_UNPACKED_BYTES: u64 = 4 << 30;
const DEB_SUFFIX: &str = ".deb";
const RPM_EXTENSION: &str = "rpm";

/// Converts a `.deb` read from `deb` into an RPM package.
pub fn convert(deb: impl Read) -> Result<rpm::Package> {
    to_rpm::build_rpm(archive::read_deb(deb, MAX_UNPACKED_BYTES)?)
}

/// The path of the RPM converted from the `.deb` at `deb`.
fn get_rpm_path(deb: &Path) -> PathBuf {
    deb.with_extension(RPM_EXTENSION)
}

/// Whether a `.deb` modified at `deb_mtime` needs converting, given the
/// modification time of its RPM (`None` when there is none yet). A `.deb`
/// replaced after its conversion is converted again.
fn needs_conversion(deb_mtime: SystemTime, rpm_mtime: Option<SystemTime>) -> bool {
    rpm_mtime.is_none_or(|rpm| rpm < deb_mtime)
}

/// Converts `deb_path` and stores the result at `rpm_path`, replacing any
/// previous one atomically. Returns the NEVRA of the package.
fn convert_file(deb_path: &Path, rpm_path: &Path) -> Result<String> {
    let deb = File::open(deb_path).with_context(|| format!("opening {}", deb_path.display()))?;
    let package = convert(BufReader::new(deb))?;
    let nevra = package.metadata.get_nevra()?.to_string();
    let dir = rpm_path
        .parent()
        .with_context(|| format!("{} has no parent folder", rpm_path.display()))?;
    // Hidden name: the scanner and watcher ignore it while it is written.
    let tmp = tempfile::Builder::new()
        .prefix(".deb-convert-")
        .suffix(".part")
        .tempfile_in(dir)
        .with_context(|| format!("creating a temporary file in {}", dir.display()))?;
    let mut writer = BufWriter::new(tmp.as_file());
    package
        .write(&mut writer)
        .with_context(|| format!("writing {}", tmp.path().display()))?;
    writer.flush()?;
    drop(writer);
    tmp.as_file().sync_all()?;
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o644))?;
    tmp.persist(rpm_path)
        .with_context(|| format!("storing {}", rpm_path.display()))?;
    Ok(nevra)
}

/// Size and modification time of a `.deb`, to tell whether it changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileVersion {
    size: u64,
    mtime: SystemTime,
}

impl From<&FileStamp> for FileVersion {
    fn from(stamp: &FileStamp) -> Self {
        Self {
            size: stamp.size,
            mtime: stamp.mtime,
        }
    }
}

/// Converts the `.deb` files under a folder (searched recursively, hidden
/// entries skipped) whose RPM is missing or older than the `.deb`.
pub struct DebConverter {
    dir: PathBuf,
    /// `.deb` files that failed to convert, so an unchanged one is not
    /// retried (and its failure logged again) on every scan.
    failed: HashMap<PathBuf, FileVersion>,
}

impl DebConverter {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            failed: HashMap::new(),
        }
    }

    /// Converts every pending `.deb` and returns how many were converted.
    /// A package that fails to convert is logged and skipped; `Err` means
    /// the folder itself could not be read.
    pub fn convert_pending(&mut self) -> Result<usize> {
        let mut debs = Vec::new();
        walk(&self.dir, URL_PREFIX, DEB_SUFFIX, 1, &mut debs)?;
        self.failed
            .retain(|path, _| debs.iter().any(|deb| &deb.abs == path));

        let mut converted = 0;
        for deb in &debs {
            let rpm_path = get_rpm_path(&deb.abs);
            let rpm_mtime = match fs::metadata(&rpm_path) {
                Ok(meta) => Some(meta.modified().unwrap_or(UNIX_EPOCH)),
                Err(err) if err.kind() == ErrorKind::NotFound => None,
                Err(err) => {
                    warn!(path = %rpm_path.display(), %err, "skipping .deb: cannot read its converted RPM");
                    continue;
                }
            };
            let version = FileVersion::from(deb);
            if !needs_conversion(deb.mtime, rpm_mtime)
                || self.failed.get(&deb.abs) == Some(&version)
            {
                continue;
            }
            match convert_file(&deb.abs, &rpm_path) {
                Ok(nevra) => {
                    info!(path = %deb.rel, nevra = %nevra, "converted .deb to RPM");
                    self.failed.remove(&deb.abs);
                    converted += 1;
                }
                Err(err) => {
                    warn!(path = %deb.rel, "converting .deb failed: {err:#}");
                    self.failed.insert(deb.abs.clone(), version);
                }
            }
        }
        Ok(converted)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::deb::archive::Compression;
    use crate::deb::testutil::DebBuilder;

    fn demo_deb(version: &str) -> Vec<u8> {
        DebBuilder::new("demo", version, "all")
            .file("/usr/bin/demo", b"#!/bin/sh\necho demo\n", 0o755)
            .build(Compression::Xz)
    }

    fn set_mtime(path: &Path, mtime: SystemTime) {
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(mtime)
            .unwrap();
    }

    fn rpm_version(path: &Path) -> String {
        let pkg = rpm::Package::open(path).unwrap();
        pkg.metadata.get_version().unwrap().to_owned()
    }

    #[test]
    fn conversion_decision() {
        let t = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert!(needs_conversion(t, None));
        assert!(needs_conversion(t, Some(t - Duration::from_secs(1))));
        assert!(!needs_conversion(t, Some(t)));
        assert!(!needs_conversion(t, Some(t + Duration::from_secs(1))));
        assert_eq!(
            get_rpm_path(Path::new("/d/tool_1.0_amd64.deb")),
            Path::new("/d/tool_1.0_amd64.rpm")
        );
    }

    #[test]
    fn converts_new_and_replaced_packages_once() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::create_dir_all(root.join(".hidden")).unwrap();
        fs::write(root.join("nested/demo_1.0_all.deb"), demo_deb("1.0")).unwrap();
        fs::write(root.join(".hidden/skipped.deb"), demo_deb("1.0")).unwrap();
        fs::write(root.join("broken.deb"), b"not a deb").unwrap();

        let mut converter = DebConverter::new(root.to_owned());
        assert_eq!(converter.convert_pending().unwrap(), 1);
        let rpm = root.join("nested/demo_1.0_all.rpm");
        assert_eq!(rpm_version(&rpm), "1.0");
        assert_eq!(
            fs::metadata(&rpm).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert!(!root.join(".hidden/skipped.rpm").exists());
        assert!(!root.join("broken.rpm").exists());
        assert!(converter.failed.contains_key(&root.join("broken.deb")));
        let leftovers: Vec<_> = fs::read_dir(root.join("nested"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.to_string_lossy().starts_with('.'))
            .collect();
        assert!(leftovers.is_empty(), "temporary files left: {leftovers:?}");

        // Nothing changed: no conversions, the failure is not retried.
        assert_eq!(converter.convert_pending().unwrap(), 0);
        // A new converter (a restart) does not convert existing RPMs again,
        // but retries the failed package once.
        let mut restarted = DebConverter::new(root.to_owned());
        assert_eq!(restarted.convert_pending().unwrap(), 0);
        assert!(restarted.failed.contains_key(&root.join("broken.deb")));

        // A .deb replaced after its conversion is converted again.
        let deb = root.join("nested/demo_1.0_all.deb");
        fs::write(&deb, demo_deb("2.0")).unwrap();
        let deb_mtime = fs::metadata(&deb).unwrap().modified().unwrap();
        set_mtime(&rpm, deb_mtime - Duration::from_secs(10));
        assert_eq!(converter.convert_pending().unwrap(), 1);
        assert_eq!(rpm_version(&rpm), "2.0");

        // A fixed package is converted, and removed .deb files are forgotten.
        fs::write(root.join("broken.deb"), demo_deb("3.0")).unwrap();
        assert_eq!(converter.convert_pending().unwrap(), 1);
        assert!(converter.failed.is_empty());
        assert_eq!(rpm_version(&root.join("broken.rpm")), "3.0");
    }

    #[test]
    fn missing_folder_is_an_error() {
        let mut converter = DebConverter::new(PathBuf::from("/nonexistent/rpm-server-test"));
        assert!(converter.convert_pending().is_err());
    }
}
