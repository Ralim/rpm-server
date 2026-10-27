//! Reading RPM headers into the data needed for repository metadata, and
//! describing the exact bytes served for each package.

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use rpm::{
    Dependency, DependencyFlags, FileFlags, FileType, IndexSignatureTag, IndexTag, PackageMetadata,
};
use sha2::{Digest, Sha256};

use crate::signing::RepoSigner;

/// createrepo_c keeps only the newest N changelog entries by default.
const CHANGELOG_LIMIT: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dep {
    pub name: String,
    /// One of EQ/LT/GT/LE/GE, or `None` when unversioned.
    pub flags: Option<&'static str>,
    pub epoch: Option<String>,
    pub ver: Option<String>,
    pub rel: Option<String>,
    pub pre: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Regular,
    Dir,
    Ghost,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageFile {
    pub path: String,
    pub kind: FileKind,
}

impl PackageFile {
    /// createrepo_c's rule for files listed in primary.xml (`cr_is_primary`).
    pub fn is_primary(&self) -> bool {
        self.path.starts_with("/etc/")
            || self.path == "/usr/lib/sendmail"
            || self.path.contains("bin/")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Changelog {
    pub author: String,
    pub date: u64,
    pub text: String,
}

/// Everything from the RPM header that ends up in repodata.
#[derive(Debug, Clone)]
pub struct PackageInfo {
    pub name: String,
    pub epoch: u32,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub summary: String,
    pub description: String,
    pub url: String,
    pub packager: String,
    pub vendor: String,
    pub license: String,
    pub group: String,
    pub buildhost: String,
    pub sourcerpm: String,
    pub build_time: u64,
    pub installed_size: u64,
    pub archive_size: u64,
    pub header_start: u64,
    pub header_end: u64,
    pub provides: Vec<Dep>,
    pub requires: Vec<Dep>,
    pub conflicts: Vec<Dep>,
    pub obsoletes: Vec<Dep>,
    pub recommends: Vec<Dep>,
    pub suggests: Vec<Dep>,
    pub supplements: Vec<Dep>,
    pub enhances: Vec<Dep>,
    pub files: Vec<PackageFile>,
    /// Oldest first, limited to [`CHANGELOG_LIMIT`].
    pub changelogs: Vec<Changelog>,
}

fn opt(r: Result<&str, rpm::Error>) -> String {
    r.map(str::to_owned).unwrap_or_default()
}

fn flag_str(flags: DependencyFlags) -> Option<&'static str> {
    let cmp = flags & (DependencyFlags::LESS | DependencyFlags::GREATER | DependencyFlags::EQUAL);
    match cmp {
        c if c == DependencyFlags::EQUAL => Some("EQ"),
        c if c == DependencyFlags::LESS => Some("LT"),
        c if c == DependencyFlags::GREATER => Some("GT"),
        c if c == DependencyFlags::LE => Some("LE"),
        c if c == DependencyFlags::GE => Some("GE"),
        _ => None,
    }
}

/// Splits `[epoch:]version[-release]`; epoch defaults to "0" when a version is present.
fn split_evr(evr: &str) -> (Option<String>, Option<String>, Option<String>) {
    if evr.is_empty() {
        return (None, None, None);
    }
    let (epoch, rest) = match evr.split_once(':') {
        Some((e, r)) if !e.is_empty() && e.bytes().all(|b| b.is_ascii_digit()) => (e, r),
        _ => ("0", evr),
    };
    let (ver, rel) = match rest.rsplit_once('-') {
        Some((v, r)) => (v, Some(r.to_owned())),
        None => (rest, None),
    };
    (Some(epoch.to_owned()), Some(ver.to_owned()), rel)
}

/// createrepo_c marks requires needed by install-time scriptlets with `pre="1"`.
fn is_pre(flags: DependencyFlags) -> bool {
    flags.intersects(
        DependencyFlags::PREREQ
            | DependencyFlags::SCRIPT_PRE
            | DependencyFlags::SCRIPT_POST
            | DependencyFlags::PRETRANS
            | DependencyFlags::POSTTRANS,
    )
}

fn convert(deps: Vec<Dependency>, with_pre: bool) -> Vec<Dep> {
    deps.into_iter()
        .filter(|d| !d.name.starts_with("rpmlib("))
        .map(|d| {
            let flags = flag_str(d.flags);
            let (epoch, ver, rel) = if flags.is_some() {
                split_evr(&d.version)
            } else {
                (None, None, None)
            };
            Dep {
                flags,
                pre: with_pre && is_pre(d.flags),
                name: d.name,
                epoch,
                ver,
                rel,
            }
        })
        .collect()
}

/// Drops requires the package satisfies itself, plus exact duplicates.
///
/// Self-owned file requires must go: dnf only loads primary.xml by default,
/// which lists just a subset of files, so a require on e.g. a file under
/// /usr/share would otherwise look unsatisfiable.
fn filter_requires(requires: Vec<Dep>, provides: &[Dep], files: &[PackageFile]) -> Vec<Dep> {
    let own_files: HashSet<&str> = files.iter().map(|f| f.path.as_str()).collect();
    let mut seen = Vec::<Dep>::new();
    for dep in requires {
        if dep.name.starts_with('/') && own_files.contains(dep.name.as_str()) {
            continue;
        }
        let self_provided = provides.iter().any(|p| {
            p.name == dep.name
                && p.flags == dep.flags
                && p.epoch == dep.epoch
                && p.ver == dep.ver
                && p.rel == dep.rel
        });
        if self_provided || seen.contains(&dep) {
            continue;
        }
        seen.push(dep);
    }
    seen
}

/// Uncompressed payload size; v6 packages carry none of these tags.
pub fn archive_size(m: &PackageMetadata) -> u64 {
    m.signature
        .get_entry_data_as_u64(IndexSignatureTag::RPMSIGTAG_LONGARCHIVESIZE)
        .or_else(|_| {
            m.signature
                .get_entry_data_as_u32(IndexSignatureTag::RPMSIGTAG_PAYLOADSIZE)
                .map(u64::from)
        })
        .or_else(|_| {
            m.header
                .get_entry_data_as_u64(IndexTag::RPMTAG_LONGARCHIVESIZE)
        })
        .or_else(|_| {
            m.header
                .get_entry_data_as_u32(IndexTag::RPMTAG_ARCHIVESIZE)
                .map(u64::from)
        })
        .unwrap_or(0)
}

impl PackageInfo {
    /// `archive_size` is passed separately because re-signing drops the
    /// legacy signature-header size tags.
    pub fn from_metadata(m: &PackageMetadata, archive_size: u64) -> Result<Self> {
        let offsets = m.get_package_segment_offsets();

        let files: Vec<PackageFile> = m
            .get_file_entries()?
            .into_iter()
            .map(|f| PackageFile {
                path: f.path().to_string_lossy().into_owned(),
                kind: if f.file_type() == FileType::Dir {
                    FileKind::Dir
                } else if f.flags().contains(FileFlags::GHOST) {
                    FileKind::Ghost
                } else {
                    FileKind::Regular
                },
            })
            .collect();

        // Newest CHANGELOG_LIMIT entries, written oldest first.
        let mut changelogs: Vec<Changelog> = m
            .get_changelog_entries()?
            .into_iter()
            .map(|c| Changelog {
                author: c.name,
                date: c.timestamp,
                text: c.description,
            })
            .collect();
        changelogs.sort_by_key(|c| std::cmp::Reverse(c.date));
        changelogs.truncate(CHANGELOG_LIMIT);
        changelogs.reverse();

        let provides = convert(m.get_provides()?, false);
        let requires = filter_requires(convert(m.get_requires()?, true), &provides, &files);

        Ok(Self {
            name: m.get_name()?.to_owned(),
            epoch: m.get_epoch().unwrap_or(0),
            version: m.get_version()?.to_owned(),
            release: m.get_release()?.to_owned(),
            arch: if m.is_source_package() {
                "src".to_owned()
            } else {
                m.get_arch()?.to_owned()
            },
            summary: opt(m.get_summary()),
            description: opt(m.get_description()),
            url: opt(m.get_url()),
            packager: opt(m.get_packager()),
            vendor: opt(m.get_vendor()),
            license: opt(m.get_license()),
            group: opt(m.get_group()),
            buildhost: opt(m.get_build_host()),
            sourcerpm: opt(m.get_source_rpm()),
            build_time: m.get_build_time().unwrap_or(0),
            installed_size: m.get_installed_size().unwrap_or(0),
            archive_size,
            header_start: offsets.header,
            header_end: offsets.payload,
            provides,
            requires,
            conflicts: convert(m.get_conflicts()?, false),
            obsoletes: convert(m.get_obsoletes()?, false),
            recommends: convert(m.get_recommends()?, false),
            suggests: convert(m.get_suggests()?, false),
            supplements: convert(m.get_supplements()?, false),
            enhances: convert(m.get_enhances()?, false),
            files,
            changelogs,
        })
    }

    /// `name-[epoch:]version-release.arch`
    pub fn nevra(&self) -> String {
        if self.epoch == 0 {
            format!(
                "{}-{}-{}.{}",
                self.name, self.version, self.release, self.arch
            )
        } else {
            format!(
                "{}-{}:{}-{}.{}",
                self.name, self.epoch, self.version, self.release, self.arch
            )
        }
    }
}

/// A package as served: `prefix` followed by the source file from `body_offset`.
///
/// Unsigned packages have an empty prefix and offset 0. Re-signed packages
/// carry a freshly written lead + signature header + main header in `prefix`,
/// and the original payload is streamed from disk after it.
#[derive(Debug)]
pub struct RpmEntry {
    /// Path relative to the repository root, using `/` separators.
    pub rel_path: String,
    pub abs_path: PathBuf,
    pub file_size: u64,
    pub mtime: SystemTime,
    pub prefix: Bytes,
    pub body_offset: u64,
    /// Size of the served bytes.
    pub size: u64,
    /// SHA-256 (hex) of the served bytes.
    pub sha256: String,
    pub info: PackageInfo,
}

impl RpmEntry {
    pub fn load(abs_path: &Path, rel_path: String, signer: Option<&RepoSigner>) -> Result<Self> {
        let file =
            File::open(abs_path).with_context(|| format!("opening {}", abs_path.display()))?;
        let fs_meta = file.metadata()?;
        let mut reader = BufReader::new(file);
        let metadata = PackageMetadata::parse(&mut reader)
            .with_context(|| format!("parsing RPM header of {}", abs_path.display()))?;
        let archive = archive_size(&metadata);

        let (metadata, prefix, body_offset) = match signer.filter(|s| s.signs_packages()) {
            Some(s) => {
                let payload_offset = metadata.get_package_segment_offsets().payload;
                let metadata = s
                    .resign_metadata(metadata)
                    .with_context(|| format!("signing {}", abs_path.display()))?;
                let mut prefix = Vec::new();
                metadata.write(&mut prefix)?;
                (metadata, Bytes::from(prefix), payload_offset)
            }
            None => (metadata, Bytes::new(), 0),
        };
        let info = PackageInfo::from_metadata(&metadata, archive)
            .with_context(|| format!("reading metadata of {}", abs_path.display()))?;

        let mut hasher = Sha256::new();
        hasher.update(&prefix);
        let mut file = reader.into_inner();
        file.seek(SeekFrom::Start(body_offset))?;
        let mut buf = vec![0u8; 256 * 1024];
        let mut copied = 0u64;
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            copied += n as u64;
        }
        if body_offset + copied != fs_meta.len() {
            bail!("{} changed while being read", abs_path.display());
        }

        Ok(Self {
            rel_path,
            abs_path: abs_path.to_owned(),
            file_size: fs_meta.len(),
            mtime: fs_meta.modified().unwrap_or(UNIX_EPOCH),
            size: prefix.len() as u64 + copied,
            prefix,
            body_offset,
            sha256: hex::encode(hasher.finalize()),
            info,
        })
    }

    pub fn mtime_secs(&self) -> u64 {
        self.mtime
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;
    use std::io::Cursor;

    fn dep(name: &str) -> Dep {
        Dep {
            name: name.into(),
            flags: None,
            epoch: None,
            ver: None,
            rel: None,
            pre: false,
        }
    }

    #[test]
    fn evr_splitting() {
        assert_eq!(split_evr(""), (None, None, None));
        assert_eq!(
            split_evr("1.0"),
            (Some("0".into()), Some("1.0".into()), None)
        );
        assert_eq!(
            split_evr("2:1.0-3.fc44"),
            (Some("2".into()), Some("1.0".into()), Some("3.fc44".into()))
        );
        assert_eq!(
            split_evr("1.0-1-2"),
            (Some("0".into()), Some("1.0-1".into()), Some("2".into()))
        );
    }

    #[test]
    fn flag_mapping() {
        assert_eq!(flag_str(DependencyFlags::EQUAL), Some("EQ"));
        assert_eq!(flag_str(DependencyFlags::GE), Some("GE"));
        assert_eq!(flag_str(DependencyFlags::LE), Some("LE"));
        assert_eq!(flag_str(DependencyFlags::LESS), Some("LT"));
        assert_eq!(
            flag_str(DependencyFlags::GREATER | DependencyFlags::SCRIPT_PRE),
            Some("GT")
        );
        assert_eq!(flag_str(DependencyFlags::ANY), None);
    }

    #[test]
    fn primary_file_rule() {
        let f = |p: &str| PackageFile {
            path: p.into(),
            kind: FileKind::Regular,
        };
        assert!(f("/etc/foo.conf").is_primary());
        assert!(f("/usr/bin/foo").is_primary());
        assert!(f("/opt/x/sbin/y").is_primary());
        assert!(f("/usr/lib/sendmail").is_primary());
        assert!(!f("/usr/bin").is_primary());
        assert!(!f("/usr/share/foo").is_primary());
    }

    #[test]
    fn requires_filtering() {
        let files = vec![PackageFile {
            path: "/usr/share/x".into(),
            kind: FileKind::Regular,
        }];
        let provides = vec![dep("cap")];
        let out = filter_requires(
            vec![
                dep("/usr/share/x"),
                dep("cap"),
                dep("bash"),
                dep("bash"),
                dep("/bin/sh"),
            ],
            &provides,
            &files,
        );
        let names: Vec<_> = out.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["bash", "/bin/sh"]);
    }

    #[test]
    fn info_from_built_package() {
        let bytes = testutil::build_rpm("demo", "1.0", &["other-thing"]);
        let m = PackageMetadata::parse(&mut Cursor::new(&bytes)).unwrap();
        let info = PackageInfo::from_metadata(&m, archive_size(&m)).unwrap();
        assert_eq!(info.nevra(), "demo-1.0-1.noarch");
        assert_eq!(info.license, "MIT");
        assert!(info.header_start > 96 && info.header_end > info.header_start);

        let req: Vec<_> = info
            .requires
            .iter()
            .map(|d| (d.name.as_str(), d.pre))
            .collect();
        assert!(req.contains(&("/bin/sh", true)));
        assert!(req.contains(&("other-thing", false)));
        assert!(!req.iter().any(|(n, _)| n.starts_with("rpmlib(")));
        assert!(!req.iter().any(|(n, _)| *n == "/usr/share/demo/data"));
        assert!(!req.iter().any(|(n, _)| *n == "demo-capability"));
        let bash = info.requires.iter().find(|d| d.name == "bash").unwrap();
        assert_eq!(bash.flags, Some("GE"));
        assert_eq!(bash.epoch.as_deref(), Some("1"));
        assert_eq!(bash.ver.as_deref(), Some("4.0"));
        assert_eq!(bash.rel.as_deref(), Some("1"));

        let kind = |p: &str| info.files.iter().find(|f| f.path == p).unwrap().kind;
        assert_eq!(kind("/etc/demo"), FileKind::Dir);
        assert_eq!(kind("/etc/demo/state"), FileKind::Ghost);
        assert_eq!(kind("/usr/bin/demo"), FileKind::Regular);

        let logs: Vec<_> = info.changelogs.iter().map(|c| c.text.as_str()).collect();
        assert_eq!(logs, ["- first", "- second"]);
    }

    #[test]
    fn entry_unsigned_matches_file() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = testutil::build_rpm("demo", "1.0", &[]);
        let path = dir.path().join("demo.rpm");
        std::fs::write(&path, &bytes).unwrap();
        let e = RpmEntry::load(&path, "demo.rpm".into(), None).unwrap();
        assert!(e.prefix.is_empty());
        assert_eq!(e.size, bytes.len() as u64);
        assert_eq!(e.sha256, hex::encode(Sha256::digest(&bytes)));
    }

    #[test]
    fn entry_signed_header_range_matches_served_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = testutil::build_rpm("demo", "1.0", &[]);
        let path = dir.path().join("demo.rpm");
        std::fs::write(&path, &bytes).unwrap();
        let signer = testutil::signer();
        let e = RpmEntry::load(&path, "demo.rpm".into(), Some(&signer)).unwrap();

        let mut served = e.prefix.to_vec();
        served.extend_from_slice(&bytes[e.body_offset as usize..]);
        assert_eq!(e.size, served.len() as u64);
        assert_eq!(e.sha256, hex::encode(Sha256::digest(&served)));

        let reparsed = PackageMetadata::parse(&mut Cursor::new(&served)).unwrap();
        let offsets = reparsed.get_package_segment_offsets();
        assert_eq!(e.info.header_start, offsets.header);
        assert_eq!(e.info.header_end, offsets.payload);
        assert_eq!(&served[offsets.header as usize..][..3], &[0x8e, 0xad, 0xe8]);
    }
}
