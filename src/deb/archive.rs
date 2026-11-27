//! Reading binary `.deb` packages: an `ar` archive holding `debian-binary`,
//! `control.tar[.gz|.xz|.zst]` and `data.tar[.gz|.xz|.zst]`, in that order
//! (deb(5)).

use std::collections::HashSet;
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Component, Path};

use anyhow::{Context, Result, bail};
use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};
use tracing::warn;

use super::control::{Control, parse_conffiles};

/// Format versions this reader understands: deb(5) defines `2.0`, and
/// dpkg accepts any `2.x`.
const FORMAT_MAJOR: &str = "2.";
/// Control members that dpkg runs or acts on at install time. They are not
/// converted (see [`DebPackage::dropped_control_members`]).
const MAINTAINER_SCRIPTS: &[&str] = &[
    "preinst", "postinst", "prerm", "postrm", "config", "triggers",
];

/// One entry of `data.tar`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataEntry {
    /// Absolute, normalised install path, e.g. `/usr/bin/tool`.
    pub path: String,
    pub kind: DataKind,
    pub meta: EntryMeta,
}

/// Ownership, permissions and timestamp of a `data.tar` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryMeta {
    /// Permission bits (`0o7777` mask) from the tar header.
    pub permissions: u16,
    /// Owner name; `root` when the tar header has none.
    pub user: String,
    /// Group name; `root` when the tar header has none.
    pub group: String,
    /// Modification time, seconds since the Unix epoch.
    pub mtime_s: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataKind {
    File(Vec<u8>),
    Dir,
    /// Symbolic link to the given target, stored verbatim.
    Symlink(String),
    /// Hard link to an earlier entry, given by its absolute path.
    HardLink(String),
}

/// The parts of a `.deb` needed to build an RPM.
#[derive(Debug)]
pub struct DebPackage {
    pub control: Control,
    /// Absolute paths of the package's configuration files.
    pub conffiles: HashSet<String>,
    /// Maintainer scripts and triggers present in `control.tar`, which are
    /// not carried over.
    pub dropped_control_members: Vec<String>,
    pub entries: Vec<DataEntry>,
}

/// Reads a `.deb` from `reader`. Regular files are held in memory; the
/// package is rejected once their total size exceeds `max_unpacked_bytes`.
pub fn read_deb(reader: impl Read, max_unpacked_bytes: u64) -> Result<DebPackage> {
    let mut archive = ar::Archive::new(reader);
    let mut format_seen = false;
    let mut control: Option<ControlMembers> = None;
    while let Some(member) = archive.next_entry() {
        let mut member = member.context("reading ar archive")?;
        let name = String::from_utf8_lossy(member.header().identifier())
            .trim_end_matches('/')
            .to_owned();
        if !format_seen {
            if name != "debian-binary" {
                bail!("not a Debian package: first member is {name:?}, expected debian-binary");
            }
            let mut version = String::new();
            member
                .by_ref()
                .take(64)
                .read_to_string(&mut version)
                .context("reading debian-binary")?;
            if !version.starts_with(FORMAT_MAJOR) {
                bail!("unsupported .deb format version {:?}", version.trim());
            }
            format_seen = true;
            continue;
        }
        // deb(5): members inserted before control.tar or data.tar that older
        // readers must ignore have names starting with an underscore.
        if name.starts_with('_') {
            continue;
        }
        let Some(control_members) = control.take() else {
            let compression = tar_compression(&name, "control.tar")?;
            control = Some(
                read_control_tar(compression.decoder(member)?)
                    .with_context(|| format!("reading {name}"))?,
            );
            continue;
        };
        let compression = tar_compression(&name, "data.tar")?;
        let entries = read_data_tar(compression.decoder(member)?, max_unpacked_bytes)
            .with_context(|| format!("reading {name}"))?;
        // deb(5): readers ignore any members after data.tar.
        return Ok(DebPackage {
            control: control_members.control,
            conffiles: control_members.conffiles,
            dropped_control_members: control_members.dropped,
            entries,
        });
    }
    if !format_seen {
        bail!("not a Debian package: empty ar archive");
    }
    match control {
        None => bail!("missing control.tar member"),
        Some(_) => bail!("missing data.tar member"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Compression {
    None,
    Gzip,
    Xz,
    Zstd,
}

/// The compression of a `control.tar`/`data.tar` member from its name.
/// bzip2 and lzma `data.tar` members are deprecated in dpkg and rejected.
pub(super) fn tar_compression(name: &str, expected: &str) -> Result<Compression> {
    let Some(suffix) = name.strip_prefix(expected) else {
        bail!("unexpected member {name:?}, expected {expected}");
    };
    Ok(match suffix {
        "" => Compression::None,
        ".gz" => Compression::Gzip,
        ".xz" => Compression::Xz,
        ".zst" => Compression::Zstd,
        _ => bail!("unsupported compression of member {name:?}"),
    })
}

impl Compression {
    fn decoder<'a>(self, reader: impl Read + 'a) -> Result<Box<dyn Read + 'a>> {
        Ok(match self {
            Compression::None => Box::new(reader),
            Compression::Gzip => Box::new(flate2::read::MultiGzDecoder::new(reader)),
            Compression::Xz => Box::new(lzma_rust2::XzReader::new(reader, true)),
            Compression::Zstd => Box::new(ZstdReader::new(BufReader::new(reader))),
        })
    }
}

/// Decodes a zstd stream of one or more frames (RFC 8878 §3.1: a stream may
/// concatenate frames), verifying each frame's content checksum when present.
struct ZstdReader<R: BufRead> {
    source: R,
    decoder: FrameDecoder,
    in_frame: bool,
}

impl<R: BufRead> ZstdReader<R> {
    fn new(source: R) -> Self {
        Self {
            source,
            decoder: FrameDecoder::new(),
            in_frame: false,
        }
    }
}

impl<R: BufRead> Read for ZstdReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.decoder.can_collect() > 0 {
                return self.decoder.read(buf);
            }
            if self.in_frame && !self.decoder.is_finished() {
                self.decoder
                    .decode_blocks(&mut self.source, BlockDecodingStrategy::UptoBlocks(1))
                    .map_err(io::Error::other)?;
                continue;
            }
            if self.in_frame {
                if let (Some(stored), Some(calculated)) = (
                    self.decoder.get_checksum_from_data(),
                    self.decoder.get_calculated_checksum(),
                ) && stored != calculated
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "zstd frame checksum mismatch: stored {stored:#010x}, \
                             calculated {calculated:#010x}"
                        ),
                    ));
                }
                self.in_frame = false;
            }
            if self.source.fill_buf()?.is_empty() {
                return Ok(0);
            }
            self.decoder
                .reset(&mut self.source)
                .map_err(io::Error::other)?;
            self.in_frame = true;
        }
    }
}

/// The parsed members of `control.tar`.
#[derive(Debug)]
struct ControlMembers {
    control: Control,
    conffiles: HashSet<String>,
    dropped: Vec<String>,
}

/// Size limit for `control` and `conffiles`, which are small text files.
const MAX_CONTROL_MEMBER_BYTES: u64 = 1 << 20;

fn read_control_tar(reader: impl Read) -> Result<ControlMembers> {
    let mut control = None;
    let mut conffiles = HashSet::new();
    let mut dropped = Vec::new();
    let mut archive = tar::Archive::new(reader);
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        let name = entry
            .path()?
            .to_string_lossy()
            .trim_start_matches("./")
            .to_owned();
        let mut read_text = |what: &str| -> Result<String> {
            if entry.size() > MAX_CONTROL_MEMBER_BYTES {
                bail!("{what} exceeds {MAX_CONTROL_MEMBER_BYTES} bytes");
            }
            let mut text = String::new();
            entry
                .read_to_string(&mut text)
                .with_context(|| format!("reading {what}"))?;
            Ok(text)
        };
        match name.as_str() {
            "control" => {
                let text = read_text("control")?;
                control = Some(text.parse().context("parsing control")?);
            }
            "conffiles" => conffiles = parse_conffiles(&read_text("conffiles")?),
            other if MAINTAINER_SCRIPTS.contains(&other) => dropped.push(other.to_owned()),
            // md5sums, shlibs, symbols, templates, ...: not needed.
            _ => {}
        }
    }
    Ok(ControlMembers {
        control: control.context("control.tar has no control file")?,
        conffiles,
        dropped,
    })
}

/// Turns a tar path such as `./usr/bin/tool` into `/usr/bin/tool`, or `None`
/// for the archive root. Paths leaving the root are rejected.
fn install_path(path: &Path) -> Result<Option<String>> {
    let mut out = String::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(part) => {
                let part = part
                    .to_str()
                    .with_context(|| format!("non UTF-8 path {}", path.display()))?;
                out.push('/');
                out.push_str(part);
            }
            Component::ParentDir | Component::Prefix(_) => {
                bail!("path {} leaves the package root", path.display());
            }
        }
    }
    Ok((!out.is_empty()).then_some(out))
}

fn read_data_tar(reader: impl Read, max_unpacked_bytes: u64) -> Result<Vec<DataEntry>> {
    let mut entries = Vec::new();
    let mut unpacked_bytes = 0u64;
    let mut archive = tar::Archive::new(reader);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let raw_path = entry.path()?.into_owned();
        let Some(path) = install_path(&raw_path)? else {
            continue;
        };
        let header = entry.header();
        let kind = match header.entry_type() {
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                unpacked_bytes = unpacked_bytes.saturating_add(entry.size());
                if unpacked_bytes > max_unpacked_bytes {
                    bail!("unpacked contents exceed {max_unpacked_bytes} bytes");
                }
                // Capacity is bounded by the check above.
                let mut contents = Vec::with_capacity(entry.size() as usize);
                entry
                    .read_to_end(&mut contents)
                    .with_context(|| format!("reading {path}"))?;
                DataKind::File(contents)
            }
            tar::EntryType::Directory => DataKind::Dir,
            tar::EntryType::Symlink => {
                let target = entry
                    .link_name()?
                    .with_context(|| format!("symlink {path} has no target"))?;
                let target = target
                    .to_str()
                    .with_context(|| format!("symlink {path} has a non UTF-8 target"))?;
                DataKind::Symlink(target.to_owned())
            }
            tar::EntryType::Link => {
                let target = entry
                    .link_name()?
                    .with_context(|| format!("hard link {path} has no target"))?;
                let target = install_path(&target)?
                    .with_context(|| format!("hard link {path} points at the package root"))?;
                DataKind::HardLink(target)
            }
            // pax global headers only carry archive metadata.
            tar::EntryType::XGlobalHeader => continue,
            other => {
                warn!(path, kind = ?other, "skipping unsupported tar entry type");
                continue;
            }
        };
        let header = entry.header();
        let name_or_root = |name: Result<Option<&str>, std::str::Utf8Error>| {
            name.ok()
                .flatten()
                .filter(|n| !n.is_empty())
                .unwrap_or("root")
                .to_owned()
        };
        entries.push(DataEntry {
            meta: EntryMeta {
                // Masked to the 12 permission bits, so it fits in a u16.
                permissions: (header.mode()? & 0o7777) as u16,
                user: name_or_root(header.username()),
                group: name_or_root(header.groupname()),
                mtime_s: header.mtime()?,
            },
            path,
            kind,
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deb::testutil::{DebBuilder, compress};

    #[test]
    fn reads_every_supported_compression() {
        for compression in [
            Compression::None,
            Compression::Gzip,
            Compression::Xz,
            Compression::Zstd,
        ] {
            let deb = DebBuilder::new("demo", "1.0-1", "amd64")
                .file("/usr/bin/demo", b"#!/bin/sh\n", 0o755)
                .build(compression);
            let pkg = read_deb(deb.as_slice(), u64::MAX)
                .unwrap_or_else(|e| panic!("{compression:?}: {e:#}"));
            assert_eq!(pkg.control.package, "demo");
            let file = pkg
                .entries
                .iter()
                .find(|e| e.path == "/usr/bin/demo")
                .unwrap();
            assert_eq!(file.kind, DataKind::File(b"#!/bin/sh\n".to_vec()));
            assert_eq!(file.meta.permissions, 0o755);
            assert_eq!(
                (file.meta.user.as_str(), file.meta.group.as_str()),
                ("root", "root")
            );
        }
    }

    #[test]
    fn reads_entry_kinds_scripts_and_conffiles() {
        let deb = DebBuilder::new("demo", "1.0-1", "all")
            .file("/etc/demo.conf", b"a=1\n", 0o644)
            .conffiles("/etc/demo.conf\n")
            .dir("/var/lib/demo", 0o750)
            .symlink("/usr/bin/demo-link", "demo")
            .hardlink("/usr/bin/demo-hard", "/etc/demo.conf")
            .script("postinst")
            .script("prerm")
            .build(Compression::Gzip);
        let pkg = read_deb(deb.as_slice(), u64::MAX).unwrap();
        assert!(pkg.conffiles.contains("/etc/demo.conf"));
        assert_eq!(pkg.dropped_control_members, ["postinst", "prerm"]);
        let kind = |path: &str| {
            pkg.entries
                .iter()
                .find(|e| e.path == path)
                .map(|e| e.kind.clone())
        };
        assert_eq!(kind("/var/lib/demo"), Some(DataKind::Dir));
        assert_eq!(
            kind("/usr/bin/demo-link"),
            Some(DataKind::Symlink("demo".into()))
        );
        assert_eq!(
            kind("/usr/bin/demo-hard"),
            Some(DataKind::HardLink("/etc/demo.conf".into()))
        );
        // The "./" root and the implicit parent directories.
        assert_eq!(kind("/"), None);
        assert_eq!(kind("/usr"), Some(DataKind::Dir));
    }

    #[test]
    fn multi_frame_zstd_and_checksums() {
        let payload: Vec<u8> = (0..200_000u32).flat_map(|i| i.to_le_bytes()).collect();
        let (first, second) = payload.split_at(123_457);
        let mut stream = compress(Compression::Zstd, first);
        stream.extend(compress(Compression::Zstd, second));
        let mut out = Vec::new();
        ZstdReader::new(stream.as_slice())
            .read_to_end(&mut out)
            .unwrap();
        assert_eq!(out, payload);

        let mut empty = Vec::new();
        ZstdReader::new(&[][..]).read_to_end(&mut empty).unwrap();
        assert!(empty.is_empty());

        // A truncated stream is an error, not a short read.
        let whole = compress(Compression::Zstd, &payload);
        let truncated = &whole[..whole.len() / 2];
        assert!(
            ZstdReader::new(truncated)
                .read_to_end(&mut Vec::new())
                .is_err()
        );
    }

    #[test]
    fn rejects_malformed_packages() {
        let good = DebBuilder::new("demo", "1.0", "all").file("/x", b"x", 0o644);
        assert!(read_deb(good.clone().build(Compression::Gzip).as_slice(), u64::MAX).is_ok());

        let too_big = good.clone().build(Compression::Gzip);
        let err = read_deb(too_big.as_slice(), 0).unwrap_err();
        assert!(format!("{err:#}").contains("exceed"), "{err:#}");

        let wrong_first = good
            .clone()
            .members(&["control.tar.gz"])
            .build(Compression::Gzip);
        assert!(read_deb(wrong_first.as_slice(), u64::MAX).is_err());

        let no_data = good
            .clone()
            .members(&["debian-binary", "control.tar.gz"])
            .build(Compression::Gzip);
        let err = read_deb(no_data.as_slice(), u64::MAX).unwrap_err();
        assert!(format!("{err:#}").contains("missing data.tar"), "{err:#}");

        let bzip2 = good
            .clone()
            .members(&["debian-binary", "control.tar.gz", "data.tar.bz2"])
            .build(Compression::Gzip);
        let err = read_deb(bzip2.as_slice(), u64::MAX).unwrap_err();
        assert!(
            format!("{err:#}").contains("unsupported compression"),
            "{err:#}"
        );

        let format3 = good.clone().format("3.0\n").build(Compression::Gzip);
        assert!(read_deb(format3.as_slice(), u64::MAX).is_err());

        assert!(read_deb(&b"!<arch>\n"[..], u64::MAX).is_err());
        assert!(read_deb(&b"not an archive"[..], u64::MAX).is_err());
        let truncated = good.build(Compression::Xz);
        assert!(read_deb(&truncated[..truncated.len() - 40], u64::MAX).is_err());
    }

    #[test]
    fn underscore_members_are_skipped() {
        let deb = DebBuilder::new("demo", "1.0", "all")
            .file("/x", b"x", 0o644)
            .members(&[
                "debian-binary",
                "_gpgorigin",
                "control.tar.gz",
                "data.tar.gz",
            ])
            .build(Compression::Gzip);
        assert!(read_deb(deb.as_slice(), u64::MAX).is_ok());
    }

    #[test]
    fn install_paths() {
        assert_eq!(install_path(Path::new("./")).unwrap(), None);
        assert_eq!(
            install_path(Path::new("./usr//bin/x")).unwrap().as_deref(),
            Some("/usr/bin/x")
        );
        assert_eq!(
            install_path(Path::new("usr/bin/")).unwrap().as_deref(),
            Some("/usr/bin")
        );
        assert!(install_path(Path::new("./usr/../../etc/x")).is_err());
    }
}
