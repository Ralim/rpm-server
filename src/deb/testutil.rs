//! Builds `.deb` packages in memory for unit tests, laid out like
//! `dpkg-deb --build --root-owner-group` output: `./`-prefixed tar paths,
//! explicit parent directories, root ownership.

use std::collections::BTreeSet;
use std::io::Write;

use super::archive::{Compression, tar_compression};

/// Modification time of every entry (2023-11-14T22:13:20Z).
pub const MTIME_S: u64 = 1_700_000_000;

#[derive(Debug, Clone)]
enum Entry {
    File(Vec<u8>, u32),
    Dir(u32),
    Symlink(String),
    HardLink(String),
}

#[derive(Debug, Clone)]
pub struct DebBuilder {
    control: String,
    conffiles: Option<String>,
    scripts: Vec<String>,
    entries: Vec<(String, Entry)>,
    members: Option<Vec<String>>,
    format: String,
}

pub fn compress(compression: Compression, data: &[u8]) -> Vec<u8> {
    match compression {
        Compression::None => data.to_vec(),
        Compression::Gzip => {
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            enc.write_all(data).unwrap();
            enc.finish().unwrap()
        }
        Compression::Xz => {
            let mut enc =
                lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(6))
                    .unwrap();
            enc.write_all(data).unwrap();
            enc.finish().unwrap()
        }
        Compression::Zstd => {
            ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest)
        }
    }
}

impl DebBuilder {
    pub fn new(package: &str, version: &str, arch: &str) -> Self {
        Self {
            control: format!("Package: {package}\nVersion: {version}\nArchitecture: {arch}\n"),
            conffiles: None,
            scripts: Vec::new(),
            entries: Vec::new(),
            members: None,
            format: "2.0\n".into(),
        }
    }

    /// Appends a raw control field line (continuation lines included).
    pub fn field(mut self, name: &str, value: &str) -> Self {
        self.control.push_str(&format!("{name}: {value}\n"));
        self
    }

    pub fn file(mut self, path: &str, contents: &[u8], mode: u32) -> Self {
        self.entries
            .push((path.into(), Entry::File(contents.to_vec(), mode)));
        self
    }

    pub fn dir(mut self, path: &str, mode: u32) -> Self {
        self.entries.push((path.into(), Entry::Dir(mode)));
        self
    }

    pub fn symlink(mut self, path: &str, target: &str) -> Self {
        self.entries
            .push((path.into(), Entry::Symlink(target.into())));
        self
    }

    /// A hard link at `path` to the earlier entry `target` (absolute).
    pub fn hardlink(mut self, path: &str, target: &str) -> Self {
        self.entries
            .push((path.into(), Entry::HardLink(target.into())));
        self
    }

    pub fn conffiles(mut self, text: &str) -> Self {
        self.conffiles = Some(text.into());
        self
    }

    pub fn script(mut self, name: &str) -> Self {
        self.scripts.push(name.into());
        self
    }

    /// Overrides the ar member names (and order); the content of each is
    /// chosen by its name.
    pub fn members(mut self, names: &[&str]) -> Self {
        self.members = Some(names.iter().map(|n| (*n).to_owned()).collect());
        self
    }

    /// Overrides the content of `debian-binary`.
    pub fn format(mut self, text: &str) -> Self {
        self.format = text.into();
        self
    }

    fn header(kind: tar::EntryType, mode: u32, size: u64) -> tar::Header {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(kind);
        h.set_mode(mode);
        h.set_size(size);
        h.set_mtime(MTIME_S);
        h.set_uid(0);
        h.set_gid(0);
        h.set_username("root").unwrap();
        h.set_groupname("root").unwrap();
        h
    }

    fn control_tar(&self) -> Vec<u8> {
        let mut tar = tar::Builder::new(Vec::new());
        let dir = Self::header(tar::EntryType::Directory, 0o755, 0);
        tar.append_data(&mut dir.clone(), "./", &[][..]).unwrap();
        let mut add = |name: &str, contents: &[u8], mode: u32| {
            let mut h = Self::header(tar::EntryType::Regular, mode, contents.len() as u64);
            tar.append_data(&mut h, format!("./{name}"), contents)
                .unwrap();
        };
        add("control", self.control.as_bytes(), 0o644);
        if let Some(conffiles) = &self.conffiles {
            add("conffiles", conffiles.as_bytes(), 0o644);
        }
        for script in &self.scripts {
            add(script, b"#!/bin/sh\nexit 0\n", 0o755);
        }
        tar.into_inner().unwrap()
    }

    fn data_tar(&self) -> Vec<u8> {
        let mut dirs = BTreeSet::new();
        for (path, _) in &self.entries {
            for (index, _) in path.match_indices('/').filter(|(i, _)| *i > 0) {
                dirs.insert(path[..index].to_owned());
            }
        }
        let mut tar = tar::Builder::new(Vec::new());
        let mut dir = Self::header(tar::EntryType::Directory, 0o755, 0);
        tar.append_data(&mut dir, "./", &[][..]).unwrap();
        for d in &dirs {
            let mut h = Self::header(tar::EntryType::Directory, 0o755, 0);
            tar.append_data(&mut h, format!(".{d}/"), &[][..]).unwrap();
        }
        for (path, entry) in &self.entries {
            let name = format!(".{path}");
            match entry {
                Entry::File(contents, mode) => {
                    let mut h = Self::header(tar::EntryType::Regular, *mode, contents.len() as u64);
                    tar.append_data(&mut h, name, contents.as_slice()).unwrap();
                }
                Entry::Dir(mode) => {
                    let mut h = Self::header(tar::EntryType::Directory, *mode, 0);
                    tar.append_data(&mut h, format!("{name}/"), &[][..])
                        .unwrap();
                }
                Entry::Symlink(target) => {
                    let mut h = Self::header(tar::EntryType::Symlink, 0o777, 0);
                    tar.append_link(&mut h, name, target).unwrap();
                }
                Entry::HardLink(target) => {
                    let mut h = Self::header(tar::EntryType::Link, 0o644, 0);
                    tar.append_link(&mut h, name, format!(".{target}")).unwrap();
                }
            }
        }
        tar.into_inner().unwrap()
    }

    /// Builds the package with both tarballs compressed as `compression`.
    pub fn build(self, compression: Compression) -> Vec<u8> {
        let ext = match compression {
            Compression::None => "",
            Compression::Gzip => ".gz",
            Compression::Xz => ".xz",
            Compression::Zstd => ".zst",
        };
        let members = self.members.clone().unwrap_or_else(|| {
            vec![
                "debian-binary".into(),
                format!("control.tar{ext}"),
                format!("data.tar{ext}"),
            ]
        });
        let mut ar = ar::Builder::new(Vec::new());
        for name in &members {
            let contents = if name == "debian-binary" {
                self.format.as_bytes().to_vec()
            } else if name.starts_with("control.tar") {
                let compression = tar_compression(name, "control.tar").unwrap_or(Compression::None);
                compress(compression, &self.control_tar())
            } else if name.starts_with("data.tar") {
                let compression = tar_compression(name, "data.tar").unwrap_or(Compression::None);
                compress(compression, &self.data_tar())
            } else {
                b"ignored member".to_vec()
            };
            let header = ar::Header::new(name.as_bytes().to_vec(), contents.len() as u64);
            ar.append(&header, contents.as_slice()).unwrap();
        }
        ar.into_inner().unwrap()
    }
}
