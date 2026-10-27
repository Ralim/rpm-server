//! Generation of the dnf/yum `repodata/` directory (rpm-md format, as
//! produced by createrepo_c) from a set of scanned packages.

use std::io::{self, Write};
use std::sync::Arc;

use anyhow::Result;
use bytes::Bytes;
use flate2::Compression;
use flate2::write::GzEncoder;
use quick_xml::Writer;
use quick_xml::events::{BytesDecl, BytesText, Event};
use sha2::{Digest, Sha256};

use crate::package::{Dep, FileKind, PackageFile, RpmEntry};
use crate::signing::RepoSigner;

const NS_REPO: &str = "http://linux.duke.edu/metadata/repo";
const NS_COMMON: &str = "http://linux.duke.edu/metadata/common";
const NS_RPM: &str = "http://linux.duke.edu/metadata/rpm";
const NS_FILELISTS: &str = "http://linux.duke.edu/metadata/filelists";
const NS_OTHER: &str = "http://linux.duke.edu/metadata/other";

pub const CONTENT_TYPE_GZIP: &str = "application/gzip";
pub const CONTENT_TYPE_XML: &str = "application/xml";
pub const CONTENT_TYPE_SIGNATURE: &str = "application/pgp-signature";

/// A generated file, with its path relative to the repository root.
#[derive(Debug, Clone)]
pub struct GeneratedFile {
    pub path: String,
    pub bytes: Bytes,
    pub content_type: &'static str,
}

type W = Writer<Vec<u8>>;

/// Removes characters that are not allowed in XML 1.0 documents.
fn clean(s: &str) -> std::borrow::Cow<'_, str> {
    let bad = |c: char| c.is_control() && !matches!(c, '\t' | '\n' | '\r');
    if s.chars().any(bad) {
        s.chars().filter(|c| !bad(*c)).collect::<String>().into()
    } else {
        s.into()
    }
}

fn new_writer() -> io::Result<W> {
    let mut w = Writer::new_with_indent(Vec::new(), b' ', 2);
    w.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)))?;
    Ok(w)
}

fn text_element(w: &mut W, name: &str, value: &str) -> io::Result<()> {
    w.create_element(name)
        .write_text_content(BytesText::new(&clean(value)))?;
    Ok(())
}

fn version_element(w: &mut W, e: &RpmEntry) -> io::Result<()> {
    let epoch = e.info.epoch.to_string();
    w.create_element("version")
        .with_attributes([
            ("epoch", epoch.as_str()),
            ("ver", e.info.version.as_str()),
            ("rel", e.info.release.as_str()),
        ])
        .write_empty()?;
    Ok(())
}

fn file_element(w: &mut W, f: &PackageFile) -> io::Result<()> {
    let el = w.create_element("file");
    let el = match f.kind {
        FileKind::Regular => el,
        FileKind::Dir => el.with_attribute(("type", "dir")),
        FileKind::Ghost => el.with_attribute(("type", "ghost")),
    };
    el.write_text_content(BytesText::new(&clean(&f.path)))?;
    Ok(())
}

fn deps_element(w: &mut W, name: &str, deps: &[Dep]) -> io::Result<()> {
    if deps.is_empty() {
        return Ok(());
    }
    w.create_element(name).write_inner_content(|w| {
        for d in deps {
            let mut attrs = vec![("name", d.name.as_str())];
            if let Some(flags) = d.flags {
                attrs.push(("flags", flags));
            }
            for (key, value) in [("epoch", &d.epoch), ("ver", &d.ver), ("rel", &d.rel)] {
                if let Some(v) = value {
                    attrs.push((key, v.as_str()));
                }
            }
            if d.pre {
                attrs.push(("pre", "1"));
            }
            w.create_element("rpm:entry")
                .with_attributes(attrs)
                .write_empty()?;
        }
        Ok(())
    })?;
    Ok(())
}

fn primary_package(w: &mut W, e: &RpmEntry) -> io::Result<()> {
    let i = &e.info;
    w.create_element("package")
        .with_attribute(("type", "rpm"))
        .write_inner_content(|w| {
            text_element(w, "name", &i.name)?;
            text_element(w, "arch", &i.arch)?;
            version_element(w, e)?;
            w.create_element("checksum")
                .with_attributes([("type", "sha256"), ("pkgid", "YES")])
                .write_text_content(BytesText::new(&e.sha256))?;
            text_element(w, "summary", &i.summary)?;
            text_element(w, "description", &i.description)?;
            text_element(w, "packager", &i.packager)?;
            text_element(w, "url", &i.url)?;
            let (file_time, build_time) = (e.mtime_secs().to_string(), i.build_time.to_string());
            w.create_element("time")
                .with_attributes([("file", file_time.as_str()), ("build", build_time.as_str())])
                .write_empty()?;
            let sizes = [e.size, i.installed_size, i.archive_size].map(|s| s.to_string());
            w.create_element("size")
                .with_attributes([
                    ("package", sizes[0].as_str()),
                    ("installed", sizes[1].as_str()),
                    ("archive", sizes[2].as_str()),
                ])
                .write_empty()?;
            // Left unencoded: dnf percent-encodes location hrefs itself.
            w.create_element("location")
                .with_attribute(("href", e.rel_path.as_str()))
                .write_empty()?;
            w.create_element("format").write_inner_content(|w| {
                text_element(w, "rpm:license", &i.license)?;
                text_element(w, "rpm:vendor", &i.vendor)?;
                text_element(w, "rpm:group", &i.group)?;
                text_element(w, "rpm:buildhost", &i.buildhost)?;
                text_element(w, "rpm:sourcerpm", &i.sourcerpm)?;
                let (start, end) = (i.header_start.to_string(), i.header_end.to_string());
                w.create_element("rpm:header-range")
                    .with_attributes([("start", start.as_str()), ("end", end.as_str())])
                    .write_empty()?;
                deps_element(w, "rpm:provides", &i.provides)?;
                deps_element(w, "rpm:requires", &i.requires)?;
                deps_element(w, "rpm:conflicts", &i.conflicts)?;
                deps_element(w, "rpm:obsoletes", &i.obsoletes)?;
                deps_element(w, "rpm:suggests", &i.suggests)?;
                deps_element(w, "rpm:enhances", &i.enhances)?;
                deps_element(w, "rpm:recommends", &i.recommends)?;
                deps_element(w, "rpm:supplements", &i.supplements)?;
                for f in i.files.iter().filter(|f| f.is_primary()) {
                    file_element(w, f)?;
                }
                Ok(())
            })?;
            Ok(())
        })?;
    Ok(())
}

/// Starts a per-package element for filelists.xml / other.xml.
fn keyed_package(
    w: &mut W,
    e: &RpmEntry,
    body: impl FnOnce(&mut W) -> io::Result<()>,
) -> io::Result<()> {
    w.create_element("package")
        .with_attributes([
            ("pkgid", e.sha256.as_str()),
            ("name", e.info.name.as_str()),
            ("arch", e.info.arch.as_str()),
        ])
        .write_inner_content(|w| {
            version_element(w, e)?;
            body(w)
        })?;
    Ok(())
}

fn document(
    root: &str,
    namespaces: &[(&str, &str)],
    packages: &[Arc<RpmEntry>],
    mut each: impl FnMut(&mut W, &RpmEntry) -> io::Result<()>,
) -> io::Result<Vec<u8>> {
    let mut w = new_writer()?;
    let count = packages.len().to_string();
    let mut attrs = namespaces.to_vec();
    attrs.push(("packages", count.as_str()));
    w.create_element(root)
        .with_attributes(attrs)
        .write_inner_content(|w| {
            for e in packages {
                each(w, e)?;
            }
            Ok(())
        })?;
    let mut out = w.into_inner();
    out.push(b'\n');
    Ok(out)
}

pub fn primary_xml(packages: &[Arc<RpmEntry>]) -> io::Result<Vec<u8>> {
    document(
        "metadata",
        &[("xmlns", NS_COMMON), ("xmlns:rpm", NS_RPM)],
        packages,
        primary_package,
    )
}

pub fn filelists_xml(packages: &[Arc<RpmEntry>]) -> io::Result<Vec<u8>> {
    document("filelists", &[("xmlns", NS_FILELISTS)], packages, |w, e| {
        keyed_package(w, e, |w| {
            for f in &e.info.files {
                file_element(w, f)?;
            }
            Ok(())
        })
    })
}

pub fn other_xml(packages: &[Arc<RpmEntry>]) -> io::Result<Vec<u8>> {
    document("otherdata", &[("xmlns", NS_OTHER)], packages, |w, e| {
        keyed_package(w, e, |w| {
            for c in &e.info.changelogs {
                let date = c.date.to_string();
                w.create_element("changelog")
                    .with_attributes([
                        ("author", clean(&c.author).as_ref()),
                        ("date", date.as_str()),
                    ])
                    .write_text_content(BytesText::new(&clean(&c.text)))?;
            }
            Ok(())
        })
    })
}

fn gzip(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data)?;
    enc.finish()
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

struct MetadataFile {
    kind: &'static str,
    location: String,
    compressed: Vec<u8>,
    open_checksum: String,
    open_size: usize,
}

impl MetadataFile {
    fn new(kind: &'static str, xml: Vec<u8>) -> io::Result<Self> {
        let compressed = gzip(&xml)?;
        // Checksum-prefixed names keep caches and proxies from mixing generations.
        let location = format!("repodata/{}-{kind}.xml.gz", sha256_hex(&compressed));
        Ok(Self {
            kind,
            location,
            open_checksum: sha256_hex(&xml),
            open_size: xml.len(),
            compressed,
        })
    }
}

fn repomd_xml(files: &[MetadataFile], revision: u64) -> io::Result<Vec<u8>> {
    let mut w = new_writer()?;
    let revision = revision.to_string();
    w.create_element("repomd")
        .with_attributes([("xmlns", NS_REPO), ("xmlns:rpm", NS_RPM)])
        .write_inner_content(|w| {
            text_element(w, "revision", &revision)?;
            for f in files {
                w.create_element("data")
                    .with_attribute(("type", f.kind))
                    .write_inner_content(|w| {
                        w.create_element("checksum")
                            .with_attribute(("type", "sha256"))
                            .write_text_content(BytesText::new(&sha256_hex(&f.compressed)))?;
                        w.create_element("open-checksum")
                            .with_attribute(("type", "sha256"))
                            .write_text_content(BytesText::new(&f.open_checksum))?;
                        w.create_element("location")
                            .with_attribute(("href", f.location.as_str()))
                            .write_empty()?;
                        text_element(w, "timestamp", &revision)?;
                        text_element(w, "size", &f.compressed.len().to_string())?;
                        text_element(w, "open-size", &f.open_size.to_string())?;
                        Ok(())
                    })?;
            }
            Ok(())
        })?;
    let mut out = w.into_inner();
    out.push(b'\n');
    Ok(out)
}

/// Builds every file under `repodata/`, including `repomd.xml.asc` when a
/// signer is given.
pub fn generate(
    packages: &[Arc<RpmEntry>],
    signer: Option<&RepoSigner>,
    revision: u64,
) -> Result<Vec<GeneratedFile>> {
    let files = [
        MetadataFile::new("primary", primary_xml(packages)?)?,
        MetadataFile::new("filelists", filelists_xml(packages)?)?,
        MetadataFile::new("other", other_xml(packages)?)?,
    ];
    let repomd = repomd_xml(&files, revision)?;

    let mut out = Vec::new();
    if let Some(signer) = signer {
        out.push(GeneratedFile {
            path: "repodata/repomd.xml.asc".into(),
            bytes: signer.sign_detached(&repomd)?.into(),
            content_type: CONTENT_TYPE_SIGNATURE,
        });
    }
    out.push(GeneratedFile {
        path: "repodata/repomd.xml".into(),
        bytes: repomd.into(),
        content_type: CONTENT_TYPE_XML,
    });
    out.extend(files.into_iter().map(|f| GeneratedFile {
        path: f.location,
        bytes: f.compressed.into(),
        content_type: CONTENT_TYPE_GZIP,
    }));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;
    use flate2::read::GzDecoder;
    use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey};
    use quick_xml::Reader;
    use std::io::Read;

    fn entries(dir: &std::path::Path, signer: Option<&RepoSigner>) -> Vec<Arc<RpmEntry>> {
        ["alpha", "beta"]
            .iter()
            .map(|name| {
                let path = dir.join(format!("{name}.rpm"));
                std::fs::write(&path, testutil::build_rpm(name, "1.0", &[])).unwrap();
                Arc::new(RpmEntry::load(&path, format!("sub dir/{name}+1.rpm"), signer).unwrap())
            })
            .collect()
    }

    /// Parses the whole document; quick-xml rejects mismatched tags.
    fn assert_well_formed(xml: &str) {
        let mut reader = Reader::from_str(xml);
        loop {
            match reader.read_event().unwrap() {
                Event::Eof => break,
                _ => continue,
            }
        }
    }

    fn gunzip(data: &[u8]) -> String {
        let mut s = String::new();
        GzDecoder::new(data).read_to_string(&mut s).unwrap();
        s
    }

    fn find<'a>(files: &'a [GeneratedFile], suffix: &str) -> &'a GeneratedFile {
        files.iter().find(|f| f.path.ends_with(suffix)).unwrap()
    }

    #[test]
    fn repomd_checksums_match_files() {
        let dir = tempfile::tempdir().unwrap();
        let files = generate(&entries(dir.path(), None), None, 1234).unwrap();
        assert!(!files.iter().any(|f| f.path.ends_with(".asc")));

        let repomd = std::str::from_utf8(&find(&files, "repomd.xml").bytes)
            .unwrap()
            .to_owned();
        assert_well_formed(&repomd);
        assert!(repomd.contains("<revision>1234</revision>"));
        for kind in ["primary", "filelists", "other"] {
            let f = find(&files, &format!("-{kind}.xml.gz"));
            let plain = gunzip(&f.bytes);
            assert_well_formed(&plain);
            assert!(repomd.contains(&format!("<location href=\"{}\"/>", f.path)));
            assert!(repomd.contains(&sha256_hex(&f.bytes)));
            assert!(repomd.contains(&sha256_hex(plain.as_bytes())));
            assert!(repomd.contains(&format!("<open-size>{}</open-size>", plain.len())));
        }
    }

    #[test]
    fn primary_content() {
        let dir = tempfile::tempdir().unwrap();
        let pkgs = entries(dir.path(), None);
        let xml = String::from_utf8(primary_xml(&pkgs).unwrap()).unwrap();
        assert_well_formed(&xml);
        assert!(xml.contains(r#"packages="2""#));
        assert!(xml.contains("<name>alpha</name>"));
        assert!(xml.contains(r#"<version epoch="0" ver="1.0" rel="1"/>"#));
        assert!(xml.contains(&format!(
            r#"<checksum type="sha256" pkgid="YES">{}</checksum>"#,
            pkgs[0].sha256
        )));
        assert!(xml.contains(r#"<location href="sub dir/alpha+1.rpm"/>"#));
        assert!(xml.contains("Line one &amp; &lt;two&gt;\nline two</description>"));
        assert!(xml.contains(r#"<rpm:entry name="/bin/sh" pre="1"/>"#));
        assert!(xml.contains(r#"<rpm:entry name="bash" flags="GE" epoch="1" ver="4.0" rel="1"/>"#));
        assert!(xml.contains(r#"<file type="dir">/etc/alpha</file>"#));
        assert!(xml.contains(r#"<file type="ghost">/etc/alpha/state</file>"#));
        assert!(xml.contains("<file>/usr/bin/alpha</file>"));
        assert!(!xml.contains("/usr/share/alpha/data"));
        let range = format!(
            r#"<rpm:header-range start="{}" end="{}"/>"#,
            pkgs[0].info.header_start, pkgs[0].info.header_end
        );
        assert!(xml.contains(&range));
    }

    #[test]
    fn filelists_and_other_content() {
        let dir = tempfile::tempdir().unwrap();
        let pkgs = entries(dir.path(), None);
        let filelists = String::from_utf8(filelists_xml(&pkgs).unwrap()).unwrap();
        assert_well_formed(&filelists);
        assert!(filelists.contains(&format!(
            r#"<package pkgid="{}" name="alpha" arch="noarch">"#,
            pkgs[0].sha256
        )));
        assert!(filelists.contains("<file>/usr/share/alpha/data</file>"));

        let other = String::from_utf8(other_xml(&pkgs).unwrap()).unwrap();
        assert_well_formed(&other);
        let first = other.find("- first").unwrap();
        let second = other.find("- second").unwrap();
        assert!(first < second);
        assert!(
            other
                .contains(r#"author="Tester &lt;t@example.invalid&gt; - 1.0-1" date="1690000000""#)
        );
    }

    #[test]
    fn signed_repomd() {
        let dir = tempfile::tempdir().unwrap();
        let signer = testutil::signer();
        let files = generate(&entries(dir.path(), Some(&signer)), Some(&signer), 1).unwrap();
        let repomd = find(&files, "repomd.xml");
        let asc = std::str::from_utf8(&find(&files, "repomd.xml.asc").bytes)
            .unwrap()
            .to_owned();
        let (sig, _) = DetachedSignature::from_string(&asc).unwrap();
        let (public, _) = SignedPublicKey::from_string(signer.public_key_armored()).unwrap();
        sig.verify(&public, &repomd.bytes).unwrap();
    }

    #[test]
    fn clean_strips_invalid_xml_chars() {
        assert_eq!(clean("a\u{1}b\u{7f}c\td\ne\rf"), "abc\td\ne\rf");
        assert!(matches!(clean("plain"), std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn empty_repository() {
        let files = generate(&[], None, 1).unwrap();
        let primary = gunzip(&find(&files, "-primary.xml.gz").bytes);
        assert_well_formed(&primary);
        assert!(primary.contains(r#"packages="0""#));
    }
}
