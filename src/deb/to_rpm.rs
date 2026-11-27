//! Building an RPM from a parsed `.deb`.
//!
//! Like alien's defaults, Debian dependencies are not carried over (Debian
//! package names don't match RPM ones, so most would be unsatisfiable), and
//! neither are maintainer scripts (they expect dpkg's arguments and
//! environment). Directories are only packaged when the `.deb` ships them
//! empty: listing shared directories such as `/usr/bin` with Debian's modes
//! would conflict with the `filesystem` package, as rpm treats a mode
//! difference on a shared directory as a file conflict.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, bail};
use rpm::{
    BuildConfig, CompressionType, FileOptions, FileOptionsBuilder, PackageBuilder, Timestamp,
};
use tracing::warn;

use super::archive::{DataEntry, DataKind, DebPackage, EntryMeta};
use super::control::get_rpm_arch;

/// The directories above `path`, excluding `/` (`/usr/bin/x` gives `/usr`
/// and `/usr/bin`).
fn ancestors(path: &str) -> impl Iterator<Item = &str> {
    path.match_indices('/')
        .filter(|(index, _)| *index > 0)
        .map(|(index, _)| &path[..index])
}

/// RPM v4 header timestamps are 32-bit; later times are clamped.
fn get_timestamp(mtime_s: u64) -> Timestamp {
    Timestamp::from(u32::try_from(mtime_s).unwrap_or(u32::MAX))
}

/// Builds the RPM for `deb`. Every package is gzip-compressed RPM v4, which
/// all supported clients (including EL7 / Amazon Linux 2) can install.
pub fn build_rpm(deb: DebPackage) -> Result<rpm::Package> {
    let DebPackage {
        control,
        conffiles,
        dropped_control_members,
        entries,
    } = deb;
    let name = control.package.as_str();
    let arch = get_rpm_arch(&control.architecture)?;
    // Debian packages keep their license in this file instead of a field.
    let license = format!("see /usr/share/doc/{name}/copyright");
    let summary = control.synopsis.as_deref().unwrap_or(name);
    let mut builder = PackageBuilder::new(
        name,
        &control.version.get_rpm_version(),
        &license,
        arch,
        summary,
    );
    builder.using_config(BuildConfig::v4().compression(CompressionType::Gzip));
    if let Some(epoch) = control.version.epoch {
        builder.epoch(epoch);
    }
    // Without a Debian revision the builder's default release "1" is used.
    if let Some(revision) = &control.version.revision {
        builder.release(revision);
    }
    builder.description(control.extended_description.as_deref().unwrap_or(summary));
    if let Some(homepage) = &control.homepage {
        builder.url(homepage);
    }
    if let Some(maintainer) = &control.maintainer {
        builder.packager(maintainer);
    }
    if let Some(section) = &control.section {
        builder.group(section);
    }
    if !dropped_control_members.is_empty() {
        warn!(
            package = name,
            scripts = ?dropped_control_members,
            "maintainer scripts are not converted; the package may need manual setup"
        );
    }

    let parents: HashSet<String> = entries
        .iter()
        .flat_map(|e| ancestors(&e.path))
        .map(str::to_owned)
        .collect();
    // rpm requires every member of a hard link set to carry identical
    // content and metadata, so each link copies its target.
    let link_sources: HashMap<String, (Vec<u8>, EntryMeta)> = {
        let link_targets: HashSet<&str> = entries
            .iter()
            .filter_map(|e| match &e.kind {
                DataKind::HardLink(target) => Some(target.as_str()),
                _ => None,
            })
            .collect();
        entries
            .iter()
            .filter(|e| link_targets.contains(e.path.as_str()))
            .filter_map(|e| match &e.kind {
                DataKind::File(contents) => {
                    Some((e.path.clone(), (contents.clone(), e.meta.clone())))
                }
                _ => None,
            })
            .collect()
    };

    let file_options = |path: &str, meta: &EntryMeta| {
        let options = with_meta(FileOptions::new(path), meta).permissions(meta.permissions);
        if conffiles.contains(path) {
            options.config().noreplace()
        } else {
            options
        }
    };

    for DataEntry { path, kind, meta } in entries {
        let added = match kind {
            DataKind::File(contents) => {
                let mut options = file_options(&path, &meta);
                if link_sources.contains_key(&path) {
                    options = options.hardlink(path.as_str());
                }
                builder.with_file_contents(contents, options)
            }
            DataKind::HardLink(target) => {
                let Some((contents, target_meta)) = link_sources.get(&target) else {
                    bail!(
                        "hard link {path} points at {target}, which is not a regular file \
                         in the package"
                    );
                };
                let options = file_options(&path, target_meta).hardlink(target);
                builder.with_file_contents(contents.as_slice(), options)
            }
            DataKind::Dir if parents.contains(&path) => continue,
            DataKind::Dir => builder.with_dir_entry(
                with_meta(FileOptions::dir(path.as_str()), &meta).permissions(meta.permissions),
            ),
            // rpm ignores symlink permissions.
            DataKind::Symlink(target) => builder.with_symlink(with_meta(
                FileOptions::symlink(path.as_str(), target),
                &meta,
            )),
        };
        added.with_context(|| format!("adding {path}"))?;
    }
    builder.build().context("building the RPM")
}

/// Applies the owner, group and modification time of `meta`.
fn with_meta(options: FileOptionsBuilder, meta: &EntryMeta) -> FileOptionsBuilder {
    options
        .user(meta.user.as_str())
        .group(meta.group.as_str())
        .modified_at(get_timestamp(meta.mtime_s))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rpm::{CompressionType, FileFlags, FileType};

    use super::*;
    use crate::deb::archive::{Compression, read_deb};
    use crate::deb::testutil::{DebBuilder, MTIME_S};

    fn try_convert(builder: DebBuilder) -> Result<rpm::Package> {
        let deb = builder.build(Compression::Gzip);
        let package = build_rpm(read_deb(deb.as_slice(), u64::MAX)?)?;
        // Parse the written bytes, as clients and the scanner would.
        let mut bytes = Vec::new();
        package.write(&mut bytes)?;
        Ok(rpm::Package::parse(&mut bytes.as_slice())?)
    }

    fn convert(builder: DebBuilder) -> rpm::Package {
        try_convert(builder).unwrap()
    }

    #[test]
    fn header_fields_from_control() {
        let pkg = convert(
            DebBuilder::new("demo-tool", "2:1.4-beta-3ubuntu1", "amd64")
                .field("Maintainer", "Jane Doe <jane@example.invalid>")
                .field("Homepage", "https://example.invalid/demo")
                .field("Section", "utils")
                .field("Depends", "libc6 (>= 2.34), libfoo1")
                .field("Description", "Demo tool\n Does demo things.\n .\n Really.")
                .file("/usr/bin/demo-tool", b"#!/bin/sh\n", 0o755)
                .script("postinst"),
        );
        let md = &pkg.metadata;
        assert_eq!(md.get_name().unwrap(), "demo-tool");
        assert_eq!(md.get_epoch().unwrap(), 2);
        assert_eq!(md.get_version().unwrap(), "1.4_beta");
        assert_eq!(md.get_release().unwrap(), "3ubuntu1");
        assert_eq!(md.get_arch().unwrap(), "x86_64");
        assert_eq!(md.get_summary().unwrap(), "Demo tool");
        assert_eq!(
            md.get_description().unwrap(),
            "Does demo things.\n\nReally."
        );
        assert_eq!(md.get_url().unwrap(), "https://example.invalid/demo");
        assert_eq!(
            md.get_packager().unwrap(),
            "Jane Doe <jane@example.invalid>"
        );
        assert_eq!(md.get_group().unwrap(), "utils");
        assert_eq!(
            md.get_license().unwrap(),
            "see /usr/share/doc/demo-tool/copyright"
        );
        assert_eq!(md.get_payload_compressor().unwrap(), CompressionType::Gzip);
        // Debian dependencies and maintainer scripts are dropped; only the
        // rpmlib() features the payload needs remain.
        let requires = md.get_requires().unwrap();
        assert!(
            requires.iter().all(|d| d.name.starts_with("rpmlib(")),
            "{requires:?}"
        );
        assert!(md.get_post_install_script().is_err());
    }

    #[test]
    fn defaults_without_optional_fields() {
        let pkg = convert(DebBuilder::new("bare", "1.0", "all").file("/x", b"x", 0o644));
        let md = &pkg.metadata;
        assert!(matches!(md.get_epoch(), Err(_) | Ok(0)));
        assert_eq!(md.get_version().unwrap(), "1.0");
        assert_eq!(md.get_release().unwrap(), "1");
        assert_eq!(md.get_arch().unwrap(), "noarch");
        assert_eq!(md.get_summary().unwrap(), "bare");
        assert_eq!(md.get_description().unwrap(), "bare");
    }

    #[test]
    fn files_directories_links_and_conffiles() {
        let pkg = convert(
            DebBuilder::new("demo", "1.0-1", "arm64")
                .file("/usr/bin/demo", b"#!/bin/sh\necho demo\n", 0o755)
                .file("/etc/demo/demo.conf", b"a=1\n", 0o640)
                .file("/usr/share/demo/data", b"data\n", 0o644)
                .conffiles("/etc/demo/demo.conf\n")
                .dir("/var/lib/demo", 0o750)
                .symlink("/usr/bin/demo-alias", "demo")
                .hardlink("/usr/bin/demo-hard", "/usr/bin/demo"),
        );
        let entries = pkg.metadata.get_file_entries().unwrap();
        let by_path: BTreeMap<String, _> = entries
            .iter()
            .map(|e| (e.path().to_string_lossy().into_owned(), e))
            .collect();
        // Directories that contain files (including /usr, /etc, ...) are
        // left to the packages that own them; the empty one is packaged.
        assert_eq!(
            by_path.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "/etc/demo/demo.conf",
                "/usr/bin/demo",
                "/usr/bin/demo-alias",
                "/usr/bin/demo-hard",
                "/usr/share/demo/data",
                "/var/lib/demo",
            ]
        );

        let demo = by_path["/usr/bin/demo"];
        assert_eq!(demo.file_type(), FileType::Regular);
        assert_eq!(demo.permissions(), 0o755);
        assert_eq!((demo.user(), demo.group()), ("root", "root"));
        assert_eq!(u32::from(demo.modified_at()), MTIME_S as u32);
        assert!(!demo.flags().contains(FileFlags::CONFIG));

        let conf = by_path["/etc/demo/demo.conf"];
        assert_eq!(conf.permissions(), 0o640);
        assert!(
            conf.flags()
                .contains(FileFlags::CONFIG | FileFlags::NOREPLACE)
        );

        let dir = by_path["/var/lib/demo"];
        assert_eq!(dir.file_type(), FileType::Dir);
        assert_eq!(dir.permissions(), 0o750);

        let alias = by_path["/usr/bin/demo-alias"];
        assert_eq!(alias.file_type(), FileType::SymbolicLink);
        assert_eq!(alias.linkto(), Some("demo"));

        let hard = by_path["/usr/bin/demo-hard"];
        assert_eq!(hard.file_type(), FileType::Regular);
        assert_eq!((hard.permissions(), hard.size()), (0o755, demo.size()));

        let contents: BTreeMap<String, Vec<u8>> = pkg
            .files()
            .unwrap()
            .map(|f| f.unwrap())
            .filter_map(|f| {
                let content = f.content()?.to_vec();
                Some((f.metadata.path().to_string_lossy().into_owned(), content))
            })
            .collect();
        // A hard link set's data is stored once in the payload, on one member.
        let demo_contents: Vec<_> = ["/usr/bin/demo", "/usr/bin/demo-hard"]
            .iter()
            .filter_map(|p| contents.get(*p))
            .collect();
        assert_eq!(demo_contents, [b"#!/bin/sh\necho demo\n"]);
        assert_eq!(contents["/etc/demo/demo.conf"], b"a=1\n");
    }

    #[test]
    fn rejects_unconvertible_packages() {
        let err = try_convert(DebBuilder::new("demo", "1.0", "hurd-i386").file("/x", b"x", 0o644))
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("unsupported Debian architecture"),
            "{err:#}"
        );

        let err = try_convert(
            DebBuilder::new("demo", "1.0", "all")
                .symlink("/usr/bin/a", "b")
                .hardlink("/usr/bin/c", "/usr/bin/a"),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("not a regular file"), "{err:#}");
    }

    #[test]
    fn ancestor_directories() {
        assert_eq!(
            ancestors("/usr/bin/x").collect::<Vec<_>>(),
            ["/usr", "/usr/bin"]
        );
        assert_eq!(ancestors("/x").count(), 0);
    }

    #[test]
    fn timestamps_are_clamped() {
        assert_eq!(u32::from(get_timestamp(0)), 0);
        assert_eq!(u32::from(get_timestamp(u64::MAX)), u32::MAX);
    }
}
