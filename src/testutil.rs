//! Helpers shared by unit tests.

use std::sync::{Arc, OnceLock};

use rpm::{BuildConfig, CompressionType, Dependency, FileOptions, PackageBuilder};

use crate::signing::{RepoSigner, generate_secret_key};

/// A process-wide test signing key (key generation is not free).
pub fn signer() -> Arc<RepoSigner> {
    static SIGNER: OnceLock<Arc<RepoSigner>> = OnceLock::new();
    SIGNER
        .get_or_init(|| {
            let asc = generate_secret_key("rpm-server test <test@example.invalid>", None).unwrap();
            Arc::new(RepoSigner::from_armored(&asc, None, true).unwrap())
        })
        .clone()
}

/// Builds a small noarch package exercising the metadata fields we emit.
pub fn build_rpm(name: &str, version: &str, requires: &[&str]) -> Vec<u8> {
    let mut builder = PackageBuilder::new(name, version, "MIT", "noarch", "A test package");
    builder
        .using_config(
            BuildConfig::v4()
                .compression(CompressionType::Gzip)
                .source_date(1_700_000_000u32),
        )
        .release("1")
        .description("Line one & <two>\nline two")
        .url("https://example.invalid/demo")
        .with_file_contents(
            "#!/bin/sh\necho hi\n",
            FileOptions::new(format!("/usr/bin/{name}")).permissions(0o755),
        )
        .unwrap()
        .with_file_contents(
            "data\n",
            FileOptions::new(format!("/usr/share/{name}/data")).permissions(0o644),
        )
        .unwrap()
        .with_dir_entry(FileOptions::dir(format!("/etc/{name}")))
        .unwrap()
        .with_ghost(FileOptions::ghost(format!("/etc/{name}/state")))
        .unwrap()
        .provides(Dependency::eq(format!("{name}-capability"), "1.0"))
        .requires(Dependency::any(format!("/usr/share/{name}/data")))
        .requires(Dependency::eq(format!("{name}-capability"), "1.0"))
        .requires(Dependency::script_pre("/bin/sh"))
        .requires(Dependency::greater_eq("bash", "1:4.0-1"))
        .add_changelog_entry(
            "Tester <t@example.invalid> - 1.0-1",
            "- first",
            1_690_000_000u32,
        )
        .add_changelog_entry(
            "Tester <t@example.invalid> - 1.0-2",
            "- second",
            1_700_000_000u32,
        );
    for r in requires {
        builder.requires(Dependency::any(*r));
    }
    let mut out = Vec::new();
    builder.build().unwrap().write(&mut out).unwrap();
    out
}
