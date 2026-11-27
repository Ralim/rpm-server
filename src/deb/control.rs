//! The `control` and `conffiles` members of a binary Debian package
//! (deb-control(5), deb-conffiles(5)) and the mapping of package names,
//! versions and architectures to RPM conventions.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use tracing::warn;

/// Debian architecture names (dpkg `cputable`/`ostable`, Debian Policy §11.1)
/// and the RPM architecture names Fedora/EL use for the same ABI
/// (`rpmrc.in` in rpm). `i386` maps to `i686`, the baseline of every
/// 32-bit x86 RPM distribution still in use.
const RPM_ARCHES: &[(&str, &str)] = &[
    ("all", "noarch"),
    ("amd64", "x86_64"),
    ("arm64", "aarch64"),
    ("armel", "armv5tel"),
    ("armhf", "armv7hl"),
    ("i386", "i686"),
    ("loong64", "loongarch64"),
    ("mips64el", "mips64el"),
    ("ppc64", "ppc64"),
    ("ppc64el", "ppc64le"),
    ("riscv64", "riscv64"),
    ("s390x", "s390x"),
];

/// `conffiles` flag marking an entry that is not shipped, only removed on
/// upgrade (deb-conffiles(5), dpkg >= 1.20.1).
const REMOVE_ON_UPGRADE: &str = "remove-on-upgrade";

/// The fields of a binary package's `control` file used for the RPM header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control {
    /// `Package`, valid per Debian Policy §5.6.7 (and therefore also as an
    /// RPM name).
    pub package: String,
    pub version: DebVersion,
    /// `Architecture`, a Debian architecture name such as `amd64` or `all`.
    pub architecture: String,
    pub maintainer: Option<String>,
    pub homepage: Option<String>,
    pub section: Option<String>,
    /// The first line of `Description`.
    pub synopsis: Option<String>,
    /// The remaining lines of `Description`, with ` .` lines turned into
    /// blank lines; `None` when there are none.
    pub extended_description: Option<String>,
}

impl FromStr for Control {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> Result<Self> {
        let mut fields = parse_fields(text)?;
        let mut required = |name: &str| {
            fields
                .remove(name)
                .filter(|v| !v.is_empty())
                .with_context(|| format!("missing {name} field"))
        };
        let package = required("package")?;
        let version = required("version")?;
        let architecture = required("architecture")?;
        if !is_valid_package_name(&package) {
            bail!("invalid package name {package:?}");
        }
        let version = version
            .parse()
            .with_context(|| format!("invalid version {version:?}"))?;
        let (synopsis, extended_description) = fields
            .remove("description")
            .map_or((None, None), |d| split_description(&d));
        let mut optional = |name: &str| fields.remove(name).filter(|v| !v.is_empty());
        Ok(Self {
            package,
            version,
            architecture,
            maintainer: optional("maintainer"),
            homepage: optional("homepage"),
            section: optional("section"),
            synopsis,
            extended_description,
        })
    }
}

/// Splits a single deb822 paragraph into its fields. Keys are lowercased, as
/// field names are case-insensitive. Continuation lines are appended to the
/// value after a newline, keeping their leading whitespace.
fn parse_fields(text: &str) -> Result<HashMap<String, String>> {
    let mut fields: HashMap<String, String> = HashMap::new();
    let mut current: Option<String> = None;
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        if line.trim().is_empty() {
            // A binary package's control file has a single paragraph.
            if fields.is_empty() {
                continue;
            }
            break;
        }
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            let Some(value) = current.as_ref().and_then(|name| fields.get_mut(name)) else {
                bail!("line {number}: continuation line before the first field");
            };
            value.push('\n');
            value.push_str(line);
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            bail!("line {number}: expected `Field: value`, got {line:?}");
        };
        let name = name.trim().to_ascii_lowercase();
        if fields.contains_key(&name) {
            bail!("line {number}: duplicate field {name:?}");
        }
        fields.insert(name.clone(), value.trim().to_owned());
        current = Some(name);
    }
    Ok(fields)
}

/// Splits a `Description` value into its synopsis and extended description.
/// Each continuation line loses the one leading space that marks it; a line
/// of just `.` stands for a blank line (deb-control(5)).
fn split_description(value: &str) -> (Option<String>, Option<String>) {
    let mut lines = value.lines();
    let synopsis = lines
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let extended: Vec<&str> = lines
        .map(|line| {
            // Continuation lines start with a single-byte space or tab.
            let line = &line[1..];
            if line.trim() == "." { "" } else { line }
        })
        .collect();
    let extended = extended.join("\n").trim_end().to_owned();
    (synopsis, (!extended.is_empty()).then_some(extended))
}

/// Debian Policy §5.6.7: at least two characters of lowercase letters,
/// digits, `+`, `-` and `.`, starting with a letter or digit.
fn is_valid_package_name(name: &str) -> bool {
    name.len() >= 2
        && name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '+' | '-' | '.'))
}

/// A Debian version, `[epoch:]upstream_version[-debian_revision]`
/// (Debian Policy §5.6.12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebVersion {
    pub epoch: Option<u32>,
    pub upstream: String,
    pub revision: Option<String>,
}

impl FromStr for DebVersion {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        let (epoch, rest) = match s.split_once(':') {
            Some((epoch, rest)) => {
                if epoch.is_empty() || !epoch.bytes().all(|b| b.is_ascii_digit()) {
                    bail!("epoch {epoch:?} is not a number");
                }
                let epoch = epoch
                    .parse()
                    .with_context(|| format!("epoch {epoch:?} is out of range"))?;
                (Some(epoch), rest)
            }
            None => (None, s),
        };
        // The revision starts after the last hyphen; any earlier hyphens
        // belong to the upstream version.
        let (upstream, revision) = match rest.rsplit_once('-') {
            Some((upstream, revision)) => (upstream, Some(revision)),
            None => (rest, None),
        };
        if upstream.is_empty() {
            bail!("empty upstream version");
        }
        if let Some(c) = upstream
            .chars()
            .find(|&c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '~' | '-' | ':')))
        {
            bail!("invalid character {c:?} in upstream version");
        }
        if let Some(revision) = revision {
            if revision.is_empty() {
                bail!("empty Debian revision");
            }
            if let Some(c) = revision
                .chars()
                .find(|&c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '~')))
            {
                bail!("invalid character {c:?} in Debian revision");
            }
        }
        Ok(Self {
            epoch,
            upstream: upstream.to_owned(),
            revision: revision.map(str::to_owned),
        })
    }
}

impl fmt::Display for DebVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(epoch) = self.epoch {
            write!(f, "{epoch}:")?;
        }
        f.write_str(&self.upstream)?;
        if let Some(revision) = &self.revision {
            write!(f, "-{revision}")?;
        }
        Ok(())
    }
}

impl DebVersion {
    /// The RPM `Version`: the upstream version with `-` and `:` (not allowed
    /// in RPM versions) replaced by `_`. Every other character Debian allows
    /// is valid in RPM, and `~` sorts before release in both.
    pub fn get_rpm_version(&self) -> String {
        self.upstream.replace(['-', ':'], "_")
    }
}

/// The RPM architecture for a Debian architecture name, or an error for
/// architectures RPM distributions do not build for.
pub fn get_rpm_arch(debian_arch: &str) -> Result<&'static str> {
    RPM_ARCHES
        .iter()
        .find(|(deb, _)| *deb == debian_arch)
        .map(|(_, rpm)| *rpm)
        .with_context(|| format!("unsupported Debian architecture {debian_arch:?}"))
}

/// Parses a `conffiles` member: one absolute path per line, optionally
/// preceded by flags (deb-conffiles(5)). Entries flagged `remove-on-upgrade`
/// are not part of the package and are left out.
pub fn parse_conffiles(text: &str) -> HashSet<String> {
    let mut conffiles = HashSet::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let Some(path_start) = line.find('/') else {
            warn!(line, "ignoring conffiles line without an absolute path");
            continue;
        };
        let (flags, path) = line.split_at(path_start);
        let mut remove_on_upgrade = false;
        for flag in flags.split_whitespace() {
            if flag == REMOVE_ON_UPGRADE {
                remove_on_upgrade = true;
            } else {
                warn!(flag, path, "ignoring unknown conffiles flag");
            }
        }
        if !remove_on_upgrade {
            conffiles.insert(path.to_owned());
        }
    }
    conffiles
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example from the dpkg deb-control(5) manual page.
    const GREP_CONTROL: &str = "\
Package: grep
Essential: yes
Priority: required
Section: base
Maintainer: Wichert Akkerman <wakkerma@debian.org>
Architecture: sparc
Version: 2.4-1
Pre-Depends: libc6 (>= 2.0.105)
Provides: rgrep
Conflicts: rgrep
Description: GNU grep, egrep and fgrep.
 The GNU family of grep utilities may be the \"fastest grep in the west\".
 GNU grep is based on a fast lazy-state deterministic matcher (about
 twice as fast as stock Unix egrep) hybridized with a Boyer-Moore-Gosper
 search for a fixed string that eliminates impossible text from being
 considered by the full regexp matcher without necessarily having to
 look at every character. The result is typically many times faster
 than Unix grep or egrep. (Regular expressions containing backreferencing
 will run more slowly, however).
";

    #[test]
    fn parses_manual_page_example() {
        let c: Control = GREP_CONTROL.parse().unwrap();
        assert_eq!(c.package, "grep");
        assert_eq!(c.version.to_string(), "2.4-1");
        assert_eq!(c.architecture, "sparc");
        assert_eq!(
            c.maintainer.as_deref(),
            Some("Wichert Akkerman <wakkerma@debian.org>")
        );
        assert_eq!(c.section.as_deref(), Some("base"));
        assert_eq!(c.homepage, None);
        assert_eq!(c.synopsis.as_deref(), Some("GNU grep, egrep and fgrep."));
        let extended = c.extended_description.unwrap();
        assert!(extended.starts_with("The GNU family of grep utilities"));
        assert!(extended.ends_with("will run more slowly, however)."));
        assert_eq!(extended.lines().count(), 8);
        assert!(get_rpm_arch(&c.architecture).is_err());
    }

    #[test]
    fn description_blank_lines_and_case_insensitive_fields() {
        let c: Control = "package: demo\nVERSION: 1.0\nArchitecture: all\n\
             Homepage: https://example.invalid/\n\
             Description: Short\n First paragraph.\n .\n   indented\n\n\
             Package: second-paragraph-ignored\n"
            .parse()
            .unwrap();
        assert_eq!(c.package, "demo");
        assert_eq!(c.homepage.as_deref(), Some("https://example.invalid/"));
        assert_eq!(c.synopsis.as_deref(), Some("Short"));
        assert_eq!(
            c.extended_description.as_deref(),
            Some("First paragraph.\n\n  indented")
        );

        let c: Control = "Package: demo\nVersion: 1\nArchitecture: all\nDescription: only\n"
            .parse()
            .unwrap();
        assert_eq!(c.extended_description, None);
        let c: Control = "Package: demo\nVersion: 1\nArchitecture: all\n"
            .parse()
            .unwrap();
        assert_eq!((c.synopsis, c.extended_description), (None, None));
    }

    #[test]
    fn rejects_invalid_control_files() {
        let base = "Package: demo\nVersion: 1.0\nArchitecture: all\n";
        assert!(base.parse::<Control>().is_ok());
        for bad in [
            "Version: 1.0\nArchitecture: all\n",
            "Package: demo\nArchitecture: all\n",
            "Package: demo\nVersion: 1.0\n",
            "Package: demo\nVersion:\nArchitecture: all\n",
            "Package: Demo\nVersion: 1.0\nArchitecture: all\n",
            "Package: d\nVersion: 1.0\nArchitecture: all\n",
            "Package: demo\nVersion: x y\nArchitecture: all\n",
            "Package: demo\nPackage: demo\nVersion: 1.0\nArchitecture: all\n",
            " continuation\nPackage: demo\nVersion: 1.0\nArchitecture: all\n",
            "Package demo\nVersion: 1.0\nArchitecture: all\n",
        ] {
            assert!(bad.parse::<Control>().is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn version_parsing() {
        // Forms from Debian Policy §5.6.12.
        let v: DebVersion = "1:2.30-1ubuntu1~22.04".parse().unwrap();
        assert_eq!(v.epoch, Some(1));
        assert_eq!(v.upstream, "2.30");
        assert_eq!(v.revision.as_deref(), Some("1ubuntu1~22.04"));
        assert_eq!(v.to_string(), "1:2.30-1ubuntu1~22.04");

        let v: DebVersion = "2.0-rc1-3".parse().unwrap();
        assert_eq!(v.upstream, "2.0-rc1");
        assert_eq!(v.revision.as_deref(), Some("3"));
        assert_eq!(v.get_rpm_version(), "2.0_rc1");

        let v: DebVersion = "3:1.2:3~beta+dfsg".parse().unwrap();
        assert_eq!(v.epoch, Some(3));
        assert_eq!(v.revision, None);
        assert_eq!(v.get_rpm_version(), "1.2_3~beta+dfsg");
        assert_eq!(v.to_string(), "3:1.2:3~beta+dfsg");

        for bad in [
            "", "1:", "x:1.0", "+1:1.0", "-1", "1.0-", "1.0_1", "1.0-a-", "1 0",
        ] {
            assert!(bad.parse::<DebVersion>().is_err(), "accepted {bad:?}");
        }
        assert!("99999999999:1".parse::<DebVersion>().is_err());
    }

    #[test]
    fn architecture_mapping() {
        assert_eq!(get_rpm_arch("amd64").unwrap(), "x86_64");
        assert_eq!(get_rpm_arch("arm64").unwrap(), "aarch64");
        assert_eq!(get_rpm_arch("all").unwrap(), "noarch");
        assert_eq!(get_rpm_arch("i386").unwrap(), "i686");
        assert_eq!(get_rpm_arch("ppc64el").unwrap(), "ppc64le");
        assert!(get_rpm_arch("hurd-i386").is_err());
        assert!(get_rpm_arch("").is_err());
    }

    #[test]
    fn conffiles_parsing() {
        let set = parse_conffiles(
            "/etc/demo/demo.conf\n\n  /etc/default/demo  \n\
             remove-on-upgrade /etc/demo/old.conf\nbogus-flag /etc/demo/x\nnot-a-path\n",
        );
        let mut paths: Vec<_> = set.into_iter().collect();
        paths.sort();
        assert_eq!(
            paths,
            ["/etc/default/demo", "/etc/demo/demo.conf", "/etc/demo/x"]
        );
    }
}
