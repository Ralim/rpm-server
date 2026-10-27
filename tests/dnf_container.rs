//! End-to-end tests: a repository is served from this test process and real
//! dnf clients running in podman containers (`--network=host`) install from it.
//!
//! Requires `podman` and network access to pull the client images.

use std::path::Path;
use std::process::Output;
use std::sync::Arc;

use rpm::{BuildConfig, CompressionType, Dependency, FileOptions, PackageBuilder};
use rpm_server::repo::Scanner;
use rpm_server::server::AppState;
use rpm_server::signing::{RepoSigner, generate_secret_key};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

const FEDORA: &str = "registry.fedoraproject.org/fedora:latest";
const AMAZON_LINUX: &str = "public.ecr.aws/amazonlinux/amazonlinux:2023";
const REPO_ID: &str = "rpmserve-test";
const GREETING: &str = "hello from rpm-server";

fn write_rpm(path: &Path, builder: &mut PackageBuilder) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut bytes = Vec::new();
    builder.build().unwrap().write(&mut bytes).unwrap();
    std::fs::write(path, bytes).unwrap();
}

/// Two packages: `hello-rpmserve` (root dir) depends on `hello-rpmserve-data++`
/// (nested dir, `+` in the file name), which carries the greeting text.
fn write_packages(root: &Path) {
    let config = || BuildConfig::v4().compression(CompressionType::Gzip);

    let mut app = PackageBuilder::new(
        "hello-rpmserve",
        "1.0",
        "MIT",
        "noarch",
        "Greets from rpm-server",
    );
    app.using_config(config())
        .release("1")
        .with_file_contents(
            "#!/bin/sh\ncat /usr/share/hello-rpmserve-data/message\n",
            FileOptions::new("/usr/bin/hello-rpmserve").permissions(0o755),
        )
        .unwrap()
        .with_file_contents(
            "unused\n",
            FileOptions::new("/usr/share/hello-rpmserve/self").permissions(0o644),
        )
        .unwrap()
        // Satisfied by this package itself through a non-primary file.
        .requires(Dependency::any("/usr/share/hello-rpmserve/self"))
        .requires(Dependency::greater_eq("hello-rpmserve-data", "1.0"));
    write_rpm(&root.join("hello-rpmserve-1.0-1.noarch.rpm"), &mut app);

    let mut data = PackageBuilder::new(
        "hello-rpmserve-data++",
        "1.0",
        "MIT",
        "noarch",
        "Data for hello-rpmserve",
    );
    data.using_config(config())
        .release("1")
        .with_file_contents(
            format!("{GREETING}\n"),
            FileOptions::new("/usr/share/hello-rpmserve-data/message").permissions(0o644),
        )
        .unwrap()
        .provides(Dependency::eq("hello-rpmserve-data", "1.0"));
    write_rpm(
        &root.join("nested/dir/hello-rpmserve-data++-1.0-1.noarch.rpm"),
        &mut data,
    );
}

struct TestServer {
    _dir: tempfile::TempDir,
    base_url: String,
    shutdown: Option<oneshot::Sender<()>>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

async fn start_server(signed: bool) -> TestServer {
    let dir = tempfile::tempdir().unwrap();
    write_packages(dir.path());
    let signer = signed.then(|| {
        let asc = generate_secret_key("rpm-server e2e <e2e@example.invalid>", None).unwrap();
        Arc::new(RepoSigner::from_armored(&asc, None, true).unwrap())
    });
    let root = dir.path().to_owned();
    let repo = tokio::task::spawn_blocking(move || Scanner::new(root, signer).scan())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(repo.package_count, 2);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let state = AppState::new(repo, REPO_ID.into(), None);
    let (tx, rx) = oneshot::channel();
    tokio::spawn(rpm_server::serve(listener, state, async {
        let _ = rx.await;
    }));
    TestServer {
        _dir: dir,
        base_url: format!("http://127.0.0.1:{port}"),
        shutdown: Some(tx),
    }
}

async fn podman_run(image: &str, script: &str) -> Output {
    let output = tokio::process::Command::new("podman")
        .args(["run", "--rm", "--network=host", image, "sh", "-c", script])
        .output()
        .await
        .expect("failed to execute podman; it is required for these tests");
    eprintln!(
        "--- {image} stdout ---\n{}\n--- {image} stderr ---\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn assert_installed(output: &Output) {
    assert!(output.status.success(), "container script failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!("GREETING: {GREETING}")),
        "greeting missing from output"
    );
}

/// Installs using the server's generated `.repo` file, so package signatures
/// (`gpgcheck`) and the repomd.xml signature (`repo_gpgcheck`) are enforced.
fn signed_install_script(base_url: &str) -> String {
    format!(
        r#"set -ex
curl -fsS -o /etc/yum.repos.d/{REPO_ID}.repo {base_url}/{REPO_ID}.repo
cat /etc/yum.repos.d/{REPO_ID}.repo
grep -q '^gpgcheck=1$' /etc/yum.repos.d/{REPO_ID}.repo
grep -q '^repo_gpgcheck=1$' /etc/yum.repos.d/{REPO_ID}.repo
dnf -y --disablerepo='*' --enablerepo={REPO_ID} install hello-rpmserve
curl -fsS -o /tmp/data.rpm '{base_url}/nested/dir/hello-rpmserve-data++-1.0-1.noarch.rpm'
rpm -K /tmp/data.rpm | grep 'signatures OK'
echo "GREETING: $(hello-rpmserve)"
"#
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn fedora_dnf5_installs_from_signed_repo() {
    let server = start_server(true).await;
    let output = podman_run(FEDORA, &signed_install_script(&server.base_url)).await;
    assert_installed(&output);
}

#[tokio::test(flavor = "multi_thread")]
async fn amazon_linux_dnf4_installs_from_signed_repo() {
    let server = start_server(true).await;
    let output = podman_run(AMAZON_LINUX, &signed_install_script(&server.base_url)).await;
    assert_installed(&output);
}

#[tokio::test(flavor = "multi_thread")]
async fn fedora_dnf5_unsigned_repo_and_gpgcheck_enforcement() {
    let server = start_server(false).await;
    let base_url = &server.base_url;
    let script = format!(
        r#"set -ex
cat > /etc/yum.repos.d/{REPO_ID}.repo <<EOF
[{REPO_ID}]
name={REPO_ID}
baseurl={base_url}/
gpgcheck=1
repo_gpgcheck=0
skip_if_unavailable=0
EOF
if dnf -y --disablerepo='*' --enablerepo={REPO_ID} install hello-rpmserve; then
  echo "unsigned packages were installed despite gpgcheck=1"
  exit 1
fi
dnf -y --disablerepo='*' --enablerepo={REPO_ID} --setopt={REPO_ID}.gpgcheck=0 install hello-rpmserve
echo "GREETING: $(hello-rpmserve)"
"#
    );
    let output = podman_run(FEDORA, &script).await;
    assert_installed(&output);
}
