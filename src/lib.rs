//! Serves a directory of RPM packages as a dnf repository, generating
//! `repodata/` in memory and optionally re-signing packages on the fly.

pub mod config;
pub mod health;
pub mod package;
pub mod repo;
pub mod repodata;
pub mod server;
pub mod signing;
pub mod sources;
#[cfg(test)]
mod testutil;
pub mod watch;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::repo::Scanner;
use crate::server::AppState;
use crate::sources::Updater;

/// Rescans the package folders every `every` (if set) and whenever
/// `trigger` is notified, swapping in new snapshots.
pub fn spawn_rescan(
    scanner: Scanner,
    state: Arc<AppState>,
    every: Option<Duration>,
    trigger: Arc<Notify>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut scanner = Some(scanner);
        let mut ticker = every.map(|every| {
            let mut t = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            t
        });
        loop {
            let tick = async {
                match &mut ticker {
                    Some(t) => {
                        t.tick().await;
                    }
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                () = tick => {},
                () = trigger.notified() => {},
            }
            let Some(mut s) = scanner.take() else { return };
            let joined = tokio::task::spawn_blocking(move || {
                let result = s.scan();
                (s, result)
            })
            .await;
            match joined {
                Ok((s, result)) => {
                    scanner = Some(s);
                    match result {
                        Ok(repo) => {
                            state.set_scan_error(None);
                            if let Some(repo) = repo {
                                state.set_repo(repo);
                            }
                        }
                        Err(err) => {
                            error!("rescan failed, keeping previous metadata: {err:#}");
                            state.set_scan_error(Some(format!("{err:#}")));
                        }
                    }
                }
                Err(err) => {
                    error!("rescan task panicked, rescanning disabled: {err}");
                    state.set_scan_error(Some("rescan task panicked".into()));
                    return;
                }
            }
        }
    })
}

/// Downloads sources immediately and then every `every`, notifying
/// `on_change` when a new package was stored.
pub fn spawn_updater(updater: Updater, every: Duration, on_change: Arc<Notify>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(every);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            info!("updating online sources");
            if updater.update_all().await {
                on_change.notify_one();
            }
        }
    })
}

/// Serves `state` on `listener` until `shutdown` resolves.
pub async fn serve(
    listener: TcpListener,
    state: Arc<AppState>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(listener, server::router(state))
        .with_graceful_shutdown(shutdown)
        .await
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            error!("failed to listen for ctrl-c: {err}");
            std::future::pending::<()>().await;
        }
    };
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(err) => {
                error!("failed to listen for SIGTERM: {err}");
                std::future::pending::<()>().await;
            }
        }
    };
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    info!("shutting down");
}

/// Runs the server described by `config` until SIGINT/SIGTERM.
pub async fn run(config: Config) -> Result<()> {
    let signer = config.load_signer()?;
    match &signer {
        Some(s) => info!(
            fingerprint = %s.fingerprint(),
            sign_packages = s.signs_packages(),
            "signing enabled"
        ),
        None => info!("no signing key configured; serving packages unmodified"),
    }

    let download_dir = config.prepare_download_dir()?;
    let dir = config.dir.clone();
    let scan_download_dir = download_dir.clone();
    let (scanner, repo) = tokio::task::spawn_blocking(move || {
        let mut scanner = Scanner::new(dir, signer);
        if let Some(d) = scan_download_dir {
            scanner = scanner.with_extra_root(sources::URL_PREFIX, d);
        }
        let repo = scanner.scan()?;
        anyhow::Ok((scanner, repo))
    })
    .await??;
    let repo = repo.context("initial scan produced no repository")?;
    let state = AppState::new(repo, config.repo_id.clone(), config.base_url.clone());

    let rescan_trigger = Arc::new(Notify::new());
    let every = (config.rescan_interval > 0).then(|| Duration::from_secs(config.rescan_interval));
    spawn_rescan(scanner, state.clone(), every, rescan_trigger.clone());

    let mut watch_roots = vec![config.dir.clone()];
    watch_roots.extend(download_dir.clone());
    match watch::spawn_watcher(watch_roots, rescan_trigger.clone(), watch::DEBOUNCE) {
        Ok(_) => info!("watching package folders for changes"),
        Err(err) => warn!("filesystem watching unavailable, relying on periodic rescans: {err:#}"),
    }

    if let (Some(sources_file), Some(download_dir)) = (config.sources_file.clone(), download_dir) {
        let updater = Updater::new(sources_file, download_dir)?;
        spawn_updater(
            updater,
            Duration::from_secs(config.update_interval),
            rescan_trigger,
        );
    }

    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("binding {}", config.listen))?;
    info!(addr = %listener.local_addr()?, dir = %config.dir.display(), "listening");
    serve(listener, state, shutdown_signal()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn wait_for(state: &AppState, path: &str, present: bool) {
        for _ in 0..100 {
            if state.repo().get(path).is_some() == present {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("{path} present={present} never observed");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn watched_changes_reach_the_repository() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let mut scanner = Scanner::new(root.clone(), None);
        let repo = scanner.scan().unwrap().unwrap();
        let state = AppState::new(repo, "test".into(), None);
        let trigger = Arc::new(Notify::new());
        // No periodic rescans: only the watcher can cause updates.
        spawn_rescan(scanner, state.clone(), None, trigger.clone());
        let _watch =
            watch::spawn_watcher(vec![root.clone()], trigger, Duration::from_millis(200)).unwrap();

        std::fs::create_dir(root.join("new")).unwrap();
        std::fs::write(root.join("new/a.rpm"), testutil::build_rpm("a", "1.0", &[])).unwrap();
        wait_for(&state, "new/a.rpm", true).await;

        std::fs::remove_file(root.join("new/a.rpm")).unwrap();
        wait_for(&state, "new/a.rpm", false).await;
    }

    async fn wait_for_health(state: &Arc<AppState>, status: u16) {
        use tower::ServiceExt;
        for _ in 0..100 {
            let req = axum::http::Request::get("/healthz")
                .body(axum::body::Body::empty())
                .unwrap();
            let resp = server::router(state.clone()).oneshot(req).await.unwrap();
            if resp.status().as_u16() == status {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("health never reached {status}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn failed_rescan_marks_unhealthy_until_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("rpms");
        std::fs::create_dir(&root).unwrap();
        let mut scanner = Scanner::new(root.clone(), None);
        let state = AppState::new(scanner.scan().unwrap().unwrap(), "test".into(), None);
        let trigger = Arc::new(Notify::new());
        spawn_rescan(scanner, state.clone(), None, trigger.clone());
        wait_for_health(&state, 200).await;

        std::fs::remove_dir(&root).unwrap();
        trigger.notify_one();
        wait_for_health(&state, 503).await;

        std::fs::create_dir(&root).unwrap();
        trigger.notify_one();
        wait_for_health(&state, 200).await;
    }
}
