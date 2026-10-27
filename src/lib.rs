//! Serves a directory of RPM packages as a dnf repository, generating
//! `repodata/` in memory and optionally re-signing packages on the fly.

pub mod config;
pub mod package;
pub mod repo;
pub mod repodata;
pub mod server;
pub mod signing;
#[cfg(test)]
mod testutil;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{error, info};

use crate::config::Config;
use crate::repo::Scanner;
use crate::server::AppState;

/// Periodically rescans the package directory and swaps in new snapshots.
pub fn spawn_rescan(scanner: Scanner, state: Arc<AppState>, every: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut scanner = Some(scanner);
        let mut ticker = tokio::time::interval(every);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            ticker.tick().await;
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
                        Ok(Some(repo)) => state.set_repo(repo),
                        Ok(None) => {}
                        Err(err) => error!("rescan failed, keeping previous metadata: {err:#}"),
                    }
                }
                Err(err) => {
                    error!("rescan task panicked, rescanning disabled: {err}");
                    return;
                }
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

    let dir = config.dir.clone();
    let (scanner, repo) = tokio::task::spawn_blocking(move || {
        let mut scanner = Scanner::new(dir, signer);
        let repo = scanner.scan()?;
        anyhow::Ok((scanner, repo))
    })
    .await??;
    let repo = repo.context("initial scan produced no repository")?;
    let state = AppState::new(repo, config.repo_id.clone(), config.base_url.clone());

    if config.rescan_interval > 0 {
        spawn_rescan(
            scanner,
            state.clone(),
            Duration::from_secs(config.rescan_interval),
        );
    }

    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("binding {}", config.listen))?;
    info!(addr = %listener.local_addr()?, dir = %config.dir.display(), "listening");
    serve(listener, state, shutdown_signal()).await?;
    Ok(())
}
