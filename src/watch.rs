//! Filesystem watching: triggers a rescan shortly after packages change,
//! so the periodic rescan only acts as a fallback (e.g. for NFS mounts,
//! where inotify does not see changes made on other hosts).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use notify::event::{AccessKind, AccessMode};
use notify::{Event, EventKind, RecursiveMode, Watcher};
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

/// Quiet period after the last change before rescanning, so a file being
/// copied in is scanned once it is complete.
pub const DEBOUNCE: Duration = Duration::from_secs(2);

/// Whether a change touches only hidden entries (relative to the watched
/// root), such as in-progress downloads or downloader state.
fn is_hidden(path: &Path, roots: &[PathBuf]) -> bool {
    let rel = roots
        .iter()
        .find_map(|r| path.strip_prefix(r).ok())
        .unwrap_or(path);
    rel.components()
        .any(|c| c.as_os_str().to_str().is_some_and(|s| s.starts_with('.')))
}

/// Ignores reads (including the server's own) and hidden paths.
fn is_relevant(event: &Event, roots: &[PathBuf]) -> bool {
    if let EventKind::Access(kind) = event.kind
        && kind != AccessKind::Close(AccessMode::Write)
    {
        return false;
    }
    event.paths.is_empty() || event.paths.iter().any(|p| !is_hidden(p, roots))
}

/// Watches `roots` recursively and notifies `trigger` once changes have
/// settled for `debounce`. Watch errors (e.g. a dropped event queue) also
/// trigger a rescan, as changes may have been missed.
pub fn spawn_watcher(
    roots: Vec<PathBuf>,
    trigger: Arc<Notify>,
    debounce: Duration,
) -> Result<JoinHandle<()>> {
    let (tx, mut rx) = mpsc::unbounded_channel::<()>();
    let filter_roots = roots.clone();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| match res {
        Ok(event) if is_relevant(&event, &filter_roots) => {
            let _ = tx.send(());
        }
        Ok(_) => {}
        Err(err) => {
            warn!(%err, "filesystem watch error; rescanning");
            let _ = tx.send(());
        }
    })
    .context("creating filesystem watcher")?;
    for root in &roots {
        watcher
            .watch(root, RecursiveMode::Recursive)
            .with_context(|| format!("watching {}", root.display()))?;
    }

    Ok(tokio::spawn(async move {
        // Dropping the watcher stops it, so it lives as long as this task.
        let _watcher = watcher;
        while rx.recv().await.is_some() {
            loop {
                match tokio::time::timeout(debounce, rx.recv()).await {
                    Ok(Some(())) => continue,
                    Ok(None) => return,
                    Err(_elapsed) => break,
                }
            }
            debug!("filesystem change detected");
            trigger.notify_one();
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{CreateKind, ModifyKind, RenameMode};

    fn event(kind: EventKind, paths: &[&str]) -> Event {
        let mut e = Event::new(kind);
        for p in paths {
            e = e.add_path(PathBuf::from(p));
        }
        e
    }

    #[test]
    fn relevance_filter() {
        let roots = [PathBuf::from("/srv/.data/rpms")];
        let create = EventKind::Create(CreateKind::File);
        assert!(is_relevant(
            &event(create, &["/srv/.data/rpms/a.rpm"]),
            &roots
        ));
        assert!(is_relevant(
            &event(create, &["/srv/.data/rpms/sub/a.rpm"]),
            &roots
        ));
        assert!(!is_relevant(
            &event(create, &["/srv/.data/rpms/.download-1.part"]),
            &roots
        ));
        assert!(!is_relevant(
            &event(create, &["/srv/.data/rpms/.sources/abc.tmp"]),
            &roots
        ));
        assert!(is_relevant(&event(EventKind::Any, &[]), &roots));

        let rename = EventKind::Modify(ModifyKind::Name(RenameMode::Both));
        let paths = ["/srv/.data/rpms/.download-1.part", "/srv/.data/rpms/a.rpm"];
        assert!(is_relevant(&event(rename, &paths), &roots));

        let read = EventKind::Access(AccessKind::Close(AccessMode::Read));
        let open = EventKind::Access(AccessKind::Open(AccessMode::Any));
        let write = EventKind::Access(AccessKind::Close(AccessMode::Write));
        assert!(!is_relevant(
            &event(read, &["/srv/.data/rpms/a.rpm"]),
            &roots
        ));
        assert!(!is_relevant(
            &event(open, &["/srv/.data/rpms/a.rpm"]),
            &roots
        ));
        assert!(is_relevant(
            &event(write, &["/srv/.data/rpms/a.rpm"]),
            &roots
        ));
    }

    async fn fired(trigger: &Notify, within: Duration) -> bool {
        tokio::time::timeout(within, trigger.notified())
            .await
            .is_ok()
    }

    #[tokio::test]
    async fn notifies_after_changes_settle() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::write(root.join("existing.rpm"), b"x").unwrap();
        let trigger = Arc::new(Notify::new());
        let _task = spawn_watcher(
            vec![root.clone()],
            trigger.clone(),
            Duration::from_millis(200),
        )
        .unwrap();

        // Reads and hidden files are ignored.
        std::fs::read(root.join("existing.rpm")).unwrap();
        std::fs::write(root.join(".hidden.part"), b"x").unwrap();
        assert!(!fired(&trigger, Duration::from_secs(1)).await);

        // A burst of writes produces a single notification.
        std::fs::create_dir(root.join("sub")).unwrap();
        for i in 0..5 {
            std::fs::write(root.join(format!("sub/{i}.rpm")), b"x").unwrap();
        }
        assert!(fired(&trigger, Duration::from_secs(5)).await);
        assert!(!fired(&trigger, Duration::from_secs(1)).await);

        // Directories created after the watch started are watched too.
        std::fs::remove_file(root.join("sub/0.rpm")).unwrap();
        assert!(fired(&trigger, Duration::from_secs(5)).await);
    }

    #[test]
    fn missing_root_is_an_error() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let r = spawn_watcher(
            vec![PathBuf::from("/nonexistent/rpm-server-test")],
            Arc::new(Notify::new()),
            DEBOUNCE,
        );
        assert!(r.is_err());
    }
}
