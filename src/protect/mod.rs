pub mod audio;
pub mod dbus;
pub mod wayland;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::RwLock;
use zbus::Connection;

/// Set of cgroups and PIDs we must never throttle — compositor, portals,
/// audio stack.
#[derive(Debug, Clone)]
pub struct ProtectSet {
    pub cgroups: HashSet<PathBuf>,
    pub pids: HashSet<u32>,
    pub refreshed_at: Instant,
}

impl ProtectSet {
    pub fn empty() -> Self {
        Self {
            cgroups: HashSet::new(),
            pids: HashSet::new(),
            refreshed_at: Instant::now(),
        }
    }

    /// Run every discovery source and build a fresh set. Safe to call
    /// repeatedly (eg. on `NameOwnerChanged`). Each run logs what it finds
    /// at `info`.
    pub async fn discover(bus: Option<&Connection>) -> Self {
        let mut set = Self::empty();

        for comp in wayland::discover_compositors() {
            tracing::info!(
                source = "wayland",
                socket = %comp.socket.display(),
                pid = comp.pid,
                scope = %comp.scope_cgroup.display(),
                "protected: compositor",
            );
            set.pids.insert(comp.pid);
            set.cgroups.insert(comp.scope_cgroup);
        }

        if let Some(conn) = bus {
            for svc in dbus::discover_named_services(conn).await {
                tracing::info!(
                    source = "dbus",
                    bus_name = %svc.bus_name,
                    pid = svc.pid,
                    scope = %svc.scope_cgroup.display(),
                    "protected: named service",
                );
                set.pids.insert(svc.pid);
                set.cgroups.insert(svc.scope_cgroup);
            }
        }

        for path in audio::discover_audio_stack() {
            tracing::info!(
                source = "audio",
                scope = %path.display(),
                "protected: audio",
            );
            set.cgroups.insert(path);
        }

        set.refreshed_at = Instant::now();
        set
    }

    pub fn is_empty(&self) -> bool {
        self.cgroups.is_empty() && self.pids.is_empty()
    }

    /// Exact cgroup-path match.
    pub fn contains_cgroup(&self, path: &Path) -> bool {
        self.cgroups.contains(path)
    }

    /// True if `path` equals or is a descendant of any protected cgroup.
    /// The attribution-filter predicate.
    pub fn covers(&self, path: &Path) -> bool {
        self.cgroups
            .iter()
            .any(|protected| path == protected || path.starts_with(protected))
    }
}

/// Shared handle to a `ProtectSet` that can be atomically swapped. The
/// trigger loop reads it; a background task refreshes it on
/// `NameOwnerChanged`.
#[derive(Clone)]
pub struct Protect {
    inner: Arc<RwLock<ProtectSet>>,
}

impl Protect {
    pub fn new(set: ProtectSet) -> Self {
        Self {
            inner: Arc::new(RwLock::new(set)),
        }
    }

    /// Clone a snapshot of the current set. Cheap (HashSet clone, ~dozens of
    /// entries). Preferred over holding a read guard across `.await` points
    /// in the trigger loop.
    pub async fn snapshot(&self) -> ProtectSet {
        self.inner.read().await.clone()
    }

    pub async fn replace(&self, new_set: ProtectSet) {
        let mut guard = self.inner.write().await;
        *guard = new_set;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_with(paths: &[&str]) -> ProtectSet {
        let mut s = ProtectSet::empty();
        for p in paths {
            s.cgroups.insert(PathBuf::from(p));
        }
        s
    }

    #[test]
    fn contains_cgroup_is_exact() {
        let s = set_with(&["/sys/fs/cgroup/user.slice/plasma.service"]);
        assert!(s.contains_cgroup(Path::new(
            "/sys/fs/cgroup/user.slice/plasma.service"
        )));
        assert!(!s.contains_cgroup(Path::new(
            "/sys/fs/cgroup/user.slice/plasma.service/child"
        )));
    }

    #[test]
    fn covers_is_ancestor_aware() {
        let s = set_with(&["/sys/fs/cgroup/user.slice/plasma.service"]);
        assert!(s.covers(Path::new(
            "/sys/fs/cgroup/user.slice/plasma.service"
        )));
        assert!(s.covers(Path::new(
            "/sys/fs/cgroup/user.slice/plasma.service/child/leaf"
        )));
        assert!(!s.covers(Path::new("/sys/fs/cgroup/user.slice/other.scope")));
    }

    #[test]
    fn empty_set_covers_nothing() {
        let s = ProtectSet::empty();
        assert!(s.is_empty());
        assert!(!s.covers(Path::new("/anything")));
    }

    #[tokio::test]
    async fn protect_handle_snapshot_and_replace() {
        let handle = Protect::new(set_with(&["/a"]));
        assert!(handle.snapshot().await.contains_cgroup(Path::new("/a")));
        handle.replace(set_with(&["/b"])).await;
        assert!(!handle.snapshot().await.contains_cgroup(Path::new("/a")));
        assert!(handle.snapshot().await.contains_cgroup(Path::new("/b")));
    }
}
