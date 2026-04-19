pub mod wayland;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Set of cgroups and PIDs we must never throttle — compositor, portals,
/// audio stack in future sessions, etc. Discovery is pluggable; v1 of the
/// discovery only talks to the Wayland sockets. D-Bus and session queries
/// land in sessions 2.2 and 2.3.
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

    /// Query every source and build a fresh protect set. Logs each
    /// compositor it resolves at `info` so operators can see what's
    /// being held harmless.
    pub fn discover() -> Self {
        let mut set = Self::empty();
        for comp in wayland::discover_compositors() {
            tracing::info!(
                source = "wayland",
                socket = %comp.socket.display(),
                pid = comp.pid,
                cgroup = %comp.cgroup.display(),
                scope = %comp.scope_cgroup.display(),
                "protected: compositor"
            );
            set.pids.insert(comp.pid);
            set.cgroups.insert(comp.scope_cgroup);
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

    /// True if `path` equals or is a descendant of any protected cgroup —
    /// the semantically interesting check for "should this cgroup be
    /// off-limits to the attributor".
    pub fn covers(&self, path: &Path) -> bool {
        self.cgroups
            .iter()
            .any(|protected| path == protected || path.starts_with(protected))
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
}
