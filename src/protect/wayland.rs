use anyhow::{anyhow, Context, Result};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};

use nix::sys::socket::{
    connect, getsockopt, socket, sockopt, AddressFamily, SockFlag, SockType, UnixAddr,
    UnixCredentials,
};

use crate::cgroup::tree::CGROUP_ROOT;

#[derive(Debug, Clone)]
pub struct Compositor {
    /// Path of the Wayland socket we identified the compositor through.
    pub socket: PathBuf,
    /// Compositor process PID via `SO_PEERCRED`.
    pub pid: u32,
    /// The PID's actual cgroup path under `/sys/fs/cgroup`.
    pub cgroup: PathBuf,
    /// Walked up to the nearest enclosing `.scope`/`.service` (usually ==
    /// `cgroup` for well-behaved session units).
    pub scope_cgroup: PathBuf,
}

/// Discover every Wayland compositor reachable from this user session and
/// return one `Compositor` per connectable socket.
///
/// Side effect: issues a stream `connect(2)` against each socket. The
/// compositor sees a client connect + close without sending protocol bytes;
/// every Wayland compositor tolerates this.
pub fn discover_compositors() -> Vec<Compositor> {
    let runtime_dir = match std::env::var("XDG_RUNTIME_DIR") {
        Ok(s) => PathBuf::from(s),
        Err(_) => {
            tracing::debug!("XDG_RUNTIME_DIR not set; skipping wayland socket discovery");
            return Vec::new();
        }
    };

    let entries = match std::fs::read_dir(&runtime_dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::debug!(
                error = %e,
                dir = %runtime_dir.display(),
                "cannot read XDG_RUNTIME_DIR",
            );
            return Vec::new();
        }
    };

    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else { continue };
        if !is_wayland_socket(name_str) {
            continue;
        }
        let path = entry.path();
        match inspect_socket(&path) {
            Ok(comp) => out.push(comp),
            Err(e) => tracing::debug!(
                socket = %path.display(),
                error = %e,
                "skipping wayland socket",
            ),
        }
    }
    out
}

fn is_wayland_socket(name: &str) -> bool {
    name.starts_with("wayland-") && !name.ends_with(".lock")
}

fn inspect_socket(path: &Path) -> Result<Compositor> {
    let fd: OwnedFd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .context("creating AF_UNIX stream socket")?;

    let addr =
        UnixAddr::new(path).with_context(|| format!("UnixAddr::new({})", path.display()))?;
    connect(fd.as_raw_fd(), &addr)
        .with_context(|| format!("connect({})", path.display()))?;

    let creds: UnixCredentials = getsockopt(&fd, sockopt::PeerCredentials)
        .with_context(|| format!("SO_PEERCRED on {}", path.display()))?;

    let pid = u32::try_from(creds.pid())
        .with_context(|| format!("SO_PEERCRED returned non-positive pid {}", creds.pid()))?;
    let cgroup = pid_cgroup_v2(pid).with_context(|| format!("reading cgroup of pid {pid}"))?;
    let scope_cgroup = enclosing_scope_or_service(&cgroup);

    Ok(Compositor {
        socket: path.to_path_buf(),
        pid,
        cgroup,
        scope_cgroup,
    })
}

/// Read `/proc/<pid>/cgroup` and return the absolute cgroupfs path for the
/// v2 unified hierarchy (the `0::` entry). Errors if no v2 entry is present
/// (hybrid or v1 system).
pub fn pid_cgroup_v2(pid: u32) -> Result<PathBuf> {
    let file = format!("/proc/{pid}/cgroup");
    let contents = std::fs::read_to_string(&file).with_context(|| format!("reading {file}"))?;
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            let rel = rest.trim_start_matches('/');
            let root = Path::new(CGROUP_ROOT);
            return Ok(if rel.is_empty() {
                root.to_path_buf()
            } else {
                root.join(rel)
            });
        }
    }
    Err(anyhow!(
        "no cgroup v2 entry (`0::...`) in {file} — cgroup v1 hybrid system?"
    ))
}

/// If `cgroup`'s basename ends with `.scope` or `.service`, return it.
/// Otherwise walk parents until we find one. Returns the input path
/// unchanged if no ancestor matches (defensive fallback).
pub fn enclosing_scope_or_service(cgroup: &Path) -> PathBuf {
    let mut cur = cgroup;
    loop {
        if let Some(name) = cur.file_name().and_then(|n| n.to_str()) {
            if name.ends_with(".scope") || name.ends_with(".service") {
                return cur.to_path_buf();
            }
        }
        match cur.parent() {
            Some(parent) if !parent.as_os_str().is_empty() && parent != cur => cur = parent,
            _ => return cgroup.to_path_buf(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_wayland_socket_names() {
        assert!(is_wayland_socket("wayland-0"));
        assert!(is_wayland_socket("wayland-1"));
        assert!(!is_wayland_socket("wayland-0.lock"));
        assert!(!is_wayland_socket("wayland-1.lock"));
        assert!(!is_wayland_socket("pipewire-0"));
        assert!(!is_wayland_socket("bus"));
    }

    #[test]
    fn enclosing_scope_returns_service_at_leaf() {
        let p = Path::new(
            "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/\
             session.slice/plasma-kwin_wayland.service",
        );
        assert_eq!(enclosing_scope_or_service(p), p);
    }

    #[test]
    fn enclosing_scope_walks_up_past_subgroups() {
        // compositor spawned a child process living in a pressure-tracked
        // descendant cgroup of its service — we want the service.
        let inner = Path::new(
            "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/\
             session.slice/plasma-kwin_wayland.service/init.scope/extra",
        );
        let expected = Path::new(
            "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/\
             session.slice/plasma-kwin_wayland.service/init.scope",
        );
        assert_eq!(enclosing_scope_or_service(inner), expected);
    }

    #[test]
    fn enclosing_scope_falls_back_when_no_match() {
        let p = Path::new("/sys/fs/cgroup/user.slice");
        assert_eq!(enclosing_scope_or_service(p), p);
    }

    #[test]
    fn pid_cgroup_v2_for_self() {
        let pid = std::process::id();
        let cg = pid_cgroup_v2(pid).unwrap();
        assert!(cg.starts_with(CGROUP_ROOT), "got {cg:?}");
        assert!(cg.exists(), "cgroup path should exist on v2 systems: {cg:?}");
    }

    #[test]
    fn pid_cgroup_v2_for_invalid_pid() {
        // PID 0 is never a real process; /proc/0/cgroup doesn't exist.
        let err = pid_cgroup_v2(0);
        assert!(err.is_err());
    }
}
