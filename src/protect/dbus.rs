use std::path::PathBuf;

use anyhow::{Context, Result};
use zbus::fdo::DBusProxy;
use zbus::names::BusName;
use zbus::Connection;

use crate::protect::wayland::{enclosing_scope_or_service, pid_cgroup_v2};

/// Session-bus well-known names we want to resolve PIDs for and protect.
/// Adding to this list is additive — unreached names just get `NameHasNoOwner`
/// and are skipped.
pub const TRACKED_NAMES: &[&str] = &[
    "org.gnome.Shell",
    "org.kde.KWin",
    "org.freedesktop.portal.Desktop",
    "org.freedesktop.impl.portal.desktop.gnome",
    "org.freedesktop.impl.portal.desktop.kde",
];

#[derive(Debug, Clone)]
pub struct NamedService {
    pub bus_name: String,
    pub pid: u32,
    pub cgroup: PathBuf,
    pub scope_cgroup: PathBuf,
}

/// Resolve each `TRACKED_NAMES` entry to a PID via
/// `GetConnectionUnixProcessID` and then to a cgroup. Names that aren't
/// owned on the current session bus are silently skipped.
///
/// Returns an empty vec if the session bus isn't reachable at all.
pub async fn discover_named_services(conn: &Connection) -> Vec<NamedService> {
    let proxy = match DBusProxy::new(conn).await {
        Ok(p) => p,
        Err(e) => {
            tracing::debug!(error = %e, "cannot build org.freedesktop.DBus proxy");
            return Vec::new();
        }
    };

    let mut out = Vec::new();
    for name in TRACKED_NAMES {
        match resolve_name(&proxy, name).await {
            Ok(svc) => out.push(svc),
            Err(e) => tracing::debug!(
                name = %name,
                error = %e,
                "well-known name not resolved to a pid",
            ),
        }
    }
    out
}

async fn resolve_name(proxy: &DBusProxy<'_>, name: &str) -> Result<NamedService> {
    let bus_name =
        BusName::try_from(name).with_context(|| format!("invalid bus name {name:?}"))?;
    let pid = proxy
        .get_connection_unix_process_id(bus_name)
        .await
        .with_context(|| format!("GetConnectionUnixProcessID({name})"))?;
    let cgroup = pid_cgroup_v2(pid)?;
    let scope_cgroup = enclosing_scope_or_service(&cgroup);
    Ok(NamedService {
        bus_name: name.to_string(),
        pid,
        cgroup,
        scope_cgroup,
    })
}

/// True if `name` is a well-known name whose owner change should trigger a
/// protect-set refresh.
pub fn is_tracked_name(name: &str) -> bool {
    TRACKED_NAMES.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracked_names_are_syntactically_valid() {
        for name in TRACKED_NAMES {
            assert!(
                BusName::try_from(*name).is_ok(),
                "invalid bus name: {name}"
            );
        }
    }

    #[test]
    fn is_tracked_name_rejects_unknown() {
        assert!(is_tracked_name("org.gnome.Shell"));
        assert!(!is_tracked_name("org.example.Random"));
    }
}
