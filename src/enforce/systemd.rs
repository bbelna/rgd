//! systemd Manager proxy for transient property writes.
//!
//! Every enforcement call goes through `SetUnitProperties(name, runtime=true,
//! properties)` on the user systemd's `org.freedesktop.systemd1.Manager`
//! interface. `runtime=true` is the critical flag: all properties evaporate
//! on `systemctl daemon-reload`, reboot, or explicit unset — so a worst-case
//! daemon crash leaves the system in a recoverable state bounded by the next
//! reboot.
//!
//! We target the *user* systemd instance, not the system one. Desktop
//! compositor-style enforcement (the whole point of rgd) only makes sense
//! for user-session scopes; anything in `system.slice` is explicitly
//! refused upstream of this module.

use std::sync::Arc;

use anyhow::Context;
use zbus::names::BusName;
use zbus::zvariant::Value;
use zbus::Connection;

/// The destination/path for the systemd Manager interface. These are the
/// same for system and user systemd — which one you hit depends on which
/// bus the connection is attached to.
const SYSTEMD_BUS: &str = "org.freedesktop.systemd1";
const SYSTEMD_PATH: &str = "/org/freedesktop/systemd1";
const MANAGER_IFACE: &str = "org.freedesktop.systemd1.Manager";

/// Sentinel value for unsetting a `uint64` cgroup property over D-Bus.
/// `UINT64_MAX` is systemd's "unset" marker for CPUWeight and
/// `CPUQuotaPerSecUSec` (the numeric counterpart of `CPUQuota=`).
pub const UINT64_UNSET: u64 = u64::MAX;

#[derive(Clone)]
pub struct SystemdBackend {
    conn: Arc<Connection>,
}

impl SystemdBackend {
    /// Use an existing session-bus connection. In the daemon, this is the
    /// same connection the D-Bus-discovery and `NameOwnerChanged` listener
    /// share — zbus connections are multiplex-safe.
    pub fn from_session(conn: Connection) -> Self {
        Self {
            conn: Arc::new(conn),
        }
    }

    /// Resolve the user systemd manager and cache the connection. Callers
    /// that already have a session connection should prefer
    /// [`Self::from_session`].
    pub async fn connect_user_session() -> zbus::Result<Self> {
        let conn = Connection::session().await?;
        Ok(Self::from_session(conn))
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Raw `SetUnitProperties` call. Every higher-level method on this
    /// struct is a thin wrapper around this.
    pub async fn set_unit_properties(
        &self,
        unit_name: &str,
        properties: &[(&str, Value<'_>)],
    ) -> zbus::Result<()> {
        // Validate the name is in the shape systemd will accept before
        // issuing the call. This catches our own mistakes early rather
        // than relying on a cryptic D-Bus error.
        if !looks_like_unit_name(unit_name) {
            return Err(zbus::Error::Unsupported);
        }
        let dest: BusName<'_> = SYSTEMD_BUS
            .try_into()
            .expect("constant systemd1 bus name is valid");
        let body = (unit_name, true, properties);
        self.conn
            .call_method(
                Some(dest),
                SYSTEMD_PATH,
                Some(MANAGER_IFACE),
                "SetUnitProperties",
                &body,
            )
            .await
            .with_context(|| {
                format!(
                    "SetUnitProperties(name={unit_name:?}, runtime=true, {} props)",
                    properties.len()
                )
            })
            .map_err(|e| zbus::Error::FDO(Box::new(zbus::fdo::Error::Failed(e.to_string()))))?;
        Ok(())
    }

    pub async fn set_cpu_weight(&self, unit_name: &str, weight: u64) -> zbus::Result<()> {
        self.set_unit_properties(unit_name, &[("CPUWeight", Value::U64(weight))])
            .await
    }

    /// Set the CPU quota in microseconds per second. `500_000` = 50%.
    pub async fn set_cpu_quota_per_sec_usec(
        &self,
        unit_name: &str,
        usec_per_sec: u64,
    ) -> zbus::Result<()> {
        self.set_unit_properties(
            unit_name,
            &[("CPUQuotaPerSecUSec", Value::U64(usec_per_sec))],
        )
        .await
    }

    pub async fn clear_cpu_weight(&self, unit_name: &str) -> zbus::Result<()> {
        self.set_unit_properties(unit_name, &[("CPUWeight", Value::U64(UINT64_UNSET))])
            .await
    }

    pub async fn clear_cpu_quota(&self, unit_name: &str) -> zbus::Result<()> {
        self.set_unit_properties(
            unit_name,
            &[("CPUQuotaPerSecUSec", Value::U64(UINT64_UNSET))],
        )
        .await
    }
}

/// Loose syntactic check on the unit name we're about to ship to systemd.
/// We're not the name validator of record — systemd is — but a quick
/// sanity check catches our own bugs (eg. accidentally passing a full
/// cgroup path instead of a basename).
pub fn looks_like_unit_name(name: &str) -> bool {
    if name.is_empty() || name.contains('/') {
        return false;
    }
    const VALID_SUFFIXES: [&str; 7] = [
        ".scope", ".service", ".slice", ".mount", ".socket", ".timer", ".target",
    ];
    VALID_SUFFIXES.iter().any(|s| name.ends_with(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_well_formed_unit_names() {
        assert!(looks_like_unit_name("app-firefox@abc.scope"));
        assert!(looks_like_unit_name("pipewire.service"));
        assert!(looks_like_unit_name("user.slice"));
    }

    #[test]
    fn rejects_paths_and_empty() {
        assert!(!looks_like_unit_name(""));
        assert!(!looks_like_unit_name("/sys/fs/cgroup/user.slice"));
        assert!(!looks_like_unit_name("no-suffix"));
    }

    #[test]
    fn uint64_unset_is_sentinel() {
        // Explicit value check — guards against a refactor silently
        // switching to 0, which systemd interprets very differently.
        assert_eq!(UINT64_UNSET, u64::MAX);
    }
}
