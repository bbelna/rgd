//! Enforcement backends.
//!
//! Two layers sit behind the [`Enforcer`] facade:
//!
//! * [`systemd`] — `SetUnitProperties(runtime=true, …)` for CPUWeight /
//!   CPUQuota. Reversible, survives daemon crash only until the next reboot
//!   (or explicit unset). This is the path for Levels 1–4.
//! * [`cgroupfs`] — direct writes to `cgroup.freeze` / `cgroup.kill`. Used
//!   only for Levels 5 (Freeze) and 6 (Kill), both opt-in.
//!
//! Before every state-changing call the [`Enforcer`] writes `user.rgd.level`
//! and `user.rgd.applied_at` xattrs. If the daemon crashes after the xattr
//! write but before the property write, the breadcrumb matches exactly one
//! level of over-promise and is caught by startup reconciliation or
//! `rgctl panic`. If the crash happens after the property write, xattr and
//! property agree and reconciliation is a no-op.

pub mod cgroupfs;
pub mod systemd;

use std::path::Path;
use std::time::SystemTime;

use anyhow::{anyhow, Context, Result};

use crate::cgroup::unit::UnitRef;
use crate::cgroup::xattr;
use crate::policy::ladder::Level;

pub use systemd::SystemdBackend;

/// Runtime gates for optional — and irreversible — enforcement paths.
/// Anything above [`Level::Quota25`] requires both a global enable flag and
/// (in the case of kill) a per-cgroup xattr opt-in.
#[derive(Debug, Clone, Copy, Default)]
pub struct EnforcementGates {
    pub enable_freeze: bool,
    pub enable_kill: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum EnforceError {
    #[error("refusing to touch protected cgroup {0}")]
    Protected(String),
    #[error("level {level:?} requires {reason}")]
    Gated { level: Level, reason: &'static str },
    #[error("xattr write failed: {0}")]
    Xattr(#[from] std::io::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// The facade wired into `main.rs`. Holds the systemd connection and the
/// gate flags; every call is driven by `Level` transitions coming out of
/// the policy state machine.
///
/// Cheap to clone — both backends share their underlying D-Bus connection.
#[derive(Clone)]
pub struct Enforcer {
    systemd: SystemdBackend,
    gates: EnforcementGates,
}

impl Enforcer {
    pub fn new(systemd: SystemdBackend, gates: EnforcementGates) -> Self {
        Self { systemd, gates }
    }

    pub fn gates(&self) -> EnforcementGates {
        self.gates
    }

    /// Apply `target` to `cgroup_path`. Writes xattrs first, then the
    /// backend-specific properties.
    ///
    /// `cgroup_path` must be an absolute path under `/sys/fs/cgroup`; the
    /// unit name is derived from the path basename.
    pub async fn apply(&self, cgroup_path: &Path, target: Level) -> Result<(), EnforceError> {
        refuse_if_forbidden(cgroup_path)?;

        if target == Level::Kill && !xattr::read_allow_kill(cgroup_path).unwrap_or(false) {
            return Err(EnforceError::Gated {
                level: target,
                reason: "user.rgd.allow_kill xattr missing",
            });
        }
        if target == Level::Freeze && !self.gates.enable_freeze {
            return Err(EnforceError::Gated {
                level: target,
                reason: "enable_freeze=false",
            });
        }
        if target == Level::Kill && !self.gates.enable_kill {
            return Err(EnforceError::Gated {
                level: target,
                reason: "enable_kill=false",
            });
        }

        // Write the breadcrumb before making the change. If xattrs aren't
        // supported here (eg. non-cgroup test path), log but proceed — the
        // safety net is `rgctl panic` which uses xattrs, so we only lose
        // recoverability, not correctness.
        if let Err(e) = xattr::write_level(cgroup_path, target) {
            if xattr::is_unsupported(&e) {
                tracing::debug!(
                    path = %cgroup_path.display(),
                    error = %e,
                    "xattrs unsupported on this cgroup; enforcing without breadcrumb",
                );
            } else {
                return Err(EnforceError::Xattr(e));
            }
        }
        let _ = xattr::stamp_applied_at(cgroup_path, SystemTime::now());

        let unit = UnitRef::from(cgroup_path);
        match target {
            Level::Observe => {
                // Observe is the "no-op" level — ensure we haven't left
                // any previous properties applied.
                self.revert_to_observe(cgroup_path, &unit).await?;
            }
            Level::Weight => {
                self.systemd
                    .set_cpu_weight(&unit.unit, 20)
                    .await
                    .with_context(|| format!("CPUWeight=20 on {}", unit.unit))?;
                self.systemd
                    .clear_cpu_quota(&unit.unit)
                    .await
                    .with_context(|| format!("clearing CPUQuota on {}", unit.unit))?;
            }
            Level::Idle => {
                // cpu.idle=1 is the kernel mechanism; CPUWeight=1 is the
                // pre-252 fallback. Do both — if cpu.idle is unsupported
                // (<5.15) we still get weight-1, and if systemd can't do
                // idle we still get cpu.idle via cgroupfs.
                self.systemd
                    .set_cpu_weight(&unit.unit, 1)
                    .await
                    .with_context(|| format!("CPUWeight=1 on {}", unit.unit))?;
                self.systemd
                    .clear_cpu_quota(&unit.unit)
                    .await
                    .with_context(|| format!("clearing CPUQuota on {}", unit.unit))?;
                if let Err(e) = cgroupfs::set_cpu_idle(cgroup_path, true) {
                    tracing::debug!(
                        path = %cgroup_path.display(),
                        error = %e,
                        "cpu.idle write failed; continuing with CPUWeight fallback",
                    );
                }
            }
            Level::Quota50 => {
                self.systemd
                    .set_cpu_weight(&unit.unit, 20)
                    .await
                    .with_context(|| format!("CPUWeight=20 on {}", unit.unit))?;
                self.systemd
                    .set_cpu_quota_per_sec_usec(&unit.unit, 500_000)
                    .await
                    .with_context(|| format!("CPUQuota=50% on {}", unit.unit))?;
            }
            Level::Quota25 => {
                self.systemd
                    .set_cpu_weight(&unit.unit, 20)
                    .await
                    .with_context(|| format!("CPUWeight=20 on {}", unit.unit))?;
                self.systemd
                    .set_cpu_quota_per_sec_usec(&unit.unit, 250_000)
                    .await
                    .with_context(|| format!("CPUQuota=25% on {}", unit.unit))?;
            }
            Level::Freeze => {
                cgroupfs::freeze(cgroup_path, true)
                    .with_context(|| format!("freezing {}", cgroup_path.display()))?;
            }
            Level::Kill => {
                cgroupfs::kill(cgroup_path)
                    .with_context(|| format!("killing {}", cgroup_path.display()))?;
            }
        }

        Ok(())
    }

    /// Unwind every property rgd might have applied and strip every
    /// `user.rgd.*` xattr. Used when a cgroup de-escalates all the way to
    /// Observe, and when the daemon is shutting down. Best-effort on each
    /// sub-step — we never leave a cgroup half-reverted just because one
    /// call failed.
    pub async fn revert_to_observe(
        &self,
        cgroup_path: &Path,
        unit: &UnitRef,
    ) -> Result<(), EnforceError> {
        let mut last_err: Option<anyhow::Error> = None;

        if let Err(e) = self.systemd.clear_cpu_weight(&unit.unit).await {
            last_err = Some(anyhow::Error::from(e).context("clearing CPUWeight"));
        }
        if let Err(e) = self.systemd.clear_cpu_quota(&unit.unit).await {
            last_err = Some(anyhow::Error::from(e).context("clearing CPUQuota"));
        }
        if let Err(e) = cgroupfs::set_cpu_idle(cgroup_path, false) {
            if !matches!(e.kind(), std::io::ErrorKind::NotFound) {
                tracing::debug!(
                    path = %cgroup_path.display(),
                    error = %e,
                    "clearing cpu.idle failed; likely already cleared",
                );
            }
        }
        // Unfreeze if we previously froze. Idempotent — writing "0" to an
        // already-thawed cgroup is a no-op.
        if let Err(e) = cgroupfs::freeze(cgroup_path, false) {
            if !matches!(e.kind(), std::io::ErrorKind::NotFound) {
                tracing::debug!(
                    path = %cgroup_path.display(),
                    error = %e,
                    "unfreeze failed; likely already thawed",
                );
            }
        }
        if let Err(e) = xattr::clear_all(cgroup_path) {
            if !xattr::is_unsupported(&e) {
                last_err = Some(anyhow::Error::from(e).context("clearing xattrs"));
            }
        }

        match last_err {
            Some(e) => Err(EnforceError::Other(e)),
            None => Ok(()),
        }
    }

    pub fn systemd(&self) -> &SystemdBackend {
        &self.systemd
    }
}

/// Safety rail. v1 hard-refuses to touch anything under `system.slice`,
/// `init.scope`, or the cgroup root. Kernel threads live in cgroups we
/// wouldn't have permission to edit anyway, but the check keeps a clean
/// conscience.
pub fn refuse_if_forbidden(path: &Path) -> Result<(), EnforceError> {
    let s = path.to_string_lossy();
    let forbidden_segments = ["/system.slice/", "/init.scope"];
    if s.ends_with("/sys/fs/cgroup") || s == "/sys/fs/cgroup" {
        return Err(EnforceError::Protected(s.into_owned()));
    }
    for bad in forbidden_segments {
        if s.contains(bad) || s.ends_with(bad.trim_end_matches('/')) {
            return Err(EnforceError::Protected(s.into_owned()));
        }
    }
    Ok(())
}

impl From<&Path> for UnitRef {
    fn from(path: &Path) -> UnitRef {
        crate::cgroup::unit::from_path(path)
    }
}

pub fn is_cgroup_path(p: &Path) -> bool {
    p.starts_with("/sys/fs/cgroup")
}

pub fn require_cgroup_path(p: &Path) -> Result<()> {
    if is_cgroup_path(p) {
        Ok(())
    } else {
        Err(anyhow!("expected a path under /sys/fs/cgroup, got {}", p.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn refuses_system_slice() {
        let err = refuse_if_forbidden(&PathBuf::from(
            "/sys/fs/cgroup/system.slice/crond.service",
        ));
        assert!(matches!(err, Err(EnforceError::Protected(_))));
    }

    #[test]
    fn refuses_init_scope() {
        let err = refuse_if_forbidden(&PathBuf::from("/sys/fs/cgroup/init.scope"));
        assert!(matches!(err, Err(EnforceError::Protected(_))));
    }

    #[test]
    fn refuses_cgroup_root() {
        let err = refuse_if_forbidden(&PathBuf::from("/sys/fs/cgroup"));
        assert!(matches!(err, Err(EnforceError::Protected(_))));
    }

    #[test]
    fn allows_user_scope() {
        assert!(refuse_if_forbidden(&PathBuf::from(
            "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox@abc.scope"
        ))
        .is_ok());
    }

    #[test]
    fn is_cgroup_path_rejects_foreign_paths() {
        assert!(is_cgroup_path(&PathBuf::from("/sys/fs/cgroup/user.slice")));
        assert!(!is_cgroup_path(&PathBuf::from("/tmp/not-a-cgroup")));
    }
}
