//! Persistent per-cgroup state via user-namespace xattrs.
//!
//! The cgroup directory itself is the source of truth: when the cgroup dies
//! (scope exits), the xattrs die with it. This defeats PID reuse bugs and
//! stale state files. `/run/rgd/state.json` is only a startup-reconciliation
//! cache; the xattrs are authoritative.
//!
//! We only use the `user.*` namespace, which ordinary users can read/write
//! on cgroups they own. `trusted.*` requires `CAP_SYS_ADMIN` and isn't
//! needed for v1.
//!
//! Keys:
//! * `user.rgd.level` — current enforcement level, as the string returned by
//!   [`Level::as_str`]. Present iff we've ever enforced on this cgroup.
//! * `user.rgd.applied_at` — unix timestamp (decimal ASCII) of the most
//!   recent level change.
//! * `user.rgd.preference` — `batch` | `intentional` | `omit`. Operator
//!   hint; writable via `setfattr`.
//! * `user.rgd.allow_kill` — `1` to gate `Level::Kill` on this cgroup.
//!   Second opt-in beyond the global enable.

use std::io;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::policy::ladder::Level;

pub const LEVEL_KEY: &str = "user.rgd.level";
pub const APPLIED_AT_KEY: &str = "user.rgd.applied_at";
pub const PREFERENCE_KEY: &str = "user.rgd.preference";
pub const ALLOW_KILL_KEY: &str = "user.rgd.allow_kill";

/// Every xattr key `rgd` manages. Exhaustive — `rgctl panic` iterates this
/// to strip state from every touched cgroup.
pub const ALL_KEYS: &[&str] = &[LEVEL_KEY, APPLIED_AT_KEY, PREFERENCE_KEY, ALLOW_KILL_KEY];

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Preference {
    /// Low priority; escalate aggressively under pressure.
    Batch,
    /// User-intentional workload; never escalate past [`Level::Weight`].
    Intentional,
    /// Never touch this cgroup for any reason.
    Omit,
}

impl Preference {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Batch => "batch",
            Self::Intentional => "intentional",
            Self::Omit => "omit",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "batch" => Some(Self::Batch),
            "intentional" => Some(Self::Intentional),
            "omit" => Some(Self::Omit),
            _ => None,
        }
    }
}

fn parse_level(s: &str) -> Option<Level> {
    match s.trim() {
        "Observe" => Some(Level::Observe),
        "Weight" => Some(Level::Weight),
        "Idle" => Some(Level::Idle),
        "Quota50" => Some(Level::Quota50),
        "Quota25" => Some(Level::Quota25),
        "Freeze" => Some(Level::Freeze),
        "Kill" => Some(Level::Kill),
        _ => None,
    }
}

/// Read a string xattr, treating `ENODATA` (key absent) as `None` and all
/// other errors as errors. On non-UTF-8 payloads we also return `None` —
/// a malformed value is operationally indistinguishable from an absent one.
pub fn read_string(path: &Path, key: &str) -> io::Result<Option<String>> {
    match xattr::get(path, key) {
        Ok(Some(bytes)) => match String::from_utf8(bytes) {
            Ok(s) => Ok(Some(s)),
            Err(_) => Ok(None),
        },
        Ok(None) => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn write_string(path: &Path, key: &str, value: &str) -> io::Result<()> {
    xattr::set(path, key, value.as_bytes())
}

/// Remove a single xattr. `ENODATA` (key not set) is reported as `Ok(())`;
/// strips are idempotent by design.
pub fn remove(path: &Path, key: &str) -> io::Result<()> {
    match xattr::remove(path, key) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc_enodata()) => Ok(()),
        Err(e) => Err(e),
    }
}

fn libc_enodata() -> i32 {
    // ENODATA is 61 on Linux; we hard-code to avoid pulling a libc crate.
    61
}

/// Strip every `user.rgd.*` xattr we might have written. Used by
/// de-escalation to Observe and by `rgctl panic`. Missing keys are not an
/// error. Returns the number of keys actually removed.
pub fn clear_all(path: &Path) -> io::Result<usize> {
    let mut removed = 0;
    for key in ALL_KEYS {
        match xattr::remove(path, key) {
            Ok(()) => removed += 1,
            Err(e) if e.raw_os_error() == Some(libc_enodata()) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(removed)
}

pub fn read_level(path: &Path) -> io::Result<Option<Level>> {
    Ok(read_string(path, LEVEL_KEY)?.and_then(|s| parse_level(&s)))
}

pub fn write_level(path: &Path, level: Level) -> io::Result<()> {
    write_string(path, LEVEL_KEY, level.as_str())
}

/// Stamp `user.rgd.applied_at` with `now` (unix seconds, decimal ASCII).
pub fn stamp_applied_at(path: &Path, now: SystemTime) -> io::Result<()> {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    write_string(path, APPLIED_AT_KEY, &secs.to_string())
}

pub fn read_applied_at(path: &Path) -> io::Result<Option<SystemTime>> {
    let Some(s) = read_string(path, APPLIED_AT_KEY)? else {
        return Ok(None);
    };
    let Ok(secs) = s.trim().parse::<u64>() else {
        return Ok(None);
    };
    Ok(Some(UNIX_EPOCH + Duration::from_secs(secs)))
}

pub fn read_preference(path: &Path) -> io::Result<Option<Preference>> {
    Ok(read_string(path, PREFERENCE_KEY)?.and_then(|s| Preference::parse(&s)))
}

/// `user.rgd.allow_kill` is a presence-plus-value flag. Any non-empty value
/// other than explicit zeros counts as allowed — operators tend to
/// `setfattr -n user.rgd.allow_kill -v 1`, but a bare presence check alone
/// would accept `0`/`false`/empty which is surprising.
pub fn read_allow_kill(path: &Path) -> io::Result<bool> {
    let Some(s) = read_string(path, ALLOW_KILL_KEY)? else {
        return Ok(false);
    };
    let trimmed = s.trim();
    Ok(!matches!(
        trimmed,
        "" | "0" | "false" | "no" | "off"
    ))
}

/// Best-effort: if xattrs aren't supported on the underlying filesystem
/// (`EOPNOTSUPP` / `ENOTSUP`), the caller typically wants to log and move
/// on rather than fail hard. This helper unifies the detection.
pub fn is_unsupported(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(95) /* EOPNOTSUPP */ | Some(38) /* ENOSYS */
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cgroup::tests_util::TempDir;

    fn xattrs_work_here(path: &Path) -> bool {
        // Some CI filesystems (tmpfs on older kernels, overlayfs corners)
        // reject user.* xattrs. Detect by doing a probe write we can clean up.
        match xattr::set(path, "user.rgd.__probe", b"1") {
            Ok(()) => {
                let _ = xattr::remove(path, "user.rgd.__probe");
                true
            }
            Err(e) => !is_unsupported(&e),
        }
    }

    #[test]
    fn preference_parses_known_values() {
        assert_eq!(Preference::parse("batch"), Some(Preference::Batch));
        assert_eq!(
            Preference::parse("intentional"),
            Some(Preference::Intentional)
        );
        assert_eq!(Preference::parse("omit"), Some(Preference::Omit));
        assert_eq!(Preference::parse("   omit  "), Some(Preference::Omit));
        assert_eq!(Preference::parse("bogus"), None);
    }

    #[test]
    fn level_roundtrips_through_string_form() {
        for level in [
            Level::Observe,
            Level::Weight,
            Level::Idle,
            Level::Quota50,
            Level::Quota25,
            Level::Freeze,
            Level::Kill,
        ] {
            assert_eq!(parse_level(level.as_str()), Some(level));
        }
    }

    #[test]
    fn read_write_roundtrip() {
        let dir = TempDir::new("xattr-roundtrip");
        if !xattrs_work_here(dir.path()) {
            return;
        }

        write_level(dir.path(), Level::Quota50).unwrap();
        assert_eq!(read_level(dir.path()).unwrap(), Some(Level::Quota50));

        stamp_applied_at(dir.path(), UNIX_EPOCH + Duration::from_secs(1_700_000_000))
            .unwrap();
        assert_eq!(
            read_applied_at(dir.path()).unwrap(),
            Some(UNIX_EPOCH + Duration::from_secs(1_700_000_000))
        );

        write_string(dir.path(), PREFERENCE_KEY, "intentional").unwrap();
        assert_eq!(
            read_preference(dir.path()).unwrap(),
            Some(Preference::Intentional)
        );

        write_string(dir.path(), ALLOW_KILL_KEY, "1").unwrap();
        assert!(read_allow_kill(dir.path()).unwrap());
        write_string(dir.path(), ALLOW_KILL_KEY, "0").unwrap();
        assert!(!read_allow_kill(dir.path()).unwrap());
    }

    #[test]
    fn clear_all_is_idempotent() {
        let dir = TempDir::new("xattr-clear");
        if !xattrs_work_here(dir.path()) {
            return;
        }
        write_level(dir.path(), Level::Weight).unwrap();
        write_string(dir.path(), ALLOW_KILL_KEY, "1").unwrap();
        let first = clear_all(dir.path()).unwrap();
        assert!(first >= 2);
        // Second call finds nothing; must not error.
        assert_eq!(clear_all(dir.path()).unwrap(), 0);
        assert_eq!(read_level(dir.path()).unwrap(), None);
    }

    #[test]
    fn remove_missing_key_is_ok() {
        let dir = TempDir::new("xattr-remove-missing");
        if !xattrs_work_here(dir.path()) {
            return;
        }
        assert!(remove(dir.path(), LEVEL_KEY).is_ok());
    }

    #[test]
    fn missing_values_read_as_none() {
        let dir = TempDir::new("xattr-missing");
        if !xattrs_work_here(dir.path()) {
            return;
        }
        assert_eq!(read_level(dir.path()).unwrap(), None);
        assert_eq!(read_applied_at(dir.path()).unwrap(), None);
        assert_eq!(read_preference(dir.path()).unwrap(), None);
        assert!(!read_allow_kill(dir.path()).unwrap());
    }

    #[test]
    fn malformed_values_read_as_none() {
        let dir = TempDir::new("xattr-malformed");
        if !xattrs_work_here(dir.path()) {
            return;
        }
        write_string(dir.path(), LEVEL_KEY, "NotALevel").unwrap();
        assert_eq!(read_level(dir.path()).unwrap(), None);

        write_string(dir.path(), APPLIED_AT_KEY, "not-a-number").unwrap();
        assert_eq!(read_applied_at(dir.path()).unwrap(), None);
    }
}
