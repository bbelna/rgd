//! Direct cgroup-v2 knob writes.
//!
//! Used for the two levels systemd doesn't expose as first-class properties:
//! `cgroup.freeze` (Level::Freeze) and `cgroup.kill` (Level::Kill), plus
//! the optional `cpu.idle=1` belt-and-suspenders write for Level::Idle.
//!
//! These knobs are single-ASCII-digit files. Writes are short, atomic, and
//! cheap. We intentionally do *not* hold file descriptors — every call
//! re-opens the file, writes, and closes.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

/// Open `path` write-only *without* `O_CREAT`. cgroupfs knob files always
/// pre-exist when the feature is supported; if the file is missing we
/// want `NotFound` rather than silently creating a plain file in a test
/// temp dir.
fn write_existing(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut f = OpenOptions::new().write(true).truncate(true).open(path)?;
    f.write_all(bytes)
}

/// Write `"1\n"` or `"0\n"` to `cgroup.freeze`. Freezing pauses every task
/// in the cgroup using the kernel's task-state machinery; thawing releases
/// them.
pub fn freeze(cgroup_path: &Path, freeze: bool) -> io::Result<()> {
    let file = cgroup_path.join("cgroup.freeze");
    let value = if freeze { b"1\n" } else { b"0\n" };
    write_existing(&file, value)
}

/// Write `"1\n"` to `cgroup.kill`. This sends `SIGKILL` to every task in
/// the cgroup (including descendants); there is no partial state. The
/// write fails with `EBUSY` if the kill is already in progress — we report
/// it as an error, the caller can decide.
///
/// Note: writing `"0"` is not a defined operation; once killed, the cgroup's
/// tasks are gone and `cgroup.kill` is a write-once trigger per incident.
pub fn kill(cgroup_path: &Path) -> io::Result<()> {
    let file = cgroup_path.join("cgroup.kill");
    write_existing(&file, b"1\n")
}

/// Write `cpu.idle`. Kernel 5.15+ only; older kernels don't have the file
/// and this returns `NotFound`, which the caller should treat as a soft
/// failure (the `CPUWeight=1` fallback is doing the work on those systems).
pub fn set_cpu_idle(cgroup_path: &Path, idle: bool) -> io::Result<()> {
    let file = cgroup_path.join("cpu.idle");
    let value = if idle { b"1\n" } else { b"0\n" };
    write_existing(&file, value)
}

/// Read `cgroup.freeze` — returns `true` iff the cgroup is currently
/// frozen. Missing file (old kernel) yields `Ok(false)`.
pub fn is_frozen(cgroup_path: &Path) -> io::Result<bool> {
    let file = cgroup_path.join("cgroup.freeze");
    match fs::read_to_string(&file) {
        Ok(s) => Ok(s.trim() == "1"),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cgroup::tests_util::TempDir;
    use std::fs;

    #[test]
    fn freeze_writes_expected_values() {
        let dir = TempDir::new("cgroupfs-freeze");
        fs::write(dir.path().join("cgroup.freeze"), "0\n").unwrap();
        freeze(dir.path(), true).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("cgroup.freeze")).unwrap(),
            "1\n"
        );
        freeze(dir.path(), false).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("cgroup.freeze")).unwrap(),
            "0\n"
        );
    }

    #[test]
    fn kill_writes_one() {
        let dir = TempDir::new("cgroupfs-kill");
        fs::write(dir.path().join("cgroup.kill"), "0\n").unwrap();
        kill(dir.path()).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("cgroup.kill")).unwrap(),
            "1\n"
        );
    }

    #[test]
    fn set_cpu_idle_writes_flag() {
        let dir = TempDir::new("cgroupfs-idle");
        fs::write(dir.path().join("cpu.idle"), "0\n").unwrap();
        set_cpu_idle(dir.path(), true).unwrap();
        assert_eq!(
            fs::read_to_string(dir.path().join("cpu.idle")).unwrap(),
            "1\n"
        );
    }

    #[test]
    fn set_cpu_idle_missing_file_yields_notfound() {
        let dir = TempDir::new("cgroupfs-idle-missing");
        let e = set_cpu_idle(dir.path(), true).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn is_frozen_reads_flag() {
        let dir = TempDir::new("cgroupfs-is-frozen");
        fs::write(dir.path().join("cgroup.freeze"), "1\n").unwrap();
        assert!(is_frozen(dir.path()).unwrap());
        fs::write(dir.path().join("cgroup.freeze"), "0\n").unwrap();
        assert!(!is_frozen(dir.path()).unwrap());
    }

    #[test]
    fn is_frozen_missing_file_is_false() {
        let dir = TempDir::new("cgroupfs-frozen-missing");
        assert!(!is_frozen(dir.path()).unwrap());
    }
}
