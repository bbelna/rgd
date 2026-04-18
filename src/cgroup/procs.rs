use anyhow::{Context, Result};
use std::path::Path;

/// Read the PIDs listed in `<cgroup>/cgroup.procs`. Unprivileged callers
/// can see every PID but may still hit EACCES on some cgroups outside
/// their slice; callers should be tolerant.
pub fn read_pids(cgroup_path: &Path) -> Result<Vec<u32>> {
    let file = cgroup_path.join("cgroup.procs");
    let contents = std::fs::read_to_string(&file)
        .with_context(|| format!("reading {}", file.display()))?;
    let mut pids = Vec::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let pid: u32 = trimmed
            .parse()
            .with_context(|| format!("parsing PID {trimmed:?} from {}", file.display()))?;
        pids.push(pid);
    }
    Ok(pids)
}

/// Count PIDs without allocating a `Vec` — suitable for the hot log path.
/// Still materialises the file contents, but O(file size) and no alloc per pid.
pub fn read_count(cgroup_path: &Path) -> Result<usize> {
    let file = cgroup_path.join("cgroup.procs");
    let contents = std::fs::read_to_string(&file)
        .with_context(|| format!("reading {}", file.display()))?;
    Ok(contents.lines().filter(|l| !l.trim().is_empty()).count())
}

/// Read `/proc/<pid>/comm` (the scheduler's short process name, ≤16 chars,
/// trailing newline stripped). Fails if the process has already exited, which
/// is a normal race condition under churn.
pub fn read_comm(pid: u32) -> Result<String> {
    let path = format!("/proc/{pid}/comm");
    let mut comm =
        std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    if comm.ends_with('\n') {
        comm.pop();
    }
    Ok(comm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cgroup::tests_util::TempDir;
    use std::fs;

    #[test]
    fn read_pids_parses_multiline() {
        let dir = TempDir::new("procs");
        fs::write(
            dir.path().join("cgroup.procs"),
            "100\n200\n\n300\n",
        )
        .unwrap();
        let pids = read_pids(dir.path()).unwrap();
        assert_eq!(pids, vec![100, 200, 300]);
    }

    #[test]
    fn read_count_ignores_blanks() {
        let dir = TempDir::new("procs-count");
        fs::write(
            dir.path().join("cgroup.procs"),
            "1\n2\n\n3\n4\n\n",
        )
        .unwrap();
        assert_eq!(read_count(dir.path()).unwrap(), 4);
    }

    #[test]
    fn read_count_empty_file() {
        let dir = TempDir::new("procs-empty");
        fs::write(dir.path().join("cgroup.procs"), "").unwrap();
        assert_eq!(read_count(dir.path()).unwrap(), 0);
    }

    #[test]
    fn read_count_missing_file_errors() {
        let dir = TempDir::new("procs-missing");
        assert!(read_count(dir.path()).is_err());
    }

    #[test]
    fn read_pids_rejects_garbage_line() {
        let dir = TempDir::new("procs-garbage");
        fs::write(dir.path().join("cgroup.procs"), "42\nnot-a-pid\n").unwrap();
        assert!(read_pids(dir.path()).is_err());
    }

    #[test]
    fn read_comm_for_current_process() {
        // The test binary's pid always has a readable /proc/<pid>/comm.
        let pid = std::process::id();
        let comm = read_comm(pid).unwrap();
        assert!(!comm.is_empty());
        assert!(!comm.contains('\n'));
    }
}
