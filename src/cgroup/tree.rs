use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::psi::Resource;

pub const CGROUP_ROOT: &str = "/sys/fs/cgroup";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupNode {
    pub path: PathBuf,
    pub depth: usize,
    pub has_pressure: bool,
}

/// Basename of the per-cgroup pressure file for a given resource.
pub fn pressure_file(resource: Resource) -> &'static str {
    match resource {
        Resource::Cpu => "cpu.pressure",
        Resource::Memory => "memory.pressure",
        Resource::Io => "io.pressure",
    }
}

/// Walk the system cgroup v2 tree at `/sys/fs/cgroup`, returning every
/// directory along with whether it exposes the named resource's pressure file.
///
/// Unreadable subtrees (EACCES etc.) are skipped silently and logged at
/// debug level — the daemon must not die because one corner of the cgroup
/// tree isn't ours to inspect.
pub fn walk(resource: Resource) -> Result<Vec<CgroupNode>> {
    walk_from(Path::new(CGROUP_ROOT), resource)
}

pub fn walk_from(root: &Path, resource: Resource) -> Result<Vec<CgroupNode>> {
    let pressure_basename = pressure_file(resource);
    let mut nodes = Vec::new();
    let walker = WalkDir::new(root).follow_links(false).same_file_system(true);
    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!(error = %e, "skipping unreadable cgroup path");
                continue;
            }
        };
        if !entry.file_type().is_dir() {
            continue;
        }
        let path = entry.into_path();
        let has_pressure = path.join(pressure_basename).is_file();
        let depth = path
            .strip_prefix(root)
            .ok()
            .map(|p| p.components().count())
            .unwrap_or(0);
        nodes.push(CgroupNode {
            path,
            depth,
            has_pressure,
        });
    }
    if nodes.is_empty() {
        return Err(anyhow::anyhow!(
            "cgroup walk returned no directories under {}",
            root.display()
        ))
        .context("cgroup v2 tree not found — is this a cgroup v2 system?");
    }
    Ok(nodes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cgroup::tests_util::TempDir;
    use std::fs;

    #[test]
    fn resource_to_pressure_basename() {
        assert_eq!(pressure_file(Resource::Cpu), "cpu.pressure");
        assert_eq!(pressure_file(Resource::Memory), "memory.pressure");
        assert_eq!(pressure_file(Resource::Io), "io.pressure");
    }

    #[test]
    fn walks_dirs_and_detects_pressure_files() {
        let dir = TempDir::new("walk");
        let a = dir.path().join("a");
        let ab = a.join("b");
        let c = dir.path().join("c");
        fs::create_dir_all(&ab).unwrap();
        fs::create_dir_all(&c).unwrap();
        fs::write(dir.path().join("cpu.pressure"), "").unwrap();
        fs::write(a.join("cpu.pressure"), "").unwrap();
        // ab has no cpu.pressure; c has only memory.pressure.
        fs::write(c.join("memory.pressure"), "").unwrap();

        let nodes = walk_from(dir.path(), Resource::Cpu).unwrap();

        // Expect 4 dirs: root, a, a/b, c
        assert_eq!(nodes.len(), 4);
        let by_path: std::collections::HashMap<_, _> =
            nodes.iter().map(|n| (n.path.clone(), n)).collect();
        assert!(by_path[&dir.path().to_path_buf()].has_pressure);
        assert!(by_path[&a].has_pressure);
        assert!(!by_path[&ab].has_pressure);
        assert!(!by_path[&c].has_pressure); // because we asked for cpu
    }

    #[test]
    fn depth_increases_with_nesting() {
        let dir = TempDir::new("depth");
        fs::create_dir_all(dir.path().join("a/b/c")).unwrap();

        let nodes = walk_from(dir.path(), Resource::Cpu).unwrap();
        let by_path: std::collections::HashMap<_, _> =
            nodes.iter().map(|n| (n.path.clone(), n)).collect();
        assert_eq!(by_path[&dir.path().to_path_buf()].depth, 0);
        assert_eq!(by_path[&dir.path().join("a")].depth, 1);
        assert_eq!(by_path[&dir.path().join("a/b")].depth, 2);
        assert_eq!(by_path[&dir.path().join("a/b/c")].depth, 3);
    }

    #[test]
    fn empty_tree_is_an_error() {
        // A non-existent root should yield an error rather than silently
        // returning an empty list.
        let err = walk_from(Path::new("/definitely/not/a/real/path"), Resource::Cpu);
        assert!(err.is_err());
    }
}
