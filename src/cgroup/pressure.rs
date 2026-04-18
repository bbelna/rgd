use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::cgroup::tree::{self, CgroupNode};
use crate::psi::{self, Resource};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CgroupPressure {
    pub some_total_usec: u64,
    pub full_total_usec: u64,
}

/// Pressure snapshot across every cgroup that exposes the resource's pressure
/// file. Cgroups missing or unreadable pressure files are skipped (debug-logged)
/// rather than failing the whole snapshot — one stubborn cgroup shouldn't blind
/// us to the other 200.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub resource: Resource,
    pub cgroups: HashMap<PathBuf, CgroupPressure>,
}

impl Snapshot {
    pub fn len(&self) -> usize {
        self.cgroups.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cgroups.is_empty()
    }
}

pub fn read_one(cgroup_path: &Path, resource: Resource) -> Result<CgroupPressure> {
    let file = cgroup_path.join(tree::pressure_file(resource));
    let contents = std::fs::read_to_string(&file)
        .with_context(|| format!("reading {}", file.display()))?;
    let parsed = psi::parse(&contents)
        .with_context(|| format!("parsing {}", file.display()))?;
    Ok(CgroupPressure {
        some_total_usec: parsed.some_total_usec,
        full_total_usec: parsed.full_total_usec,
    })
}

pub fn snapshot(resource: Resource) -> Result<Snapshot> {
    let nodes = tree::walk(resource)?;
    Ok(snapshot_from_nodes(&nodes, resource))
}

pub fn snapshot_from_nodes(nodes: &[CgroupNode], resource: Resource) -> Snapshot {
    let mut cgroups = HashMap::with_capacity(nodes.len());
    for node in nodes.iter().filter(|n| n.has_pressure) {
        match read_one(&node.path, resource) {
            Ok(cp) => {
                cgroups.insert(node.path.clone(), cp);
            }
            Err(e) => tracing::debug!(
                path = %node.path.display(),
                error = %e,
                "skipping unreadable cgroup pressure",
            ),
        }
    }
    Snapshot { resource, cgroups }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cgroup::tests_util::TempDir;
    use std::fs;

    const SAMPLE: &str = "\
some avg10=0.00 avg60=0.00 avg300=0.00 total=1234
full avg10=0.00 avg60=0.00 avg300=0.00 total=56
";

    #[test]
    fn read_one_parses_totals() {
        let dir = TempDir::new("read_one");
        fs::write(dir.path().join("cpu.pressure"), SAMPLE).unwrap();
        let cp = read_one(dir.path(), Resource::Cpu).unwrap();
        assert_eq!(cp.some_total_usec, 1234);
        assert_eq!(cp.full_total_usec, 56);
    }

    #[test]
    fn snapshot_from_nodes_skips_missing_files() {
        let dir = TempDir::new("snapshot");
        let good = dir.path().join("good");
        let bad = dir.path().join("bad");
        fs::create_dir_all(&good).unwrap();
        fs::create_dir_all(&bad).unwrap();
        fs::write(good.join("cpu.pressure"), SAMPLE).unwrap();
        // `bad/cpu.pressure` deliberately missing.

        let nodes = vec![
            CgroupNode {
                path: good.clone(),
                depth: 1,
                has_pressure: true,
            },
            CgroupNode {
                path: bad,
                depth: 1,
                has_pressure: false, // filtered out before read
            },
        ];
        let snap = snapshot_from_nodes(&nodes, Resource::Cpu);
        assert_eq!(snap.len(), 1);
        assert!(snap.cgroups.contains_key(&good));
    }

    /// Live probe against the host's real cgroup v2 tree. `#[ignore]` so
    /// `cargo test` stays pure; run explicitly via
    /// `cargo test -- --ignored cgroup_real_host`.
    #[test]
    #[ignore = "reads the real /sys/fs/cgroup — opt in via --ignored"]
    fn cgroup_real_host_snapshot_is_nonempty() {
        let snap = snapshot(Resource::Cpu).expect("snapshot real host cgroup tree");
        assert!(
            snap.len() > 1,
            "expected more than one cgroup with cpu.pressure, got {}",
            snap.len()
        );
    }

    #[test]
    fn snapshot_from_nodes_logs_and_skips_unreadable() {
        let dir = TempDir::new("snapshot-unreadable");
        let bogus = dir.path().join("bogus");
        fs::create_dir_all(&bogus).unwrap();
        // has_pressure=true but no file actually on disk — read_one will fail.
        let nodes = vec![CgroupNode {
            path: bogus,
            depth: 1,
            has_pressure: true,
        }];
        let snap = snapshot_from_nodes(&nodes, Resource::Cpu);
        assert_eq!(snap.len(), 0);
    }
}
