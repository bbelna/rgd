use std::path::PathBuf;

use crate::cgroup::pressure::Snapshot;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribution {
    pub path: PathBuf,
    pub some_delta_usec: u64,
    pub full_delta_usec: u64,
    pub some_total_usec: u64,
}

/// Rank cgroups by how much their `some_total_usec` grew between two
/// snapshots. Cgroups absent from `previous` (fresh since last fire) or with a
/// zero delta are dropped. Returns the top `n` offenders, highest delta first.
///
/// The two snapshots are expected to be for the same resource — in debug
/// builds this is asserted.
pub fn rank(previous: &Snapshot, current: &Snapshot, top_n: usize) -> Vec<Attribution> {
    debug_assert_eq!(
        previous.resource, current.resource,
        "rank() called with mismatched snapshot resources",
    );

    let mut results: Vec<Attribution> = current
        .cgroups
        .iter()
        .filter_map(|(path, cur)| {
            let prev = previous.cgroups.get(path)?;
            let some_delta = cur.some_total_usec.saturating_sub(prev.some_total_usec);
            if some_delta == 0 {
                return None;
            }
            let full_delta = cur.full_total_usec.saturating_sub(prev.full_total_usec);
            Some(Attribution {
                path: path.clone(),
                some_delta_usec: some_delta,
                full_delta_usec: full_delta,
                some_total_usec: cur.some_total_usec,
            })
        })
        .collect();
    results.sort_by(|a, b| {
        b.some_delta_usec
            .cmp(&a.some_delta_usec)
            .then_with(|| a.path.cmp(&b.path))
    });
    results.truncate(top_n);
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cgroup::pressure::{CgroupPressure, Snapshot};
    use crate::psi::Resource;
    use std::collections::HashMap;

    fn snap(pairs: &[(&str, u64, u64)]) -> Snapshot {
        let mut cgroups = HashMap::new();
        for (path, some, full) in pairs {
            cgroups.insert(
                PathBuf::from(path),
                CgroupPressure {
                    some_total_usec: *some,
                    full_total_usec: *full,
                },
            );
        }
        Snapshot {
            resource: Resource::Cpu,
            cgroups,
        }
    }

    #[test]
    fn ranks_by_some_delta_descending() {
        let prev = snap(&[("/a", 100, 0), ("/b", 200, 0), ("/c", 50, 0)]);
        let cur = snap(&[("/a", 150, 5), ("/b", 700, 30), ("/c", 60, 0)]);

        let top = rank(&prev, &cur, 5);
        assert_eq!(top.len(), 3);
        assert_eq!(top[0].path, PathBuf::from("/b"));
        assert_eq!(top[0].some_delta_usec, 500);
        assert_eq!(top[0].full_delta_usec, 30);
        assert_eq!(top[1].path, PathBuf::from("/a"));
        assert_eq!(top[1].some_delta_usec, 50);
        assert_eq!(top[2].path, PathBuf::from("/c"));
        assert_eq!(top[2].some_delta_usec, 10);
    }

    #[test]
    fn truncates_to_top_n() {
        let prev = snap(&[("/a", 0, 0), ("/b", 0, 0), ("/c", 0, 0)]);
        let cur = snap(&[("/a", 10, 0), ("/b", 30, 0), ("/c", 20, 0)]);
        let top = rank(&prev, &cur, 2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].path, PathBuf::from("/b"));
        assert_eq!(top[1].path, PathBuf::from("/c"));
    }

    #[test]
    fn drops_zero_delta_entries() {
        let prev = snap(&[("/a", 100, 0), ("/b", 200, 0)]);
        let cur = snap(&[("/a", 100, 5), ("/b", 250, 0)]);
        let top = rank(&prev, &cur, 5);
        // `/a` had full_delta but zero some_delta — it is dropped.
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].path, PathBuf::from("/b"));
    }

    #[test]
    fn drops_cgroups_absent_from_previous() {
        // A cgroup that appeared since the last snapshot can't be blamed for
        // the delta — we have no baseline.
        let prev = snap(&[("/a", 0, 0)]);
        let cur = snap(&[("/a", 10, 0), ("/fresh", 1_000_000, 0)]);
        let top = rank(&prev, &cur, 5);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].path, PathBuf::from("/a"));
    }

    #[test]
    fn saturates_on_counter_regression() {
        // cgroup counters are monotonic, but if the kernel ever reported a
        // regression we'd rather treat it as zero than panic on underflow.
        let prev = snap(&[("/a", 100, 50)]);
        let cur = snap(&[("/a", 90, 40)]);
        let top = rank(&prev, &cur, 5);
        assert!(top.is_empty());
    }

    #[test]
    fn deterministic_tie_break_on_equal_delta() {
        let prev = snap(&[("/a", 0, 0), ("/b", 0, 0)]);
        let cur = snap(&[("/a", 100, 0), ("/b", 100, 0)]);
        let top = rank(&prev, &cur, 5);
        assert_eq!(top[0].path, PathBuf::from("/a"));
        assert_eq!(top[1].path, PathBuf::from("/b"));
    }

    #[test]
    #[should_panic]
    #[cfg(debug_assertions)]
    fn mismatched_resources_panic_in_debug() {
        let mut prev = snap(&[]);
        let cur = snap(&[]);
        prev.resource = Resource::Cpu;
        let mut cur_memory = cur;
        cur_memory.resource = Resource::Memory;
        let _ = rank(&prev, &cur_memory, 1);
    }
}
