use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::cgroup::pressure::Snapshot;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribution {
    pub path: PathBuf,
    /// `some_total_usec` delta minus the sum of the direct children's deltas.
    /// Saturates at zero — this cgroup's own contribution to the pressure.
    pub exclusive_delta_usec: u64,
    /// Raw `some_total_usec` delta — cumulative over the cgroup's entire
    /// subtree. Kept for context in logs and downstream consumers.
    pub some_delta_usec: u64,
    pub full_delta_usec: u64,
    pub some_total_usec: u64,
}

/// Rank cgroups by their *exclusive* share of a pressure delta.
///
/// cgroup v2 PSI is cumulative: `A.some_total` counts stalls in tasks inside
/// `A` *and* all of `A`'s descendants. Sorting by the raw cumulative delta
/// therefore always favors ancestors over the actual source cgroup. We
/// instead rank by `exclusive_delta = own_delta − Σ direct_children_deltas`
/// (saturating at zero), which attributes pressure to the narrowest cgroup
/// whose tasks are actually the source.
///
/// Cgroups absent from `previous` (fresh since last fire) are dropped: we
/// have no baseline to diff against, and attributing their full current
/// counter to this window would wildly over-attribute short-lived scopes.
///
/// Tie-break on equal exclusive deltas is lexicographic by path, for stable
/// output.
pub fn rank(previous: &Snapshot, current: &Snapshot, top_n: usize) -> Vec<Attribution> {
    debug_assert_eq!(
        previous.resource, current.resource,
        "rank() called with mismatched snapshot resources",
    );

    // Pass 1: cumulative deltas for cgroups seen in both snapshots, dropping
    // anything with zero some-delta before we go any further.
    struct Raw {
        some: u64,
        full: u64,
        some_total: u64,
    }
    let mut raw: HashMap<PathBuf, Raw> = HashMap::with_capacity(current.cgroups.len());
    for (path, cur) in &current.cgroups {
        let Some(prev) = previous.cgroups.get(path) else {
            continue;
        };
        let some = cur.some_total_usec.saturating_sub(prev.some_total_usec);
        if some == 0 {
            continue;
        }
        let full = cur.full_total_usec.saturating_sub(prev.full_total_usec);
        raw.insert(
            path.clone(),
            Raw {
                some,
                full,
                some_total: cur.some_total_usec,
            },
        );
    }

    // Pass 2: for each cgroup, sum its direct children's cumulative deltas —
    // but only counting children that are themselves in `raw`. A cgroup
    // missing from `raw` contributed zero, so leaving it out is correct.
    let mut children_sum: HashMap<PathBuf, u64> = HashMap::with_capacity(raw.len());
    for (path, r) in &raw {
        let Some(parent) = path.parent() else { continue };
        if !raw.contains_key(parent) {
            continue;
        }
        *children_sum.entry(parent.to_path_buf()).or_insert(0) += r.some;
    }

    // Pass 3: build attributions, keeping only cgroups with a positive
    // exclusive delta.
    let mut results: Vec<Attribution> = raw
        .into_iter()
        .filter_map(|(path, r)| {
            let children = children_sum.get(&path).copied().unwrap_or(0);
            let exclusive = r.some.saturating_sub(children);
            if exclusive == 0 {
                return None;
            }
            Some(Attribution {
                path,
                exclusive_delta_usec: exclusive,
                some_delta_usec: r.some,
                full_delta_usec: r.full,
                some_total_usec: r.some_total,
            })
        })
        .collect();

    results.sort_by(|a, b| {
        b.exclusive_delta_usec
            .cmp(&a.exclusive_delta_usec)
            .then_with(|| a.path.cmp(&b.path))
    });
    results.truncate(top_n);
    results
}

/// Cosmetic helper: returns `true` iff `maybe_child` is a direct child of
/// `maybe_parent` in the cgroup path tree. Exposed for tests and for
/// downstream consumers that may want tree-aware formatting.
pub fn is_direct_child(maybe_parent: &Path, maybe_child: &Path) -> bool {
    maybe_child.parent() == Some(maybe_parent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cgroup::pressure::{CgroupPressure, Snapshot};
    use crate::psi::Resource;

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
    fn ranks_flat_siblings_by_delta() {
        // No hierarchy — exclusive delta equals cumulative delta.
        let prev = snap(&[("/a", 100, 0), ("/b", 200, 0), ("/c", 50, 0)]);
        let cur = snap(&[("/a", 150, 5), ("/b", 700, 30), ("/c", 60, 0)]);
        let top = rank(&prev, &cur, 5);
        assert_eq!(top.len(), 3);
        assert_eq!(top[0].path, PathBuf::from("/b"));
        assert_eq!(top[0].exclusive_delta_usec, 500);
        assert_eq!(top[0].some_delta_usec, 500);
        assert_eq!(top[1].path, PathBuf::from("/a"));
        assert_eq!(top[1].exclusive_delta_usec, 50);
        assert_eq!(top[2].path, PathBuf::from("/c"));
        assert_eq!(top[2].exclusive_delta_usec, 10);
    }

    #[test]
    fn hierarchy_exclusive_delta_promotes_leaf() {
        // Linear chain with identical cumulative deltas — only the leaf has a
        // non-zero exclusive contribution. This is the bug session 1.2.1
        // fixes: previously every ancestor was tied with the leaf on raw
        // some_delta and sort order picked the wrong cgroup.
        let prev = snap(&[
            ("/root", 0, 0),
            ("/root/user.slice", 0, 0),
            ("/root/user.slice/app.slice", 0, 0),
            ("/root/user.slice/app.slice/stress.scope", 0, 0),
        ]);
        let cur = snap(&[
            ("/root", 500, 0),
            ("/root/user.slice", 500, 0),
            ("/root/user.slice/app.slice", 500, 0),
            ("/root/user.slice/app.slice/stress.scope", 500, 0),
        ]);
        let top = rank(&prev, &cur, 5);
        assert_eq!(top.len(), 1, "ancestors should have dropped out: {top:#?}");
        assert_eq!(
            top[0].path,
            PathBuf::from("/root/user.slice/app.slice/stress.scope")
        );
        assert_eq!(top[0].exclusive_delta_usec, 500);
        assert_eq!(top[0].some_delta_usec, 500);
    }

    #[test]
    fn parent_with_own_activity_ranks_above_its_quiet_siblings() {
        // Parent has 200us of pressure its tracked child only accounts for
        // 80us of — the parent keeps the remaining 120us as exclusive.
        let prev = snap(&[("/p", 0, 0), ("/p/c", 0, 0), ("/q", 0, 0)]);
        let cur = snap(&[("/p", 200, 0), ("/p/c", 80, 0), ("/q", 50, 0)]);
        let top = rank(&prev, &cur, 5);
        let by_path: HashMap<_, _> = top.iter().map(|a| (a.path.clone(), a)).collect();
        assert_eq!(by_path[&PathBuf::from("/p")].exclusive_delta_usec, 120);
        assert_eq!(by_path[&PathBuf::from("/p/c")].exclusive_delta_usec, 80);
        assert_eq!(by_path[&PathBuf::from("/q")].exclusive_delta_usec, 50);
        // Ordering: /p (120) > /p/c (80) > /q (50)
        assert_eq!(top[0].path, PathBuf::from("/p"));
        assert_eq!(top[1].path, PathBuf::from("/p/c"));
        assert_eq!(top[2].path, PathBuf::from("/q"));
    }

    #[test]
    fn non_additive_children_saturate_parent_to_zero() {
        // Two sibling children each stalled at the same time — their
        // individual deltas don't sum up in the parent (PSI is "some",
        // not a true sum). The parent's exclusive should clamp to 0, not
        // underflow into a giant u64.
        let prev = snap(&[
            ("/p", 0, 0),
            ("/p/a", 0, 0),
            ("/p/b", 0, 0),
        ]);
        let cur = snap(&[
            ("/p", 100, 0),
            ("/p/a", 90, 0),
            ("/p/b", 90, 0),
        ]);
        let top = rank(&prev, &cur, 5);
        // /p should have been dropped (exclusive = 100 − 180 saturated to 0).
        let p = top.iter().find(|a| a.path == Path::new("/p"));
        assert!(p.is_none(), "parent should drop out, got {p:?}");
        // Both children kept at their full delta.
        assert_eq!(top.len(), 2);
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
        // /a has full-delta but zero some-delta — dropped in pass 1.
        let prev = snap(&[("/a", 100, 0), ("/b", 200, 0)]);
        let cur = snap(&[("/a", 100, 5), ("/b", 250, 0)]);
        let top = rank(&prev, &cur, 5);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].path, PathBuf::from("/b"));
    }

    #[test]
    fn drops_cgroups_absent_from_previous() {
        let prev = snap(&[("/a", 0, 0)]);
        let cur = snap(&[("/a", 10, 0), ("/fresh", 1_000_000, 0)]);
        let top = rank(&prev, &cur, 5);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].path, PathBuf::from("/a"));
    }

    #[test]
    fn saturates_on_counter_regression() {
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

    #[test]
    fn is_direct_child_matches_adjacent_paths_only() {
        assert!(is_direct_child(
            Path::new("/a/b"),
            Path::new("/a/b/c")
        ));
        assert!(!is_direct_child(
            Path::new("/a"),
            Path::new("/a/b/c")
        ));
        assert!(!is_direct_child(Path::new("/a"), Path::new("/b")));
    }
}
