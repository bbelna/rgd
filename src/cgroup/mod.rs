pub mod pressure;
pub mod tree;

pub use pressure::{read_one, snapshot, snapshot_from_nodes, CgroupPressure, Snapshot};
pub use tree::{pressure_file, walk, walk_from, CgroupNode, CGROUP_ROOT};

#[cfg(test)]
pub(crate) mod tests_util {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Minimal self-cleaning temp dir for unit tests — avoids pulling
    /// `tempfile` as a dev-dep. Uniqueness: pid + unix-nanos + per-test
    /// counter; sufficient within a single `cargo test` invocation.
    pub struct TempDir {
        path: PathBuf,
    }

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    impl TempDir {
        pub fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "rgd-test-{}-{}-{}-{}",
                std::process::id(),
                tag,
                nanos,
                n
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }

        pub fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
