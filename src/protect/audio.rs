use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::cgroup::tree::CGROUP_ROOT;

pub const AUDIO_UNITS: &[&str] = &[
    "pipewire.service",
    "pipewire-pulse.service",
    "wireplumber.service",
];

/// Walk the cgroup tree looking for user-audio services by exact basename.
/// Cheap enough at startup (and on NameOwnerChanged refresh) that we don't
/// cache — the walk bottoms out within a few dozen dirs under
/// `user@1000.service`.
pub fn discover_audio_stack() -> Vec<PathBuf> {
    discover_under(Path::new(CGROUP_ROOT))
}

fn discover_under(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let walker = WalkDir::new(root)
        .follow_links(false)
        .same_file_system(true)
        .max_depth(10);
    for entry in walker {
        let Ok(entry) = entry else { continue };
        if !entry.file_type().is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else { continue };
        if AUDIO_UNITS.contains(&name_str) {
            found.push(entry.into_path());
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cgroup::tests_util::TempDir;
    use std::fs;

    #[test]
    fn finds_services_by_exact_basename() {
        let dir = TempDir::new("audio");
        let root = dir.path();
        fs::create_dir_all(root.join("user.slice/user@1000.service/pipewire.service"))
            .unwrap();
        fs::create_dir_all(root.join("user.slice/user@1000.service/wireplumber.service"))
            .unwrap();
        fs::create_dir_all(root.join("user.slice/user@1000.service/unrelated.service"))
            .unwrap();
        let found = discover_under(root);
        assert_eq!(found.len(), 2);
        assert!(found
            .iter()
            .any(|p| p.ends_with("pipewire.service")));
        assert!(found
            .iter()
            .any(|p| p.ends_with("wireplumber.service")));
    }

    #[test]
    fn empty_tree_yields_no_hits() {
        let dir = TempDir::new("audio-empty");
        assert!(discover_under(dir.path()).is_empty());
    }

    #[test]
    fn known_units_list_is_exact_basenames() {
        for unit in AUDIO_UNITS {
            assert!(unit.ends_with(".service"));
            assert!(!unit.contains('/'));
        }
    }
}
