use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitRef {
    /// The cgroup basename — the systemd unit name. Stable across restarts
    /// for long-lived units; transient scopes include a random suffix.
    pub unit: String,
    /// Human-readable identifier for logs. Best-effort: for app-launched
    /// scopes, the desktop-file or launcher name; for simple units, the
    /// unit stem; for slices, whatever remains after stripping the suffix.
    pub display: String,
}

const UNIT_SUFFIXES: [&str; 7] = [
    ".scope", ".service", ".slice", ".mount", ".socket", ".timer", ".target",
];

/// Derive a `UnitRef` from a cgroup path (or any string-shaped unit name).
/// Never fails — falls back to the unchanged basename if nothing resolves.
pub fn from_path(path: &Path) -> UnitRef {
    let unit = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("<unknown>")
        .to_string();
    let display = derive_display(&unit);
    UnitRef { unit, display }
}

fn derive_display(unit: &str) -> String {
    let stem = strip_unit_suffix(unit);
    let without_app_prefix = stem.strip_prefix("app-").unwrap_or(stem);
    // `app-firefox@abc…def.service` → keep only what's before `@`.
    let before_instance = without_app_prefix
        .split('@')
        .next()
        .unwrap_or(without_app_prefix);
    // `org.chromium.Chromium-624074` → `org.chromium.Chromium`.
    let without_random_tail = strip_random_tail(before_instance);
    // `org.chromium.Chromium` → `Chromium` (reverse-DNS last component).
    let last_dotted = without_random_tail
        .rsplit('.')
        .next()
        .unwrap_or(without_random_tail);
    if last_dotted.is_empty() {
        unit.to_string()
    } else {
        last_dotted.to_string()
    }
}

fn strip_unit_suffix(unit: &str) -> &str {
    for suffix in UNIT_SUFFIXES {
        if let Some(stripped) = unit.strip_suffix(suffix) {
            return stripped;
        }
    }
    unit
}

/// Strip a trailing `-<token>` from `s` when `<token>` looks like a random
/// systemd-generated suffix (≥5 chars, all hex digits). Conservative on
/// purpose — we'd rather leave `rgd-validate2` alone than strip good
/// content.
fn strip_random_tail(s: &str) -> &str {
    let Some((head, tail)) = s.rsplit_once('-') else {
        return s;
    };
    if is_random_tail(tail) {
        head
    } else {
        s
    }
}

fn is_random_tail(s: &str) -> bool {
    s.len() >= 5 && s.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn display_of(s: &str) -> String {
        derive_display(s)
    }

    #[test]
    fn app_service_with_instance() {
        assert_eq!(
            display_of("app-firefox@16bef687a734495ea577cecd43f27ffc.service"),
            "firefox"
        );
        assert_eq!(
            display_of("app-code@84f3ecc2ed3d405badcd6176a0b29000.service"),
            "code"
        );
    }

    #[test]
    fn reverse_dns_scope_with_pid_tail() {
        assert_eq!(
            display_of("app-org.chromium.Chromium-624074.scope"),
            "Chromium"
        );
    }

    #[test]
    fn transient_scope_without_app_prefix() {
        // `rgd-validate2` is not random-hex — shouldn't be truncated.
        assert_eq!(display_of("rgd-validate2.scope"), "rgd-validate2");
    }

    #[test]
    fn simple_service_names() {
        assert_eq!(display_of("pipewire.service"), "pipewire");
        assert_eq!(display_of("plasma-kwin_wayland.service"), "plasma-kwin_wayland");
    }

    #[test]
    fn slice_units() {
        assert_eq!(display_of("user.slice"), "user");
        assert_eq!(display_of("user-1000.slice"), "user-1000");
        assert_eq!(display_of("app.slice"), "app");
        assert_eq!(display_of("init.scope"), "init");
    }

    #[test]
    fn user_at_service_strips_instance() {
        assert_eq!(display_of("user@1000.service"), "user");
    }

    #[test]
    fn random_tail_heuristic_thresholds() {
        assert!(is_random_tail("abcdef"));
        assert!(is_random_tail("12345"));
        assert!(!is_random_tail("abcd")); // 4 chars, below threshold
        assert!(!is_random_tail("validate2")); // contains non-hex
        assert!(!is_random_tail("wayland"));
    }

    #[test]
    fn from_path_with_cgroup_root_prefix() {
        let p = Path::new(
            "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/\
             app.slice/app-firefox@abcdef1234567890.service",
        );
        let u = from_path(p);
        assert_eq!(u.unit, "app-firefox@abcdef1234567890.service");
        assert_eq!(u.display, "firefox");
    }

    #[test]
    fn from_path_falls_back_to_unknown_on_empty_basename() {
        // Path with no components — Path::file_name returns None.
        let u = from_path(Path::new("/"));
        assert_eq!(u.unit, "<unknown>");
    }

    #[test]
    fn app_scope_with_dashed_desktop_id() {
        // Dashed desktop IDs without a random tail should keep the dashes.
        assert_eq!(
            display_of("app-com.visualstudio.code-1234567890abcdef.scope"),
            "code"
        );
    }
}
