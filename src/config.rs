//! TOML-backed daemon configuration.
//!
//! Layering (highest wins):
//!   1. Explicit CLI flags.
//!   2. Values loaded from the file passed via `--config`, or the default
//!      search path (see [`Config::default_path`]).
//!   3. Compile-time defaults in [`Config::default`].
//!
//! Validation is strict: a missing file silently falls back to defaults
//! (so distros can ship a daemon with no `/etc/rgd/config.toml`), but a
//! *present* file that fails to parse or fails validation is a hard error.
//! Users asking for a property we can't safely deliver should see a
//! startup failure, not silent fallback.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::policy::ladder::LadderConfig;
use crate::psi::Resource;

/// Fully-validated, ready-to-use configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub triggers: Triggers,
    pub ladder: LadderConfig,
    pub enforcement: Enforcement,
    pub protect: Protect,
}

#[derive(Debug, Clone, Copy)]
pub struct Triggers {
    pub resource: Resource,
    pub threshold_ms: u64,
    pub window_ms: u64,
    pub top_n: usize,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Enforcement {
    pub enable_freeze: bool,
    pub enable_kill: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Protect {
    /// Extra D-Bus well-known names to resolve and add to the protect set,
    /// on top of the built-in compositor/portal/audio list.
    pub extra_names: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            triggers: Triggers {
                resource: Resource::Cpu,
                threshold_ms: 100,
                window_ms: 1000,
                top_n: 5,
            },
            ladder: LadderConfig::default(),
            enforcement: Enforcement::default(),
            protect: Protect::default(),
        }
    }
}

impl Config {
    /// Load-or-default. If `path` is `Some`, the file must exist and parse.
    /// If `path` is `None`, we look at the default path and fall back to
    /// built-in defaults on NotFound.
    pub fn load(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(p) => Self::load_file(p),
            None => match Self::default_path() {
                Some(p) if p.exists() => Self::load_file(&p),
                _ => Ok(Self::default()),
            },
        }
    }

    fn load_file(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("reading config from {}", path.display()))?;
        let raw: RawConfig = toml::from_str(&text)
            .with_context(|| format!("parsing TOML at {}", path.display()))?;
        raw.validate()
            .with_context(|| format!("validating config at {}", path.display()))
    }

    /// Default search path. Prefers `$XDG_CONFIG_HOME/rgd/config.toml`,
    /// falling back to `~/.config/rgd/config.toml`. Returns `None` if no
    /// home directory can be determined at all.
    pub fn default_path() -> Option<PathBuf> {
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            if !xdg.is_empty() {
                return Some(PathBuf::from(xdg).join("rgd").join("config.toml"));
            }
        }
        std::env::var("HOME")
            .ok()
            .filter(|h| !h.is_empty())
            .map(|h| {
                PathBuf::from(h)
                    .join(".config")
                    .join("rgd")
                    .join("config.toml")
            })
    }
}

/// Intermediate deserialization shape. All fields are optional so the file
/// can be sparse; missing entries fall through to [`Config::default`]. Only
/// [`RawConfig::validate`] produces the final typed `Config`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    triggers: RawTriggers,
    #[serde(default)]
    policy: RawPolicy,
    #[serde(default)]
    enforcement: RawEnforcement,
    #[serde(default)]
    protect: RawProtect,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTriggers {
    resource: Option<String>,
    threshold_ms: Option<u64>,
    window_ms: Option<u64>,
    top_n: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    escalate_observe_to_weight: Option<String>,
    escalate_weight_to_idle: Option<String>,
    escalate_idle_to_quota50: Option<String>,
    escalate_quota50_to_quota25: Option<String>,
    deescalate_after: Option<String>,
    untrack_after: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEnforcement {
    enable_freeze: Option<bool>,
    enable_kill: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProtect {
    #[serde(default)]
    extra_names: Vec<String>,
}

impl RawConfig {
    fn validate(self) -> Result<Config> {
        let defaults = Config::default();

        let resource = match self.triggers.resource.as_deref() {
            None => defaults.triggers.resource,
            Some("cpu") => Resource::Cpu,
            Some("memory") => Resource::Memory,
            Some("io") => Resource::Io,
            Some(other) => bail!(
                "triggers.resource = {other:?}; expected one of \"cpu\", \"memory\", \"io\""
            ),
        };
        if !matches!(resource, Resource::Cpu) {
            bail!(
                "triggers.resource = {:?}: only \"cpu\" is implemented in v1; \
                 memory/io attribution lands in Milestone 5",
                resource.as_str()
            );
        }

        let threshold_ms = self.triggers.threshold_ms.unwrap_or(defaults.triggers.threshold_ms);
        let window_ms = self.triggers.window_ms.unwrap_or(defaults.triggers.window_ms);
        let top_n = self.triggers.top_n.unwrap_or(defaults.triggers.top_n);

        // Kernel accepts window ∈ [500ms, 10000ms]; stall must be <= window.
        if !(500..=10_000).contains(&window_ms) {
            bail!(
                "triggers.window_ms = {window_ms}: kernel rejects windows outside 500..=10000"
            );
        }
        if threshold_ms == 0 {
            bail!("triggers.threshold_ms must be > 0");
        }
        if threshold_ms > window_ms {
            bail!(
                "triggers.threshold_ms = {threshold_ms} exceeds triggers.window_ms = {window_ms}; \
                 kernel would never fire"
            );
        }
        if top_n == 0 {
            bail!("triggers.top_n must be > 0");
        }

        let default_ladder = &defaults.ladder;
        let e0 = parse_duration_or(
            self.policy.escalate_observe_to_weight.as_deref(),
            default_ladder.escalate_after[0],
            "policy.escalate_observe_to_weight",
        )?;
        let e1 = parse_duration_or(
            self.policy.escalate_weight_to_idle.as_deref(),
            default_ladder.escalate_after[1],
            "policy.escalate_weight_to_idle",
        )?;
        let e2 = parse_duration_or(
            self.policy.escalate_idle_to_quota50.as_deref(),
            default_ladder.escalate_after[2],
            "policy.escalate_idle_to_quota50",
        )?;
        let e3 = parse_duration_or(
            self.policy.escalate_quota50_to_quota25.as_deref(),
            default_ladder.escalate_after[3],
            "policy.escalate_quota50_to_quota25",
        )?;

        // The ladder's own invariants: strictly positive, strictly monotone.
        let escalate_after = [e0, e1, e2, e3];
        let mut prev = Duration::ZERO;
        for (i, d) in escalate_after.iter().enumerate() {
            if d.is_zero() {
                bail!("policy escalation dwell #{i} is zero; must be > 0");
            }
            if *d <= prev {
                bail!(
                    "policy escalation dwells must be strictly increasing; got {escalate_after:?}"
                );
            }
            prev = *d;
        }

        let deescalate_after = parse_duration_or(
            self.policy.deescalate_after.as_deref(),
            default_ladder.deescalate_after,
            "policy.deescalate_after",
        )?;
        let untrack_after = parse_duration_or(
            self.policy.untrack_after.as_deref(),
            default_ladder.untrack_after,
            "policy.untrack_after",
        )?;
        if deescalate_after.is_zero() || untrack_after.is_zero() {
            bail!("policy.{{deescalate_after,untrack_after}} must be > 0");
        }

        let enable_freeze = self.enforcement.enable_freeze.unwrap_or(false);
        let enable_kill = self.enforcement.enable_kill.unwrap_or(false);
        if enable_kill && !enable_freeze {
            bail!(
                "enforcement.enable_kill requires enforcement.enable_freeze = true \
                 (the ladder never reaches Kill without passing through Freeze)"
            );
        }

        Ok(Config {
            triggers: Triggers {
                resource,
                threshold_ms,
                window_ms,
                top_n,
            },
            ladder: LadderConfig {
                escalate_after,
                deescalate_after,
                untrack_after,
                enable_freeze,
                enable_kill,
            },
            enforcement: Enforcement {
                enable_freeze,
                enable_kill,
            },
            protect: Protect {
                extra_names: self.protect.extra_names,
            },
        })
    }
}

/// Parse `"100ms"`, `"10s"`, `"2m"`, `"1h"`, or a bare integer (seconds).
/// Intentionally small vocabulary — the config surface is narrow and
/// pulling `humantime` in just to read six durations is overkill.
pub fn parse_duration(s: &str) -> Result<Duration> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        bail!("empty duration string");
    }
    // Bare integer → seconds.
    if let Ok(n) = trimmed.parse::<u64>() {
        return Ok(Duration::from_secs(n));
    }
    for (suffix, factor_ms) in [("ms", 1u64), ("s", 1000), ("m", 60_000), ("h", 3_600_000)] {
        if let Some(num_str) = trimmed.strip_suffix(suffix) {
            let num: u64 = num_str.trim().parse().with_context(|| {
                format!("parsing numeric part of duration {trimmed:?} (expected u64)")
            })?;
            return Ok(Duration::from_millis(num.saturating_mul(factor_ms)));
        }
    }
    bail!("unrecognized duration {trimmed:?} — expected e.g. 100ms, 10s, 2m, 1h")
}

fn parse_duration_or(
    maybe: Option<&str>,
    default: Duration,
    field: &str,
) -> Result<Duration> {
    match maybe {
        None => Ok(default),
        Some(s) => parse_duration(s).with_context(|| format!("invalid {field}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_short_durations() {
        assert_eq!(parse_duration("100ms").unwrap(), Duration::from_millis(100));
        assert_eq!(parse_duration("10s").unwrap(), Duration::from_secs(10));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("30").unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn rejects_garbage_durations() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("10x").is_err());
        assert!(parse_duration("ms").is_err());
    }

    #[test]
    fn defaults_match_hand_written_defaults() {
        let cfg: Config = Config::default();
        assert_eq!(cfg.triggers.threshold_ms, 100);
        assert_eq!(cfg.triggers.window_ms, 1000);
        assert_eq!(cfg.triggers.top_n, 5);
        assert!(!cfg.enforcement.enable_freeze);
        assert!(!cfg.enforcement.enable_kill);
    }

    #[test]
    fn empty_toml_yields_defaults() {
        let raw: RawConfig = toml::from_str("").unwrap();
        let cfg = raw.validate().unwrap();
        assert_eq!(cfg.triggers.threshold_ms, 100);
        assert_eq!(cfg.ladder.escalate_after, Config::default().ladder.escalate_after);
    }

    #[test]
    fn full_toml_parses_and_validates() {
        let text = r#"
            [triggers]
            resource = "cpu"
            threshold_ms = 50
            window_ms = 1000
            top_n = 3

            [policy]
            escalate_observe_to_weight = "5s"
            escalate_weight_to_idle = "15s"
            escalate_idle_to_quota50 = "30s"
            escalate_quota50_to_quota25 = "60s"
            deescalate_after = "20s"
            untrack_after = "90s"

            [enforcement]
            enable_freeze = true
            enable_kill = false

            [protect]
            extra_names = ["com.example.Thing"]
        "#;
        let raw: RawConfig = toml::from_str(text).unwrap();
        let cfg = raw.validate().unwrap();
        assert_eq!(cfg.triggers.threshold_ms, 50);
        assert_eq!(cfg.triggers.top_n, 3);
        assert_eq!(cfg.ladder.escalate_after[0], Duration::from_secs(5));
        assert_eq!(cfg.ladder.escalate_after[3], Duration::from_secs(60));
        assert_eq!(cfg.ladder.deescalate_after, Duration::from_secs(20));
        assert!(cfg.enforcement.enable_freeze);
        assert_eq!(cfg.protect.extra_names, vec!["com.example.Thing"]);
    }

    #[test]
    fn rejects_unknown_resource() {
        let text = r#"[triggers]
resource = "gpu"
"#;
        let err: anyhow::Error = toml::from_str::<RawConfig>(text)
            .unwrap()
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("gpu"));
    }

    #[test]
    fn rejects_non_cpu_resource_in_v1() {
        let text = r#"[triggers]
resource = "memory"
"#;
        let err: anyhow::Error = toml::from_str::<RawConfig>(text)
            .unwrap()
            .validate()
            .unwrap_err();
        assert!(err.to_string().contains("v1"));
    }

    #[test]
    fn rejects_window_out_of_kernel_range() {
        let text = r#"[triggers]
window_ms = 100
"#;
        let err = toml::from_str::<RawConfig>(text).unwrap().validate().unwrap_err();
        assert!(err.to_string().contains("window_ms"));
    }

    #[test]
    fn rejects_threshold_exceeding_window() {
        let text = r#"[triggers]
threshold_ms = 2000
window_ms = 1000
"#;
        let err = toml::from_str::<RawConfig>(text).unwrap().validate().unwrap_err();
        assert!(err.to_string().contains("exceeds"));
    }

    #[test]
    fn rejects_non_monotone_ladder() {
        let text = r#"[policy]
escalate_observe_to_weight = "30s"
escalate_weight_to_idle = "10s"
"#;
        let err = toml::from_str::<RawConfig>(text).unwrap().validate().unwrap_err();
        assert!(err.to_string().contains("strictly increasing"));
    }

    #[test]
    fn rejects_kill_without_freeze() {
        let text = r#"[enforcement]
enable_kill = true
enable_freeze = false
"#;
        let err = toml::from_str::<RawConfig>(text).unwrap().validate().unwrap_err();
        assert!(err.to_string().contains("enable_kill"));
    }

    #[test]
    fn rejects_unknown_keys() {
        // deny_unknown_fields should reject typos before validation even runs.
        let text = r#"[triggers]
thershold_ms = 100
"#;
        let err = toml::from_str::<RawConfig>(text);
        assert!(err.is_err(), "expected unknown-key rejection");
    }
}
