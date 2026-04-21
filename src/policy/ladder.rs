use std::time::Duration;

/// The graduated-enforcement ladder. Every level above `Observe` corresponds
/// to a specific systemd property write (or cgroupfs knob). The enforcement
/// backend maps levels to actions; this module is purely the shape of the
/// transition graph and the timing policy.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Level {
    Observe,
    Weight,
    Idle,
    Quota50,
    Quota25,
    Freeze,
    Kill,
}

impl Level {
    /// The next level up from this one, or `None` if we're at the top.
    pub fn next_up(self) -> Option<Self> {
        match self {
            Self::Observe => Some(Self::Weight),
            Self::Weight => Some(Self::Idle),
            Self::Idle => Some(Self::Quota50),
            Self::Quota50 => Some(Self::Quota25),
            Self::Quota25 => Some(Self::Freeze),
            Self::Freeze => Some(Self::Kill),
            Self::Kill => None,
        }
    }

    /// The next level down from this one. `Observe` is a fixed point.
    pub fn next_down(self) -> Self {
        match self {
            Self::Observe => Self::Observe,
            Self::Weight => Self::Observe,
            Self::Idle => Self::Weight,
            Self::Quota50 => Self::Idle,
            Self::Quota25 => Self::Quota50,
            Self::Freeze => Self::Quota25,
            Self::Kill => Self::Freeze,
        }
    }

    pub fn is_enforcement(self) -> bool {
        !matches!(self, Self::Observe)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "Observe",
            Self::Weight => "Weight",
            Self::Idle => "Idle",
            Self::Quota50 => "Quota50",
            Self::Quota25 => "Quota25",
            Self::Freeze => "Freeze",
            Self::Kill => "Kill",
        }
    }
}

/// Timing policy for the ladder. Defaults mirror the table in §6 of
/// `CLAUDE.md`; the config layer (session 6.1) will swap these at runtime.
#[derive(Debug, Clone)]
pub struct LadderConfig {
    /// Minimum dwell at current level before escalating to the next. Index
    /// is the *source* level: `[Observe→Weight, Weight→Idle, Idle→Q50, Q50→Q25]`.
    /// Beyond Quota25 (Freeze/Kill) is opt-in and gated by `enable_freeze` /
    /// `enable_kill` below — no automatic escalation into those levels.
    pub escalate_after: [Duration; 4],
    /// Time a tracked cgroup must be pressure-clear before stepping down
    /// one level.
    pub deescalate_after: Duration,
    /// Time a cgroup must sit at `Observe` with no pressure before being
    /// dropped from the tracked set entirely.
    pub untrack_after: Duration,
    pub enable_freeze: bool,
    pub enable_kill: bool,
}

impl LadderConfig {
    pub fn escalation_dwell_from(&self, level: Level) -> Option<Duration> {
        match level {
            Level::Observe => Some(self.escalate_after[0]),
            Level::Weight => Some(self.escalate_after[1]),
            Level::Idle => Some(self.escalate_after[2]),
            Level::Quota50 => Some(self.escalate_after[3]),
            Level::Quota25 if self.enable_freeze => Some(Duration::from_secs(240)),
            Level::Freeze if self.enable_kill => Some(Duration::from_secs(600)),
            _ => None,
        }
    }
}

impl Default for LadderConfig {
    fn default() -> Self {
        Self {
            escalate_after: [
                Duration::from_secs(10),
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(120),
            ],
            deescalate_after: Duration::from_secs(30),
            untrack_after: Duration::from_secs(120),
            enable_freeze: false,
            enable_kill: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_up_chain_terminates() {
        let mut cur = Level::Observe;
        let mut steps = 0;
        while let Some(next) = cur.next_up() {
            cur = next;
            steps += 1;
            assert!(steps < 10, "chain diverged");
        }
        assert_eq!(cur, Level::Kill);
        assert_eq!(steps, 6);
    }

    #[test]
    fn next_down_observe_is_fixpoint() {
        assert_eq!(Level::Observe.next_down(), Level::Observe);
    }

    #[test]
    fn next_down_reverses_next_up_except_top() {
        for level in [
            Level::Weight,
            Level::Idle,
            Level::Quota50,
            Level::Quota25,
            Level::Freeze,
        ] {
            let down_then_up = level.next_down().next_up();
            assert_eq!(down_then_up, Some(level));
        }
    }

    #[test]
    fn is_enforcement_distinguishes_observe() {
        assert!(!Level::Observe.is_enforcement());
        for level in [
            Level::Weight,
            Level::Idle,
            Level::Quota50,
            Level::Quota25,
            Level::Freeze,
            Level::Kill,
        ] {
            assert!(level.is_enforcement(), "{level:?}");
        }
    }

    #[test]
    fn default_config_is_monotone() {
        let cfg = LadderConfig::default();
        let mut prev = Duration::ZERO;
        for d in cfg.escalate_after {
            assert!(d > prev);
            prev = d;
        }
    }

    #[test]
    fn freeze_and_kill_disabled_by_default() {
        let cfg = LadderConfig::default();
        assert!(!cfg.enable_freeze);
        assert!(!cfg.enable_kill);
        assert_eq!(cfg.escalation_dwell_from(Level::Quota25), None);
        assert_eq!(cfg.escalation_dwell_from(Level::Freeze), None);
    }
}
