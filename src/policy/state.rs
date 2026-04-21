use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::policy::ladder::{LadderConfig, Level};

#[derive(Debug, Clone)]
pub struct CgroupState {
    pub level: Level,
    /// When we last transitioned into `level`. Used as the dwell clock for
    /// escalation, and as a lower bound for the clear-time clock after a
    /// de-escalation (so successive de-escalations each require a fresh
    /// clear window).
    pub level_entered_at: Instant,
    /// When we last saw pressure attributed to this cgroup. `None` iff the
    /// cgroup has never been seen pressured (impossible post-Enter, but
    /// safer to model as an option).
    pub last_pressure_at: Option<Instant>,
    pub last_exclusive_delta_usec: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    Enter {
        path: PathBuf,
    },
    Escalate {
        path: PathBuf,
        from: Level,
        to: Level,
        delta_usec: u64,
        dwell: Duration,
    },
    Deescalate {
        path: PathBuf,
        from: Level,
        to: Level,
        clear_for: Duration,
    },
    Untrack {
        path: PathBuf,
        dwell_at_observe: Duration,
    },
}

pub struct StateMachine {
    pub states: HashMap<PathBuf, CgroupState>,
    pub config: LadderConfig,
}

impl StateMachine {
    pub fn new(config: LadderConfig) -> Self {
        Self {
            states: HashMap::new(),
            config,
        }
    }

    pub fn len(&self) -> usize {
        self.states.len()
    }

    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    /// Record a new observation and produce the transitions that fire.
    ///
    /// `present` is the set of cgroups with positive exclusive-delta in this
    /// fire (the unprotected top-N). Tracked cgroups not in `present` accrue
    /// clear time since `max(last_pressure_at, level_entered_at)`; once that
    /// exceeds `deescalate_after`, they step down one level. At `Observe`
    /// they eventually untrack (`untrack_after`).
    pub fn observe(
        &mut self,
        now: Instant,
        present: &[(PathBuf, u64)],
    ) -> Vec<Transition> {
        let present_paths: HashSet<&PathBuf> = present.iter().map(|(p, _)| p).collect();
        let mut transitions = Vec::new();

        for (path, delta) in present {
            if !self.states.contains_key(path) {
                self.states.insert(
                    path.clone(),
                    CgroupState {
                        level: Level::Observe,
                        level_entered_at: now,
                        last_pressure_at: Some(now),
                        last_exclusive_delta_usec: *delta,
                    },
                );
                transitions.push(Transition::Enter { path: path.clone() });
                continue;
            }
            let (current_level, dwell) = {
                let st = self
                    .states
                    .get_mut(path)
                    .expect("contains_key true above");
                st.last_pressure_at = Some(now);
                st.last_exclusive_delta_usec = *delta;
                (st.level, now.duration_since(st.level_entered_at))
            };
            if let Some(target) = self.plan_escalation(current_level, dwell) {
                let st = self.states.get_mut(path).expect("still present");
                let from = st.level;
                st.level = target;
                st.level_entered_at = now;
                transitions.push(Transition::Escalate {
                    path: path.clone(),
                    from,
                    to: target,
                    delta_usec: *delta,
                    dwell,
                });
            }
        }

        let absent: Vec<PathBuf> = self
            .states
            .keys()
            .filter(|k| !present_paths.contains(k))
            .cloned()
            .collect();
        for path in absent {
            let (level, reference) = {
                let st = self.states.get(&path).expect("key from iter");
                let last_pressure = st.last_pressure_at.unwrap_or(st.level_entered_at);
                (st.level, last_pressure.max(st.level_entered_at))
            };
            let clear_for = now.saturating_duration_since(reference);

            if level == Level::Observe {
                if clear_for >= self.config.untrack_after {
                    transitions.push(Transition::Untrack {
                        path: path.clone(),
                        dwell_at_observe: clear_for,
                    });
                    self.states.remove(&path);
                }
                continue;
            }

            if clear_for >= self.config.deescalate_after {
                let from = level;
                let to = from.next_down();
                let st = self.states.get_mut(&path).expect("still present");
                st.level = to;
                st.level_entered_at = now;
                transitions.push(Transition::Deescalate {
                    path,
                    from,
                    to,
                    clear_for,
                });
            }
        }

        transitions
    }

    fn plan_escalation(&self, current: Level, dwell: Duration) -> Option<Level> {
        let next = current.next_up()?;
        if next == Level::Freeze && !self.config.enable_freeze {
            return None;
        }
        if next == Level::Kill && !self.config.enable_kill {
            return None;
        }
        let required = self.config.escalation_dwell_from(current)?;
        if dwell >= required {
            Some(next)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(config: LadderConfig) -> StateMachine {
        StateMachine::new(config)
    }

    fn path(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn first_observation_enters_at_observe() {
        let mut sm = make(LadderConfig::default());
        let t0 = Instant::now();
        let transitions = sm.observe(t0, &[(path("/a"), 100)]);
        assert_eq!(transitions.len(), 1);
        assert!(matches!(&transitions[0], Transition::Enter { path } if path.as_os_str() == "/a"));
        let st = sm.states.get(&path("/a")).unwrap();
        assert_eq!(st.level, Level::Observe);
        assert_eq!(st.last_exclusive_delta_usec, 100);
    }

    #[test]
    fn escalates_through_ladder_under_sustained_pressure() {
        let cfg = LadderConfig {
            escalate_after: [
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(3),
                Duration::from_secs(4),
            ],
            ..LadderConfig::default()
        };
        let mut sm = make(cfg);
        let t0 = Instant::now();
        let p = path("/a");

        sm.observe(t0, &[(p.clone(), 100)]);
        assert_eq!(sm.states[&p].level, Level::Observe);

        let ts = sm.observe(t0 + Duration::from_millis(1500), &[(p.clone(), 100)]);
        assert!(ts
            .iter()
            .any(|t| matches!(t, Transition::Escalate { from: Level::Observe, to: Level::Weight, .. })));
        assert_eq!(sm.states[&p].level, Level::Weight);

        let ts = sm.observe(t0 + Duration::from_millis(3600), &[(p.clone(), 100)]);
        assert!(ts
            .iter()
            .any(|t| matches!(t, Transition::Escalate { from: Level::Weight, to: Level::Idle, .. })));
        assert_eq!(sm.states[&p].level, Level::Idle);

        let ts = sm.observe(t0 + Duration::from_millis(7000), &[(p.clone(), 100)]);
        assert!(ts
            .iter()
            .any(|t| matches!(t, Transition::Escalate { from: Level::Idle, to: Level::Quota50, .. })));

        let ts = sm.observe(t0 + Duration::from_millis(12000), &[(p.clone(), 100)]);
        assert!(ts
            .iter()
            .any(|t| matches!(t, Transition::Escalate { from: Level::Quota50, to: Level::Quota25, .. })));
        assert_eq!(sm.states[&p].level, Level::Quota25);

        // No further escalation — Freeze is opt-in.
        let ts = sm.observe(t0 + Duration::from_millis(30000), &[(p.clone(), 100)]);
        assert!(!ts
            .iter()
            .any(|t| matches!(t, Transition::Escalate { to: Level::Freeze, .. })));
        assert_eq!(sm.states[&p].level, Level::Quota25);
    }

    #[test]
    fn deescalates_after_clear_window() {
        let cfg = LadderConfig {
            escalate_after: [Duration::from_millis(500); 4],
            deescalate_after: Duration::from_secs(2),
            ..LadderConfig::default()
        };
        let mut sm = make(cfg);
        let t0 = Instant::now();
        let p = path("/a");

        sm.observe(t0, &[(p.clone(), 100)]);
        sm.observe(t0 + Duration::from_millis(600), &[(p.clone(), 100)]);
        assert_eq!(sm.states[&p].level, Level::Weight);

        // Absent for 3s — more than deescalate_after; step down.
        let ts = sm.observe(t0 + Duration::from_millis(3700), &[]);
        assert!(ts
            .iter()
            .any(|t| matches!(t, Transition::Deescalate { from: Level::Weight, to: Level::Observe, .. })));
        assert_eq!(sm.states[&p].level, Level::Observe);
    }

    #[test]
    fn untracks_after_long_observe_period() {
        let cfg = LadderConfig {
            untrack_after: Duration::from_secs(5),
            ..LadderConfig::default()
        };
        let mut sm = make(cfg);
        let t0 = Instant::now();
        let p = path("/a");
        sm.observe(t0, &[(p.clone(), 100)]);

        // Absent for 6s after Enter at Observe → untrack.
        let ts = sm.observe(t0 + Duration::from_secs(6), &[]);
        assert!(ts.iter().any(|t| matches!(t, Transition::Untrack { .. })));
        assert!(!sm.states.contains_key(&p));
    }

    #[test]
    fn returning_pressure_delays_deescalation() {
        // Weight→Idle set high so the test only observes Observe→Weight.
        let cfg = LadderConfig {
            escalate_after: [
                Duration::from_millis(500),
                Duration::from_secs(10_000),
                Duration::from_secs(10_000),
                Duration::from_secs(10_000),
            ],
            deescalate_after: Duration::from_secs(5),
            ..LadderConfig::default()
        };
        let mut sm = make(cfg);
        let t0 = Instant::now();
        let p = path("/a");

        sm.observe(t0, &[(p.clone(), 100)]);
        sm.observe(t0 + Duration::from_millis(600), &[(p.clone(), 100)]);
        assert_eq!(sm.states[&p].level, Level::Weight);

        // Absent for 3s (below threshold): no de-escalation yet.
        let ts = sm.observe(t0 + Duration::from_secs(3), &[]);
        assert!(!ts
            .iter()
            .any(|t| matches!(t, Transition::Deescalate { .. })));
        assert_eq!(sm.states[&p].level, Level::Weight);

        // Pressure returns at 4s — last_pressure_at moves forward.
        sm.observe(t0 + Duration::from_secs(4), &[(p.clone(), 100)]);

        // Another 4s absent (t0+8s). Only 4s since pressure — not enough.
        let ts = sm.observe(t0 + Duration::from_secs(8), &[]);
        assert!(!ts
            .iter()
            .any(|t| matches!(t, Transition::Deescalate { .. })));
        assert_eq!(sm.states[&p].level, Level::Weight);

        // But now wait >=5s since last pressure → de-escalates.
        let ts = sm.observe(t0 + Duration::from_secs(10), &[]);
        assert!(ts
            .iter()
            .any(|t| matches!(t, Transition::Deescalate { from: Level::Weight, to: Level::Observe, .. })));
    }

    #[test]
    fn freeze_gate_blocks_escalation_beyond_quota25_by_default() {
        let cfg = LadderConfig {
            escalate_after: [Duration::from_millis(1); 4],
            ..LadderConfig::default()
        };
        let mut sm = make(cfg);
        let t0 = Instant::now();
        let p = path("/a");

        for ms in [0u64, 100, 200, 300, 400, 500, 600, 700] {
            sm.observe(t0 + Duration::from_millis(ms), &[(p.clone(), 100)]);
        }
        assert_eq!(sm.states[&p].level, Level::Quota25);
    }
}
