use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Parser;
use futures::StreamExt;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;
use zbus::fdo::DBusProxy;
use zbus::Connection;

use rgd::cgroup::{self, Snapshot};
use rgd::enforce::{EnforceError, Enforcer, EnforcementGates, SystemdBackend};
use rgd::policy::{self, LadderConfig, Level, StateMachine, Transition};
use rgd::protect::{self, Protect, ProtectSet};
use rgd::psi::{self, Resource, Trigger};

#[derive(Parser, Debug)]
#[command(
    name = "rgd",
    version,
    about = "Responsiveness Guardian — PSI-driven Linux responsiveness daemon"
)]
struct Cli {
    /// Which kernel PSI resource to monitor.
    #[arg(long, value_enum, default_value_t = Resource::Cpu)]
    resource: Resource,

    /// Stall amount (ms) that must accumulate within `--window-ms` to fire.
    #[arg(long, default_value_t = 100)]
    threshold_ms: u64,

    /// Rolling window (ms) over which stall is measured. Kernel accepts
    /// 500–10000 ms; values outside that range are rejected at trigger setup.
    #[arg(long, default_value_t = 1000)]
    window_ms: u64,

    /// How many top offender cgroups to log per trigger fire.
    #[arg(long, default_value_t = 5)]
    top_n: usize,

    /// Apply graduated throttling. Without this flag every transition is
    /// logged as `[DRY-RUN] would: …` but no system state changes.
    #[arg(long)]
    enforce: bool,

    /// Opt in to `cgroup.freeze` as an escalation step. Reversible, but
    /// visibly pauses the cgroup's tasks — off by default.
    #[arg(long)]
    enable_freeze: bool,

    /// Opt in to `cgroup.kill`. Additionally requires per-cgroup
    /// `user.rgd.allow_kill` xattr. Off by default.
    #[arg(long)]
    enable_kill: bool,

    /// Log output format. `text` is human-readable; `json` is one-line JSON
    /// per event, suitable for piping into `jq` or a log shipper.
    #[arg(long, value_enum, default_value_t = LogFormat::Text)]
    log_format: LogFormat,

    /// Increase log verbosity: `-v` = debug, `-vv` = trace.
    #[arg(short = 'v', action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
enum LogFormat {
    Text,
    Json,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose, cli.log_format);

    let mode = if cli.enforce { "enforce" } else { "dry-run" };
    info!(
        resource = cli.resource.as_str(),
        threshold_ms = cli.threshold_ms,
        window_ms = cli.window_ms,
        top_n = cli.top_n,
        mode,
        enable_freeze = cli.enable_freeze,
        enable_kill = cli.enable_kill,
        log_format = ?cli.log_format,
        "starting responsiveness guardian"
    );

    let threshold_us = cli.threshold_ms.saturating_mul(1_000);
    let window_us = cli.window_ms.saturating_mul(1_000);

    let trigger =
        Trigger::new(cli.resource, threshold_us, window_us).context("setting up PSI trigger")?;

    let mut previous: Snapshot = cgroup::snapshot(cli.resource)
        .context("taking initial per-cgroup pressure snapshot")?;
    let mut prev_system_some: Option<u64> = psi::read_current(cli.resource)
        .map(|p| p.some_total_usec)
        .ok();
    info!(
        cgroups = previous.len(),
        "baseline pressure snapshot established"
    );

    // Connect to the session bus once; the handle drives D-Bus discovery,
    // the NameOwnerChanged listener, and — in --enforce mode — all
    // SetUnitProperties calls to the user systemd instance.
    let bus = match Connection::session().await {
        Ok(c) => Some(c),
        Err(e) => {
            warn!(error = %e, "no session D-Bus; D-Bus discovery disabled");
            None
        }
    };

    let initial = ProtectSet::discover(bus.as_ref()).await;
    info!(
        pids = initial.pids.len(),
        cgroups = initial.cgroups.len(),
        "protect set ready"
    );
    let protect = Protect::new(initial);

    if let Some(conn) = bus.clone() {
        let handle = protect.clone();
        tokio::spawn(async move {
            if let Err(e) = run_name_owner_listener(conn, handle).await {
                warn!(error = %e, "NameOwnerChanged listener exited");
            }
        });
    }

    let enforcer: Option<Enforcer> = if cli.enforce {
        match bus.as_ref() {
            Some(conn) => {
                let backend = SystemdBackend::from_session(conn.clone());
                let gates = EnforcementGates {
                    enable_freeze: cli.enable_freeze,
                    enable_kill: cli.enable_kill,
                };
                info!(
                    enable_freeze = gates.enable_freeze,
                    enable_kill = gates.enable_kill,
                    "enforcement enabled via user systemd"
                );
                Some(Enforcer::new(backend, gates))
            }
            None => {
                warn!(
                    "--enforce requested but session D-Bus unreachable; \
                     falling back to dry-run"
                );
                None
            }
        }
    } else {
        None
    };

    let mut state_machine = StateMachine::new(LadderConfig {
        enable_freeze: cli.enable_freeze,
        enable_kill: cli.enable_kill,
        ..LadderConfig::default()
    });

    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;

    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                info!("SIGTERM received; tearing down");
                break;
            }
            _ = sigint.recv() => {
                info!("SIGINT received; tearing down");
                break;
            }
            res = trigger.wait() => {
                res.context("waiting on PSI trigger")?;
            }
        }

        let current = match cgroup::snapshot(cli.resource) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "failed to snapshot cgroup pressure; skipping this fire");
                continue;
            }
        };

        let (sys_delta_usec, sys_snapshot) = match psi::read_current(cli.resource) {
            Ok(p) => {
                let delta = prev_system_some
                    .map(|prev| p.some_total_usec.saturating_sub(prev))
                    .unwrap_or(0);
                prev_system_some = Some(p.some_total_usec);
                (delta, Some(p))
            }
            Err(e) => {
                warn!(error = %e, "failed to read system-wide PSI snapshot");
                (0, None)
            }
        };

        if let Some(p) = sys_snapshot {
            debug!(
                resource = cli.resource.as_str(),
                some_avg10 = p.some_avg10,
                some_avg60 = p.some_avg60,
                some_avg300 = p.some_avg300,
                some_total_usec = p.some_total_usec,
                full_avg10 = p.full_avg10,
                "system-wide PSI at trigger fire"
            );
        }

        let set_snapshot = protect.snapshot().await;
        let ranking = policy::rank_with_protection(&previous, &current, cli.top_n, &set_snapshot);

        if ranking.offenders.is_empty() && ranking.protected_skipped.is_empty() {
            info!(
                tracked = current.len(),
                system_delta_usec = sys_delta_usec,
                "trigger fired but no cgroup had a positive exclusive delta"
            );
        }

        let window_str = fmt_window(cli.window_ms);
        let sys_delta_str = fmt_duration_us(sys_delta_usec);
        let resource_str = cli.resource.as_str();

        for attr in &ranking.protected_skipped {
            let unit = cgroup::unit_from_path(&attr.path);
            let procs = cgroup::procs::read_count(&attr.path).unwrap_or(0);
            let delta_str = fmt_duration_us(attr.exclusive_delta_usec);
            info!(
                path = %attr.path.display(),
                unit = %unit.unit,
                display = %unit.display,
                procs,
                exclusive_delta_usec = attr.exclusive_delta_usec,
                "[PROTECTED] {} ({}, {} procs) — {} (skipped; would have ranked)",
                unit.unit,
                unit.display,
                procs,
                delta_str,
            );
        }

        for (i, attr) in ranking.offenders.iter().enumerate() {
            let unit = cgroup::unit_from_path(&attr.path);
            let procs = cgroup::procs::read_count(&attr.path).unwrap_or(0);
            let delta_str = fmt_duration_us(attr.exclusive_delta_usec);
            info!(
                rank = i + 1,
                path = %attr.path.display(),
                unit = %unit.unit,
                display = %unit.display,
                procs,
                exclusive_delta_usec = attr.exclusive_delta_usec,
                some_delta_usec = attr.some_delta_usec,
                full_delta_usec = attr.full_delta_usec,
                some_total_usec = attr.some_total_usec,
                system_delta_usec = sys_delta_usec,
                "[{}/some +{}/{}] {} ({}, {} procs) — delta {} of {} total",
                resource_str,
                sys_delta_str,
                window_str,
                unit.unit,
                unit.display,
                procs,
                delta_str,
                sys_delta_str,
            );
        }

        let observations: Vec<(PathBuf, u64)> = ranking
            .offenders
            .iter()
            .map(|a| (a.path.clone(), a.exclusive_delta_usec))
            .collect();
        let transitions = state_machine.observe(Instant::now(), &observations);
        for t in transitions {
            log_transition(&t, enforcer.is_some());
            if let Some(enforcer) = enforcer.as_ref() {
                apply_transition(enforcer, &t).await;
            }
        }

        previous = current;
    }

    // Teardown: revert every cgroup we're still holding state on.
    if let Some(enforcer) = enforcer.as_ref() {
        let tracked: Vec<(PathBuf, Level)> = state_machine
            .states
            .iter()
            .map(|(p, s)| (p.clone(), s.level))
            .collect();
        let total = tracked.len();
        let mut reverted = 0;
        for (path, level) in tracked {
            if !level.is_enforcement() {
                continue;
            }
            let unit = cgroup::unit_from_path(&path);
            match enforcer.revert_to_observe(&path, &unit).await {
                Ok(()) => {
                    reverted += 1;
                    info!(
                        path = %path.display(),
                        unit = %unit.unit,
                        from = level.as_str(),
                        "teardown: reverted to Observe",
                    );
                }
                Err(e) => warn!(
                    path = %path.display(),
                    unit = %unit.unit,
                    error = %e,
                    "teardown: revert failed — run `rgctl panic` if needed",
                ),
            }
        }
        info!(
            total_tracked = total,
            reverted,
            "teardown complete"
        );
    }

    Ok(())
}

async fn apply_transition(enforcer: &Enforcer, t: &Transition) {
    let (path, target) = match t {
        Transition::Enter { .. } => return, // Observe — no property to write.
        Transition::Escalate { path, to, .. } => (path, *to),
        Transition::Deescalate { path, to, .. } => (path, *to),
        Transition::Untrack { .. } => return, // already reverted at the Observe step.
    };
    match enforcer.apply(path, target).await {
        Ok(()) => {
            info!(
                path = %path.display(),
                level = target.as_str(),
                "applied level",
            );
        }
        Err(EnforceError::Gated { level, reason }) => {
            info!(
                path = %path.display(),
                level = level.as_str(),
                reason,
                "gated: level not applied",
            );
        }
        Err(EnforceError::Protected(p)) => {
            warn!(path = %p, "refused: protected cgroup reached enforcement");
        }
        Err(e) => {
            warn!(
                path = %path.display(),
                level = target.as_str(),
                error = %e,
                "enforcement failed",
            );
        }
    }
}

async fn run_name_owner_listener(conn: Connection, protect: Protect) -> Result<()> {
    let proxy = DBusProxy::new(&conn)
        .await
        .context("building DBusProxy for NameOwnerChanged subscription")?;
    let mut stream = proxy
        .receive_name_owner_changed()
        .await
        .context("subscribing to NameOwnerChanged")?;
    debug!("NameOwnerChanged listener started");

    while let Some(signal) = stream.next().await {
        let Ok(args) = signal.args() else {
            continue;
        };
        let name = args.name.as_str();
        if protect::dbus::is_tracked_name(name) {
            info!(
                bus_name = %name,
                old_owner = ?args.old_owner,
                new_owner = ?args.new_owner,
                "tracked name ownership changed; refreshing protect set",
            );
            let refreshed = ProtectSet::discover(Some(&conn)).await;
            protect.replace(refreshed).await;
        }
    }
    Ok(())
}

fn log_transition(t: &Transition, enforcing: bool) {
    let prefix = if enforcing { "[APPLY]" } else { "[DRY-RUN]" };
    match t {
        Transition::Enter { path } => {
            info!(path = %path.display(), "{} enter: tracking at Observe", prefix);
        }
        Transition::Escalate {
            path,
            from,
            to,
            delta_usec,
            dwell,
        } => {
            info!(
                path = %path.display(),
                from = from.as_str(),
                to = to.as_str(),
                delta_usec = *delta_usec,
                dwell_ms = dwell.as_millis() as u64,
                "{} {}: {} → {} (Δ={}, dwell={:.1}s)",
                prefix,
                path.display(),
                from.as_str(),
                to.as_str(),
                fmt_duration_us(*delta_usec),
                dwell.as_secs_f64(),
            );
        }
        Transition::Deescalate {
            path,
            from,
            to,
            clear_for,
        } => {
            info!(
                path = %path.display(),
                from = from.as_str(),
                to = to.as_str(),
                clear_for_ms = clear_for.as_millis() as u64,
                "{} {}: {} → {} (clear={:.1}s)",
                prefix,
                path.display(),
                from.as_str(),
                to.as_str(),
                clear_for.as_secs_f64(),
            );
        }
        Transition::Untrack {
            path,
            dwell_at_observe,
        } => {
            info!(
                path = %path.display(),
                dwell_at_observe_ms = dwell_at_observe.as_millis() as u64,
                "{} untrack: {} (Observe for {:.1}s)",
                prefix,
                path.display(),
                dwell_at_observe.as_secs_f64(),
            );
        }
    }
}

fn init_tracing(verbose: u8, format: LogFormat) {
    let default_level = match verbose {
        0 => "rgd=info",
        1 => "rgd=debug",
        _ => "rgd=trace",
    };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    match format {
        LogFormat::Text => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(false)
                .init();
        }
        LogFormat::Json => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(false)
                .json()
                .init();
        }
    }
}

fn fmt_window(ms: u64) -> String {
    if ms >= 1000 && ms % 1000 == 0 {
        format!("{}s", ms / 1000)
    } else {
        format!("{ms}ms")
    }
}

fn fmt_duration_us(us: u64) -> String {
    if us >= 1_000_000 {
        format!("{:.2}s", us as f64 / 1_000_000.0)
    } else {
        format!("{}ms", (us + 500) / 1000)
    }
}
