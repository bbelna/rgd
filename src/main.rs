use anyhow::{Context, Result};
use clap::Parser;
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

use rgd::cgroup::{self, Snapshot};
use rgd::policy;
use rgd::psi::{self, Resource, Trigger};

#[derive(Parser, Debug)]
#[command(
    name = "rgd",
    version,
    about = "Responsiveness Guardian — PSI-driven Linux responsiveness daemon (Milestone 1 observer)"
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

    info!(
        resource = cli.resource.as_str(),
        threshold_ms = cli.threshold_ms,
        window_ms = cli.window_ms,
        top_n = cli.top_n,
        log_format = ?cli.log_format,
        "starting PSI + per-cgroup observer (no enforcement)"
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

    loop {
        trigger.wait().await.context("waiting on PSI trigger")?;

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

        // Full system PSI stays at debug so the info log is clean.
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

        let top = policy::rank(&previous, &current, cli.top_n);
        if top.is_empty() {
            info!(
                tracked = current.len(),
                system_delta_usec = sys_delta_usec,
                "trigger fired but no cgroup had a positive exclusive delta"
            );
        } else {
            let window_str = fmt_window(cli.window_ms);
            let sys_delta_str = fmt_duration_us(sys_delta_usec);
            let resource_str = cli.resource.as_str();
            for (i, attr) in top.iter().enumerate() {
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
        }

        previous = current;
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
        // ≥ 1s — show fractional seconds to 2dp.
        format!("{:.2}s", us as f64 / 1_000_000.0)
    } else {
        // Round to nearest ms.
        format!("{}ms", (us + 500) / 1000)
    }
}
