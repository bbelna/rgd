use anyhow::{Context, Result};
use clap::Parser;
use tracing::{info, warn};
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

    /// Increase log verbosity: `-v` = debug, `-vv` = trace.
    #[arg(short = 'v', action = clap::ArgAction::Count)]
    verbose: u8,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    info!(
        resource = cli.resource.as_str(),
        threshold_ms = cli.threshold_ms,
        window_ms = cli.window_ms,
        top_n = cli.top_n,
        "starting PSI + per-cgroup observer (no enforcement)"
    );

    let threshold_us = cli.threshold_ms.saturating_mul(1_000);
    let window_us = cli.window_ms.saturating_mul(1_000);

    let trigger =
        Trigger::new(cli.resource, threshold_us, window_us).context("setting up PSI trigger")?;

    // Establish an initial baseline so the first fire has something to diff against.
    let mut previous: Snapshot = cgroup::snapshot(cli.resource)
        .context("taking initial per-cgroup pressure snapshot")?;
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

        match psi::read_current(cli.resource) {
            Ok(p) => info!(
                resource = cli.resource.as_str(),
                some_avg10 = p.some_avg10,
                some_avg60 = p.some_avg60,
                some_total_usec = p.some_total_usec,
                full_avg10 = p.full_avg10,
                "system-wide PSI at trigger fire"
            ),
            Err(e) => warn!(error = %e, "failed to read system-wide PSI snapshot"),
        }

        let top = policy::rank(&previous, &current, cli.top_n);
        if top.is_empty() {
            info!(
                tracked = current.len(),
                "trigger fired but no cgroup had a positive exclusive delta"
            );
        } else {
            for (i, attr) in top.iter().enumerate() {
                info!(
                    rank = i + 1,
                    path = %attr.path.display(),
                    exclusive_delta_usec = attr.exclusive_delta_usec,
                    some_delta_usec = attr.some_delta_usec,
                    full_delta_usec = attr.full_delta_usec,
                    some_total_usec = attr.some_total_usec,
                    "offender"
                );
            }
        }

        previous = current;
    }
}

fn init_tracing(verbose: u8) {
    let default_level = match verbose {
        0 => "rgd=info",
        1 => "rgd=debug",
        _ => "rgd=trace",
    };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}
