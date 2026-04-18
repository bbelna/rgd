use anyhow::{Context, Result};
use clap::Parser;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use rgd::psi::{self, Resource, Trigger};

#[derive(Parser, Debug)]
#[command(
    name = "rgd",
    version,
    about = "Responsiveness Guardian — PSI-driven Linux responsiveness daemon (Session 1.1 observer)"
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
        "starting PSI trigger loop (observer mode, no enforcement)"
    );

    let threshold_us = cli.threshold_ms.saturating_mul(1_000);
    let window_us = cli.window_ms.saturating_mul(1_000);

    let trigger = Trigger::new(cli.resource, threshold_us, window_us)
        .context("setting up PSI trigger")?;

    loop {
        trigger.wait().await.context("waiting on PSI trigger")?;
        match psi::read_current(cli.resource) {
            Ok(p) => info!(
                resource = cli.resource.as_str(),
                some_avg10 = p.some_avg10,
                some_avg60 = p.some_avg60,
                some_avg300 = p.some_avg300,
                some_total_usec = p.some_total_usec,
                full_avg10 = p.full_avg10,
                full_avg60 = p.full_avg60,
                full_avg300 = p.full_avg300,
                full_total_usec = p.full_total_usec,
                "PSI trigger fired"
            ),
            Err(e) => warn!(error = %e, "trigger fired but failed to read PSI snapshot"),
        }
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
