use anyhow::{Context, Result};
use std::os::fd::{FromRawFd, OwnedFd};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

use nix::fcntl::{self, OFlag};
use nix::sys::stat::Mode;
use nix::unistd;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Resource {
    Cpu,
    Memory,
    Io,
}

impl Resource {
    pub fn path(self) -> &'static str {
        match self {
            Self::Cpu => "/proc/pressure/cpu",
            Self::Memory => "/proc/pressure/memory",
            Self::Io => "/proc/pressure/io",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Memory => "memory",
            Self::Io => "io",
        }
    }
}

/// A PSI kernel trigger that wakes the async runtime (via `EPOLLPRI`) whenever
/// the specified stall threshold is breached within the specified window.
///
/// The fd is closed on drop, which the kernel treats as trigger removal —
/// so losing the handle is automatic cleanup, not a leak.
pub struct Trigger {
    inner: AsyncFd<OwnedFd>,
    resource: Resource,
}

impl Trigger {
    /// Open `/proc/pressure/<resource>`, install a `some`-line trigger with the
    /// given stall/window in microseconds, and register the fd with tokio's
    /// reactor using `Interest::PRIORITY` (which maps to `EPOLLPRI`).
    pub fn new(resource: Resource, threshold_us: u64, window_us: u64) -> Result<Self> {
        let raw_fd = fcntl::open(
            resource.path(),
            OFlag::O_RDWR | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("opening {}", resource.path()))?;

        // SAFETY: `fcntl::open` returned a freshly allocated RawFd that we
        // have exclusive ownership of; move it into OwnedFd so Drop closes it.
        let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        let command = format!("some {threshold_us} {window_us}\0");
        unistd::write(&owned_fd, command.as_bytes()).with_context(|| {
            format!(
                "writing PSI trigger {:?} to {}",
                command,
                resource.path()
            )
        })?;

        let inner = AsyncFd::with_interest(owned_fd, Interest::PRIORITY)
            .context("registering PSI trigger fd with tokio reactor")?;

        Ok(Self { inner, resource })
    }

    pub fn resource(&self) -> Resource {
        self.resource
    }

    /// Wait until the kernel signals that the trigger has fired. The trigger
    /// auto-rearms; a subsequent `wait()` blocks until the next firing.
    pub async fn wait(&self) -> Result<()> {
        let mut guard = self
            .inner
            .ready(Interest::PRIORITY)
            .await
            .context("awaiting PSI trigger readiness")?;
        guard.clear_ready();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_paths_match_procfs_layout() {
        assert_eq!(Resource::Cpu.path(), "/proc/pressure/cpu");
        assert_eq!(Resource::Memory.path(), "/proc/pressure/memory");
        assert_eq!(Resource::Io.path(), "/proc/pressure/io");
    }

    #[test]
    fn resource_as_str_roundtrips_for_logging() {
        assert_eq!(Resource::Cpu.as_str(), "cpu");
        assert_eq!(Resource::Memory.as_str(), "memory");
        assert_eq!(Resource::Io.as_str(), "io");
    }
}
