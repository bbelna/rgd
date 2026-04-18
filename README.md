# `rgd`: Responsiveness Guardian Daemon

**Under initial development, not ready for production-level use.**

`rgd` is a Linux userspace daemon that keeps your desktop responsive under load by leveraging Pressure Stall Information (PSI), `cgroup` v2, and `systemd`. `rgd` detects which `cgroup` is causing a stall and applying graduated, reversible throttling before the compositor gives up.

## The problem

Run something heavy — a runaway build, a memory-hungry browser tab, a rogue
sync process — and your Linux desktop stalls. The compositor stops redrawing,
input latency explodes, and eventually you're staring at a frozen cursor until
`systemd-oomd` or `earlyoom` kills *something*.

The existing tools all fall into two camps:

- **Reactive, kill-only.** `systemd-oomd`, `earlyoom`, `nohang` — they wait
  until pressure is catastrophic, then `SIGKILL` the biggest offender. Good
  last-resort safety net. Zero help for the "everything is sluggish but not
  dying" case.
- **Static, launch-time only.** `uresourced`, `ananicy-cpp` — they apply a
  fixed resource policy when a process starts. No feedback loop; a workload
  that exceeds its pre-declared budget just stalls the system anyway.

Benjamin Berg's 2020 Linux Plumbers talk
([LWN writeup](https://lwn.net/Articles/829567/)) pointed out that the kernel
has shipped every mechanism needed to do better, yet no daemon ties them together into a desktop responsiveness policy. Six years on, still no one has filled the gap.

`rgd` is that daemon.

## The approach

1. **PSI tells us *when*.** Kernel triggers (no polling) fire the moment a
   configured stall threshold is crossed. The daemon sleeps on `epoll` until
   the kernel wakes it.
2. **Per-`cgroup` PSI tells us *who*.** On each trigger fire, we diff per-`cgroup`
   pressure snapshots and rank the tree by pressure delta. Linux has
   already done the expensive blame attribution.
3. **`systemd` applies the throttle.** Every desktop app already lives in its
   own transient scope (`app-firefox-@12345.scope`, etc.). We set properties
   on those scopes via `SetUnitProperties(runtime=true, …)` — no new `cgroups`,
   and `--runtime` means a reboot fixes any mistake.
4. **Enforcement is graduated and reversible.**
   `Observe → CPUWeight=20 → cpu.idle → CPUQuota=50% → CPUQuota=25% → freeze → kill`.
   The last two are opt-in and per-`cgroup` gated. When pressure subsides,
   every level steps back down on its own.
5. **The compositor is protected.** Auto-detected via Wayland `SO_PEERCRED`,
   D-Bus well-known names (`org.gnome.Shell`, `org.kde.KWin`), and the portal
   / audio stack, and kept out of the throttle candidate set.

## Safety model

- **Dry-run is the default.** `--enforce` is an explicit, separate flag.
- **Every intervention is reversible** through Level 4; Level 5 (freeze) is
  reversible by unfreezing; Level 6 (kill) is off by default and
  double-opt-in per `cgroup`.
- **Source of truth is on the `cgroup` itself.** We write `user.rgd.level` and
  `user.rgd.applied_at` xattrs *before* applying any property change. If the
  daemon crashes, the breadcrumb trail stays with the `cgroup` and dies with it.
- **Panic button.** `rgctl panic` walks the `cgroup` tree, strips every
  `user.rgd.*` `xattr`, and unsets every property we could have set — designed
  to work even if the daemon is wedged.
- **Never touches** `system.slice`, `init.scope`, or anything containing PID
  1, in v1.

## Building

```sh
cargo build --release
```

## References

- [Kernel PSI documentation](https://docs.kernel.org/accounting/psi.html)
- [cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- `systemd.resource-control(5)`
- [Benjamin Berg, LPC 2020 — the gap rgd fills](https://lwn.net/Articles/829567/)
- [Facebook's PSI microsite](https://facebookmicrosites.github.io/psi/)

## License

GPL-3.0-or-later.
