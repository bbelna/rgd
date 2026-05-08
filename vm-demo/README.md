# rgd VM demo

End-to-end test that proves rgd does what it claims: detect runaway CPU
pressure, attribute it to the right cgroup, and walk it down the
escalation ladder while the desktop stays responsive.

## One-time setup on the host

```bash
# from the repo root
cargo build --release
sudo setcap cap_sys_resource=ep target/release/rgd   # for any future host runs
```

The VM image, ISO, and overlay disk live under `vm/`:

```
vm/
├── fedora-kde-43.iso     3.1G — Fedora 43 KDE Live ISO
├── persist.qcow2         16G  — overlay disk for /home and dnf cache
└── launch.sh             qemu-system-x86_64 invocation
```

## Run the demo

```bash
bash vm/launch.sh
```

When the Fedora live session boots, click **Try Fedora** (no install
needed). Open Konsole, paste:

```bash
sudo mount -t 9p -o trans=virtio,version=9p2000.L rgd /mnt && \
  bash /mnt/vm-demo/00-bootstrap.sh
```

That sets the `liveuser` password (`rgd-demo`), starts sshd, installs
`stress-ng`, and deploys the host-built `rgd` binary with
`CAP_SYS_RESOURCE`.

From the **host**, drive each take over SSH:

```bash
ssh -p 2222 -o StrictHostKeyChecking=no liveuser@127.0.0.1 \
  bash /mnt/vm-demo/01-baseline.sh
ssh -p 2222 liveuser@127.0.0.1 bash /mnt/vm-demo/02-dryrun.sh
ssh -p 2222 liveuser@127.0.0.1 bash /mnt/vm-demo/03-enforce.sh
ssh -p 2222 liveuser@127.0.0.1 bash /mnt/vm-demo/04-panic.sh
```

Or paste the same commands inside the VM Konsole.

**Watch the QEMU window during each take.** The `interactivity probe`
gives you a quantitative number; the qualitative "is KDE smooth?" is
what makes the demo land.

## What each take proves

| Take | Workload | rgd | Expected KDE behavior | Quantitative check |
|------|----------|-----|------------------------|--------------------|
| 1 | `stress-ng --cpu 0` | OFF | Mouse stutter, animations choppy | probe `max_ms` high |
| 2 | same | dry-run | Same as Take 1 | probe `max_ms` ≈ Take 1; log shows ladder *would* fire |
| 3 | same | `--enforce` | Smooth after ~10s | probe `max_ms` drops; `cpu.max` shows `25000 100000` |
| 4 | shorter stress | `--enforce` then SIGKILL | n/a | properties remain; `rgctl panic` clears them |

## Artifacts

Everything writes to `vm-demo/artifacts/`:

```
00-vm-env.txt           kernel, systemd, cgroup controllers
01-baseline-probe.json  scheduler-wakeup latency under unprotected stress
01-baseline-state.txt   cgroup property snapshots (mostly empty for take 1)
02-dryrun-rgd.jsonl     daemon JSON log
02-dryrun-probe.json    same probe shape
02-dryrun-state.txt     scope state snapshots
03-enforce-rgd.jsonl    daemon JSON log including [APPLY] lines
03-enforce-probe.json   the money number — should be much lower than 01
03-enforce-state.txt    scope state at t=8/20/40/65 — watch CPUQuota descend
04-panic-rgd.jsonl
04-panic-state.txt      pre/post SIGKILL/post-panic snapshots
```

The compelling artifact is the side-by-side of `01` vs `03` probe JSON
plus `03-enforce-state.txt` (which contains the four ladder snapshots).
