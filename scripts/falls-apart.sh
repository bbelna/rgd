#!/usr/bin/env bash
# falls-apart.sh — drive a CPU-oversubscription workload that would normally
# wreck desktop responsiveness, while measuring scheduler-wakeup latency from
# a normal-priority probe. Run twice for a side-by-side:
#
#   1) rgd in dry-run mode (default)        — baseline "without rgd"
#   2) rgd --enforce on the same workload   — runaway scope walked down
#
# Compare the JSON the probe prints. Without rgd, p99/max latency under load
# climbs into the tens or hundreds of ms — that's what makes the desktop feel
# like it's falling apart. With rgd's CPU ladder applied, the runaway scope
# gets quota-capped and the probe numbers should drop back toward idle.
#
# The runaway runs in a named transient unit (rgd-runaway.service) so rgd's
# attributor has an unambiguous cgroup to blame, and so the scope is trivially
# stoppable from outside.
#
# Knobs (env vars):
#   THREADS  default = 4 * nproc
#   DUR      default = 90s  (long enough for the full Observe→Quota25 walk)

set -euo pipefail

THREADS="${THREADS:-$(( $(nproc) * 4 ))}"
DUR="${DUR:-90}"
UNIT="rgd-runaway.service"

cleanup() {
  systemctl --user stop "$UNIT" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "=== falls-apart: $THREADS threads of matrixprod for ${DUR}s in $UNIT ==="
date -Is

python3 - "$DUR" <<'PY' &
import sys, time, json
dur = float(sys.argv[1])
samples = []
end = time.monotonic() + dur
while time.monotonic() < end:
  t0 = time.monotonic_ns()
  time.sleep(0.005)
  t1 = time.monotonic_ns()
  samples.append((t1 - t0) / 1e6 - 5.0)  # excess ms over the 5ms target
samples.sort()
def pct(p):
  return samples[min(len(samples) - 1, int(len(samples) * p))]
print(json.dumps({
  "samples": len(samples),
  "p50_ms": round(pct(0.50), 3),
  "p95_ms": round(pct(0.95), 3),
  "p99_ms": round(pct(0.99), 3),
  "max_ms": round(samples[-1], 3),
}, indent=2))
PY
PROBE=$!

systemd-run --user --wait \
  --unit="$UNIT" \
  -p CollectMode=inactive-or-failed \
  stress-ng --cpu "$THREADS" --cpu-method matrixprod --timeout "${DUR}s" \
  >/dev/null 2>&1 &
WORKLOAD=$!

wait "$PROBE" "$WORKLOAD"
date -Is
echo "=== done ==="
