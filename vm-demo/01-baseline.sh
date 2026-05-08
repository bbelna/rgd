#!/usr/bin/env bash
# Take 1 — baseline: stress-ng --cpu 0 with rgd OFF.
# Watch the QEMU window. Move your mouse, switch desktops, drag a window.
# This is the "without rgd" picture. Logs go to artifacts/01-baseline-*.
set -euo pipefail
SCRIPT_DIR=/mnt/vm-demo
source "$SCRIPT_DIR/lib.sh"

PROBE="$ART/01-baseline-probe.json"
STATE="$ART/01-baseline-state.txt"
: >"$STATE"

echo "==> Take 1: BASELINE (no rgd) — ${WORKLOAD_SECS}s"
echo "==> Watch KDE responsiveness in the QEMU window."
sleep 1

start_stress "$WORKLOAD_SECS"
probe_scope_state "BEFORE workload (t=0s)" "$STATE"

run_interactivity_probe "$PROBE" "$WORKLOAD_SECS"

probe_scope_state "AFTER workload (t=${WORKLOAD_SECS}s)" "$STATE"
wait $STRESS_PID 2>/dev/null || true

echo
echo "==> Take 1 complete. Probe summary:"
cat "$PROBE"
echo
echo "Artifacts:"
echo "  $PROBE"
echo "  $STATE"
