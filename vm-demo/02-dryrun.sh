#!/usr/bin/env bash
# Take 2 — rgd in dry-run mode, same workload.
# Logs ladder progression but applies nothing. KDE responsiveness should
# look exactly like Take 1 — that's the point: the daemon doesn't help
# until you flip --enforce.
set -euo pipefail
SCRIPT_DIR=/mnt/vm-demo
source "$SCRIPT_DIR/lib.sh"

LOG="$ART/02-dryrun-rgd.jsonl"
PROBE="$ART/02-dryrun-probe.json"
STATE="$ART/02-dryrun-state.txt"
: >"$STATE"

echo "==> Take 2: DRY-RUN — ${WORKLOAD_SECS}s"

# Start rgd before the workload so it has a baseline snapshot.
RUST_LOG=rgd=info /usr/local/bin/rgd \
  --config "$CONFIG" \
  --log-format json \
  >"$LOG" 2>&1 &
RGD_PID=$!
trap 'kill $RGD_PID 2>/dev/null; wait $RGD_PID 2>/dev/null || true' EXIT
sleep 1

start_stress "$WORKLOAD_SECS"
probe_scope_state "BEFORE workload" "$STATE"
run_interactivity_probe "$PROBE" "$WORKLOAD_SECS"
probe_scope_state "AFTER workload" "$STATE"
wait $STRESS_PID 2>/dev/null || true
sleep 5  # let de-escalation log

kill -TERM $RGD_PID 2>/dev/null || true
wait $RGD_PID 2>/dev/null || true
trap - EXIT

echo
echo "==> Take 2 complete. Probe summary:"
cat "$PROBE"
echo
echo "==> rgd ladder transitions in this run:"
grep -oE '"[A-Z-]*\] [^"]*: [A-Za-z0-9]+ → [A-Za-z0-9]+[^"]*"' "$LOG" | head -30 || true
echo
echo "Artifacts:"
echo "  $LOG"
echo "  $PROBE"
echo "  $STATE"
