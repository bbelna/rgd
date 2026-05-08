#!/usr/bin/env bash
# Take 3 — rgd --enforce. Same workload. Watch KDE STAY responsive while
# the stress scope gets walked down the ladder. Concrete proof: cpu.max
# changes on the cgroup, xattrs appear, systemctl reports applied props.
set -euo pipefail
SCRIPT_DIR=/mnt/vm-demo
source "$SCRIPT_DIR/lib.sh"

LOG="$ART/03-enforce-rgd.jsonl"
PROBE="$ART/03-enforce-probe.json"
STATE="$ART/03-enforce-state.txt"
: >"$STATE"

echo "==> Take 3: ENFORCE — ${WORKLOAD_SECS}s"

RUST_LOG=rgd=info /usr/local/bin/rgd \
  --config "$CONFIG" \
  --enforce \
  --log-format json \
  >"$LOG" 2>&1 &
RGD_PID=$!
trap 'kill -TERM $RGD_PID 2>/dev/null; wait $RGD_PID 2>/dev/null || true' EXIT
sleep 1

start_stress "$WORKLOAD_SECS"
probe_scope_state "t=0s — BEFORE" "$STATE"

# Sample state at characteristic ladder checkpoints.
( sleep 8 ; probe_scope_state "t=8s — should be at Weight"  "$STATE" ) &
( sleep 20 ; probe_scope_state "t=20s — should be at Idle"   "$STATE" ) &
( sleep 40 ; probe_scope_state "t=40s — should be at Quota50" "$STATE" ) &
( sleep 65 ; probe_scope_state "t=65s — should be at Quota25" "$STATE" ) &

run_interactivity_probe "$PROBE" "$WORKLOAD_SECS"
wait

probe_scope_state "AFTER stress ended" "$STATE"
sleep 15  # let de-escalation kick in
probe_scope_state "POST de-escalation grace" "$STATE"

# Clean shutdown — daemon should revert any remaining levels at SIGTERM.
kill -TERM $RGD_PID 2>/dev/null || true
wait $RGD_PID 2>/dev/null || true
trap - EXIT
sleep 1
probe_scope_state "POST rgd SIGTERM (should show no rgd state)" "$STATE"

echo
echo "==> Take 3 complete. Probe summary:"
cat "$PROBE"
echo
echo "==> Key transitions:"
grep -oE '"\[APPLY\][^"]*"' "$LOG" | head -20 || true
echo
echo "Artifacts:"
echo "  $LOG"
echo "  $PROBE"
echo "  $STATE"
