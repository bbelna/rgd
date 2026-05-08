#!/usr/bin/env bash
# Take 4 — panic recovery. Bring rgd up under load, escalate it past
# Quota50, then SIGKILL the daemon (graceful teardown does NOT run).
# Confirm state is left behind, then prove `rgctl panic` cleans it up.
set -euo pipefail
SCRIPT_DIR=/mnt/vm-demo
source "$SCRIPT_DIR/lib.sh"

LOG="$ART/04-panic-rgd.jsonl"
STATE="$ART/04-panic-state.txt"
: >"$STATE"
: >"$LOG"

echo "==> Take 4: PANIC RECOVERY"

RUST_LOG=rgd=info /usr/local/bin/rgd \
  --config "$CONFIG" \
  --enforce \
  --log-format json \
  >"$LOG" 2>&1 &
RGD_PID=$!
sleep 1

# Generate sustained load just long enough to push past Quota50.
start_stress 60
sleep 45

probe_scope_state "PRE-PANIC (rgd alive, stress at level >= Quota50)" "$STATE"

echo "==> SIGKILL rgd (no graceful teardown)"
kill -KILL $RGD_PID 2>/dev/null || true
wait $RGD_PID 2>/dev/null || true
sleep 1

probe_scope_state "POST-SIGKILL (xattrs + properties should still be set)" "$STATE"

echo "==> rgctl panic"
/usr/local/bin/rgctl panic 2>&1 | tee -a "$STATE" || true
sleep 1

probe_scope_state "POST-rgctl-panic (state should be clean)" "$STATE"

# Stop the workload.
systemctl --user stop "$SCOPE.scope" 2>/dev/null || true
wait $STRESS_PID 2>/dev/null || true

echo
echo "==> Take 4 complete."
echo "Artifacts:"
echo "  $LOG"
echo "  $STATE"
