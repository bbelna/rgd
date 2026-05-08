# Sourced by the take scripts. Defines paths + helpers.
SHARE=/mnt
DEMO=$SHARE/vm-demo
ART=$DEMO/artifacts
CONFIG=$DEMO/demo-config.toml
SCOPE=rgd-demo-stress
WORKLOAD_SECS=${WORKLOAD_SECS:-90}

mkdir -p "$ART"

# Spawn an interactivity probe — a Python loop that asks the scheduler to
# wake it every 1ms and records the worst delay it sees. Runs in the user's
# default session scope (NOT in the stress scope), so it's a fair proxy
# for "would the compositor have stalled?" Returns max_delay_ms / mean / p99.
run_interactivity_probe() {
  local out=$1 secs=$2
  python3 - "$secs" >"$out" <<'PY'
import sys, time, json
duration = float(sys.argv[1])
samples = []
last = time.monotonic()
deadline = last + duration
while time.monotonic() < deadline:
    time.sleep(0.001)
    now = time.monotonic()
    samples.append((now - last) * 1000.0)
    last = now
samples.sort()
n = len(samples)
print(json.dumps({
    "samples": n,
    "min_ms": round(samples[0], 3),
    "p50_ms": round(samples[n//2], 3),
    "p99_ms": round(samples[int(n*0.99)], 3),
    "max_ms": round(samples[-1], 3),
    "mean_ms": round(sum(samples)/n, 3),
}, indent=2))
PY
}

# Launch the stress workload in its own transient scope so rgd can attribute
# (and throttle) it without touching anything else.
start_stress() {
  local secs=$1
  systemd-run --user --scope --unit="$SCOPE" --quiet \
    stress-ng --cpu 0 --timeout "${secs}s" &
  STRESS_PID=$!
  sleep 0.5
  # Resolve the actual cgroup path so later stages can probe it.
  STRESS_CGROUP=$(cat /proc/$STRESS_PID/cgroup 2>/dev/null | head -1 | cut -d: -f3)
  STRESS_CGROUP_FS=/sys/fs/cgroup${STRESS_CGROUP}
  echo "stress scope: $SCOPE  cgroup: $STRESS_CGROUP_FS  pid: $STRESS_PID"
}

# Probe the live cgroup state. Useful before/during/after each take.
probe_scope_state() {
  local label=$1 out=$2
  {
    echo "## $label  ($(date -Is))"
    echo
    echo "### systemctl --user show $SCOPE"
    systemctl --user show "$SCOPE" 2>&1 \
      | grep -E '^(CPUWeight|CPUQuota|CPUWeightSet|CPUQuotaPerSecUSec)=' || echo "  (scope not active)"
    echo
    echo "### xattrs on $STRESS_CGROUP_FS"
    getfattr -d -m '^user\.rgd\.' "$STRESS_CGROUP_FS" 2>/dev/null \
      | sed 's/^/  /' || echo "  (no xattrs)"
    echo
    echo "### $STRESS_CGROUP_FS/cpu.max"
    cat "$STRESS_CGROUP_FS/cpu.max" 2>/dev/null || echo "  (unavailable)"
    echo
    echo "### $STRESS_CGROUP_FS/cpu.weight"
    cat "$STRESS_CGROUP_FS/cpu.weight" 2>/dev/null || echo "  (unavailable)"
    echo
    echo "### $STRESS_CGROUP_FS/cpu.idle"
    cat "$STRESS_CGROUP_FS/cpu.idle" 2>/dev/null || echo "  (unavailable)"
    echo "----"
  } >>"$out"
}
