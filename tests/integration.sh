#!/usr/bin/env bash
# Real-lab integration test (root; GitHub Actions or the lab VM).
#   sudo tests/integration.sh            run 3 rounds, then tear the lab down
#   sudo KEEP_LAB=1 tests/integration.sh leave the lab up at the end
# Each round: setup_lab.sh -> tests/lab_harness.py (the whole expected-outcomes
# table in docs/LAB_INTERFACE.md, temp-block, snapshot/restore, reset, counter,
# render templates) -> reset_lab.sh -> baseline re-checked. Round 3 starts from a
# torn-down lab. Stops at the first failure and leaves the lab up for inspection.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

STEP_NO=0
step() { STEP_NO=$((STEP_NO + 1)); echo; echo "=== STEP ${STEP_NO}: $* [integration.sh] ==="; }
die() { echo "INTEGRATION FAILED: $*" >&2; exit 1; }
on_exit() {
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "INTEGRATION FAILED at step ${STEP_NO} (exit $rc). The lab was left up for inspection; scripts/teardown_lab.sh removes it." >&2
  fi
}
trap on_exit EXIT

[ "$(id -u)" -eq 0 ] || die "run as root: sudo $0"
[ -x "$REPO/.venv/bin/python" ] || die ".venv missing; run scripts/install.sh first"
PY="$REPO/.venv/bin/python"
started=$(date +%s)

for round in 1 2 3; do
  if [ "$round" -eq 3 ]; then
    step "Round $round: teardown first, so setup starts from nothing"
    "$REPO/scripts/teardown_lab.sh"
    for ns in router employee app db; do
      if ip netns list | awk '{print $1}' | grep -qx "$ns"; then die "namespace $ns survived teardown"; fi
    done
  fi

  step "Round $round: setup_lab.sh"
  "$REPO/scripts/setup_lab.sh" || die "setup_lab.sh failed (round $round)"

  step "Round $round: lab harness (expected-outcomes table and every Lab method)"
  "$PY" -m tests.lab_harness || die "lab harness failed (round $round)"

  step "Round $round: reset_lab.sh"
  "$REPO/scripts/reset_lab.sh" || die "reset_lab.sh failed (round $round)"

  step "Round $round: after reset the lab is the vulnerable baseline with counter 0"
  "$PY" - <<'EOF' || die "baseline check after reset failed (round $round)"
from backend.fake_lab import FakeLab
from backend.lab import Lab
lab = Lab.from_env()
want = [(r.rule_id, r.verdict, r.dport) for r in FakeLab(lab.addresses).rules()]
got = [(r.rule_id, r.verdict, r.dport) for r in lab.rules()]
assert got == want, f"rules after reset: {got}, want {want}"
assert lab.rule14_counter() == 0, f"counter after reset: {lab.rule14_counter()}"
assert not lab.block_active(), "temp-block present after reset"
attack = lab.run_attack()
assert attack.reached, f"attacker should reach the db on the baseline: {attack}"
assert lab.rule14_counter() == 1, f"counter after one attack: {lab.rule14_counter()}"
lab.reset()
print("    baseline ok: rule-10, rule-12, rule-14 accept; counter 0 -> 1 on attack -> 0 on reset")
EOF
  "$REPO/scripts/attack.sh" | grep -q "RESULT: REACHED" || die "scripts/attack.sh did not reach the db on the baseline"
  "$REPO/scripts/reset_lab.sh" >/dev/null || die "reset_lab.sh failed (round $round, second reset)"
done

if [ "${KEEP_LAB:-}" = 1 ]; then
  step "KEEP_LAB=1: leaving the lab up"
else
  step "Teardown"
  "$REPO/scripts/teardown_lab.sh"
fi

echo
echo "INTEGRATION PASSED: 3 rounds in $(( $(date +%s) - started )) s"
