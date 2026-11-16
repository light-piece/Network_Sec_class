#!/usr/bin/env bash
# End-to-end API test against a running backend, calling the endpoints in the
# same order dashboard/js/workflow.js does (docs/API_CONTRACT.md).
#
# Usage:  tests/api_flow.sh <A|B> [base-url]
#   A: first recommendation is correct -> both checks pass.
#   B: first recommendation is too broad -> app check fails -> containment restored,
#      rollback, recommendation with failed feedback -> second version passes.
# The backend must run with AI_MODE=mock and MOCK_AI_SCENARIO matching <A|B>.
set -euo pipefail

SCENARIO="${1:?usage: tests/api_flow.sh <A|B> [base-url]}"
BASE="${2:-http://127.0.0.1:8000}"
API="$BASE/api"
STEP_NO=0

step() { STEP_NO=$((STEP_NO + 1)); echo "=== STEP ${STEP_NO}: $* [api_flow.sh $SCENARIO] ==="; }
die()  { echo "API FLOW FAILED ($SCENARIO): $*" >&2; exit 1; }

# call METHOD PATH [JSON-BODY] -> prints the body; fails on non-2xx with the response.
call() {
  local method="$1" path="$2" body="${3:-}" out code
  out="$(mktemp)"
  if [ -n "$body" ]; then
    code="$(curl -sS -m 60 -o "$out" -w '%{http_code}' -X "$method" -H 'Content-Type: application/json' -d "$body" "$API$path")"
  else
    code="$(curl -sS -m 60 -o "$out" -w '%{http_code}' -X "$method" "$API$path")"
  fi
  if [ "${code:0:1}" != "2" ]; then
    echo "HTTP $code from $method $path:" >&2; cat "$out" >&2; echo >&2; rm -f "$out"
    die "$method $path returned $code"
  fi
  cat "$out"; rm -f "$out"
}

# json FIELD.PATH < body  (dotted path, list indexes allowed)
json() {
  python3 -c '
import json, sys
v = json.load(sys.stdin)
for k in sys.argv[1].split("."):
    v = v[int(k)] if isinstance(v, list) else v[k]
print(v if not isinstance(v, (dict, list)) else json.dumps(v))' "$1"
}

expect() {  # expect LABEL ACTUAL WANTED
  [ "$2" = "$3" ] || die "$1: got '$2', want '$3'"
  echo "    ok  $1 = $3"
}

check() {  # check INCIDENT REC CHECK-ID -> prints status
  call POST "/incidents/$1/verifications/$3" "{\"recommendationId\": \"$2\"}" | json status
}

step "Backend status"
STATUS="$(call GET /status)"
expect "lab" "$(echo "$STATUS" | json lab)" "up"
expect "app" "$(echo "$STATUS" | json app)" "ok"
expect "database" "$(echo "$STATUS" | json database)" "ok"
expect "aiModel" "$(echo "$STATUS" | json aiModel)" "Mock AI (scenario $SCENARIO)"

step "Reset to the vulnerable baseline"
call POST /lab/reset >/dev/null

step "Attack from the employee workstation"
expect "attack reached the database" "$(call POST /lab/attack | json reached)" "True"

step "Detection (long-poll for the incident)"
INC_JSON="$(call GET /incidents/active)"
INC="$(echo "$INC_JSON" | json id)"
expect "matched rule" "$(echo "$INC_JSON" | json policy.ruleId)" "14"
echo "    incident $INC"

step "Temporary block"
expect "containment" "$(call POST "/incidents/$INC/containment" | json status)" "active"

step "AI recommendation v1"
REC_JSON="$(call POST "/incidents/$INC/recommendations" '{"feedback": null}')"
REC="$(echo "$REC_JSON" | json id)"
expect "version" "$(echo "$REC_JSON" | json version)" "1"
echo "    $REC: $(echo "$REC_JSON" | json summary)"

step "Approve and apply v1"
call POST "/recommendations/$REC/decision" '{"decision": "approved"}' >/dev/null
expect "correction" "$(call POST "/incidents/$INC/corrections" "{\"recommendationId\": \"$REC\"}" | json status)" "applied"

step "Lift the temporary block and verify v1"
expect "lift" "$(call DELETE "/incidents/$INC/containment" | json status)" "lifted"
BLOCKED="$(check "$INC" "$REC" unauthorized_blocked)"
APPOK="$(check "$INC" "$REC" legitimate_app)"
expect "unauthorized_blocked" "$BLOCKED" "passed"

if [ "$SCENARIO" = "A" ]; then
  expect "legitimate_app" "$APPOK" "passed"
else
  expect "legitimate_app (too-broad fix must break the app)" "$APPOK" "failed"

  step "Restore the block and roll back v1"
  expect "restore containment" "$(call POST "/incidents/$INC/containment" | json status)" "active"
  expect "rollback" "$(call POST "/incidents/$INC/corrections/$REC/rollback" | json status)" "rolled_back"

  step "AI recommendation v2 with failed-check feedback"
  FEEDBACK='{"feedback": {"type": "failed", "version": 1, "summary": "Company application still works failed: the application could not reach the database."}}'
  REC2_JSON="$(call POST "/incidents/$INC/recommendations" "$FEEDBACK")"
  REC2="$(echo "$REC2_JSON" | json id)"
  expect "version" "$(echo "$REC2_JSON" | json version)" "2"
  echo "    $REC2: $(echo "$REC2_JSON" | json summary)"

  step "Approve and apply v2"
  call POST "/recommendations/$REC2/decision" '{"decision": "approved"}' >/dev/null
  expect "correction" "$(call POST "/incidents/$INC/corrections" "{\"recommendationId\": \"$REC2\"}" | json status)" "applied"

  step "Lift the temporary block and verify v2"
  expect "lift" "$(call DELETE "/incidents/$INC/containment" | json status)" "lifted"
  expect "unauthorized_blocked" "$(check "$INC" "$REC2" unauthorized_blocked)" "passed"
  expect "legitimate_app" "$(check "$INC" "$REC2" legitimate_app)" "passed"
fi

step "Dashboard is served"
curl -sS -m 10 "$BASE/" | grep -q "Threat Containment Console" || die "GET / did not return the dashboard"
echo "    ok  GET / serves the dashboard"

step "Reset"
call POST /lab/reset >/dev/null
expect "attack reaches the database again after reset" "$(call POST /lab/attack | json reached)" "True"
call POST /lab/reset >/dev/null

echo "API FLOW PASSED (scenario $SCENARIO)"
