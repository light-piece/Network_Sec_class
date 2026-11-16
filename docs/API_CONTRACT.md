# API contract

The backend (FastAPI) must implement this API so the existing dashboard works unchanged except for the small edits in plan section 2.2.

**Sources of truth:** `dashboard/js/api-service.js` (paths and methods) and `dashboard/js/mock-service.js` (response shapes). This document restates them; if they ever disagree, the JavaScript wins and this file gets fixed.

## Conventions

- **Base path:** all endpoints are under `/api` (`config.js` `API_BASE` becomes the relative `/api`).
- **Format:** JSON in and out. `Content-Type: application/json` on requests with a body.
- **Errors:** non-2xx status with FastAPI's standard body `{"detail": "<human-readable message>"}`. `api-service.js` throws on any non-2xx, so messages must be readable by an administrator (the dashboard will show them; see plan 2.2).
- **Status codes:** `200` success · `404` unknown incident/recommendation, or no incident after long-poll · `409` action not valid in the current state (e.g. applying a rejected recommendation) · `422` invalid body (FastAPI default) · `502` AI unreachable or returned an invalid recommendation · `500` lab command failed.
- **IDs:** strings. Incidents `INC-<year>-<4 digits>` (e.g. `INC-2026-0001`); recommendations `REC-<n>`, numbered per incident starting at 1.
- **Timestamps:** milliseconds since the Unix epoch (JavaScript `Date` style).
- **State:** in memory; one open incident at a time. `POST /api/lab/reset` clears it.

---

## Data shapes

These mirror the comment block at the top of `mock-service.js`. Implement them as Pydantic models (`backend/models.py`).

### Host

```json
{ "name": "Employee workstation", "role": "Employee workstation", "ip": "10.10.10.10", "segment": "Employee network 10.10.10.0/24" }
```

### Incident

```json
{
  "id": "INC-2026-0001",
  "detectedAt": 1794800000000,
  "source": { Host },
  "target": { Host },
  "app":    { Host },
  "connection": { "protocol": "TCP", "srcPort": null, "dstPort": 5432, "service": "PostgreSQL", "observedBy": "Firewall rule counter (rule-14)" },
  "policy": { "ruleId": "14", "ruleText": "allow 10.10.10.0/24 → 10.10.30.10 tcp/5432", "intendedPath": "Employee → company application → database" }
}
```

- Host names come from configuration. Defaults: `Employee workstation` (10.10.10.10), `Company database` (10.10.30.10), `Company app` (10.10.20.10).
- `srcPort` may be `null`: the rule counter does not record it.
- `policy.ruleId` is the display number without the `rule-` prefix (`"14"`).

### Containment

```json
{ "status": "active", "ruleId": "T-1", "ruleText": "deny 10.10.10.10 → 10.10.30.10 tcp/5432" }
```
`status` is `"active"` or `"lifted"`. `ruleId`/`ruleText` are required when active, optional when lifted.

### Rule (display row)

```json
{ "num": "14", "action": "allow", "src": "Employee network", "dst": "Company database", "port": "tcp/5432", "note": "Misconfigured", "change": "removed" }
```

- `num`: display number. Lab rules map `rule-10` → `"10"`, `rule-12` → `"12"`, `rule-14` → `"14"`; the default policy shows as `"99"` (`deny any any any`, note `Default deny`). A rule added by the AI gets a number that sorts into its position (e.g. `"11"` before rule 12, `"13"` after it).
- `action`: `"allow"` or `"deny"` (display words; the nftables verdicts are `accept`/`drop`).
- `change`: `"unchanged"`, `"added"` or `"removed"`, relative to the "before" list.

### Recommendation

```json
{
  "id": "REC-1",
  "version": 1,
  "model": "qwen3:4b via Ollama",
  "summary": "One sentence the administrator reads first.",
  "change": "What changes, in plain words.",
  "affects": "Who loses access.",
  "unaffected": "Who keeps access.",
  "before": [ Rule, ... ],
  "after":  [ Rule, ... ],
  "commands": [ "nft ... (exact commands that will run, for display)" ],
  "whatChanged": "",
  "revisedBecause": null,
  "previousVersion": null,
  "previousFailure": null,
  "failDetail": null
}
```

- `model`: `"qwen3:4b via Ollama"` in real mode, `"Mock AI (scenario A)"` / `"Mock AI (scenario B)"` in mock mode.
- `before`/`after`: produced **by the backend** from the validated AI actions (dry run), not written by the AI.
- `commands`: the exact nftables commands the backend will run, generated from fixed templates.
- `whatChanged`: empty for version 1; for later versions, how it differs from the previous one (AI-written).
- `revisedBecause`, `previousVersion`, `previousFailure`: copied from the request's `feedback` (see below); `null` for version 1.
- `failDetail`: `null` when created. After a failed verification the backend sets it to an explanation built from the failed check's evidence; the dashboard shows it in the failure summary.
- **Mock-only fields** `outcome`, `blockedBy`, `failEvidence` exist in `mock-service.js` to fake results. The real API does **not** return them; real check results come from `/verifications`.

### CheckResult

```json
{ "id": "unauthorized_blocked", "status": "passed", "detail": "The direct connection was refused.", "evidence": "pg_isready -h 10.10.30.10 -p 5432 → exit 2 (no response) · blocked" }
```

- `id`: **exactly** `"unauthorized_blocked"` or `"legitimate_app"` (the dashboard's `TCC.CHECK_IDS`).
- `status`: `"passed"` or `"failed"` from the API (`"not_tested"` and `"running"` are dashboard-only states).
- `evidence`: short, factual: the command run, its result, and timing.

### Feedback (request body field)

```json
{ "type": "failed", "version": 1, "summary": "“Company application still works” failed: ..." }
```
`type` is `"rejected"` (admin asked for a different approach) or `"failed"` (verification failed). `summary` is present when `type` is `"failed"`.

---

## Endpoints the dashboard calls

### 1. `GET /api/incidents/active`
Returns the open incident. **Long-poll:** if none exists yet, wait up to 15 s for the detector to create one.
- `200` → `Incident`
- `404` → `{"detail": "No unauthorized connection detected."}` after 15 s

### 2. `POST /api/incidents/{id}/containment`
Turns the temporary block on. Also used to **restore** it after a failed verification. Idempotent: if already on, returns the current state.
- `200` → `Containment` (`status: "active"`)

### 3. `DELETE /api/incidents/{id}/containment`
Removes the temporary block. Idempotent.
- `200` → `{"status": "lifted"}`

### 4. `POST /api/incidents/{id}/recommendations`
Body: `{"feedback": Feedback | null}`. Asks the AI for a recommendation, validates it, builds the before/after rules and the commands.
- `200` → `Recommendation`
- `502` → AI unreachable, timed out, or still invalid after one retry. `detail` says which.
- `409` → maximum attempts (`MAX_ATTEMPTS`, default 3) reached for this incident.

### 5. `POST /api/recommendations/{recId}/decision`
Body: `{"decision": "approved" | "rejected"}`. Records the administrator's decision.
- `200` → `{"recId": "REC-1", "decision": "approved"}`

### 6. `POST /api/incidents/{id}/corrections`
Body: `{"recommendationId": "REC-1"}`. Saves a backup of the lab firewall table, then applies the recommendation. Only for an **approved** recommendation.
- `200` → `{"status": "applied", "recId": "REC-1"}`
- `409` → not approved, or another correction is already applied

### 7. `POST /api/incidents/{id}/corrections/{recId}/rollback`
Restores the backup taken before that recommendation was applied.
- `200` → `{"status": "rolled_back", "recId": "REC-1"}`

### 8. `POST /api/incidents/{id}/verifications/{checkId}`
Body: `{"recommendationId": "REC-1"}`. Runs one real check. The dashboard calls both checks in parallel, after lifting containment.
- `200` → `CheckResult` (a failed check is still `200`, with `status: "failed"`)
- `404` → unknown `checkId`
- Side effect: when a check fails, set the recommendation's `failDetail`.

**Call order the dashboard uses** (`workflow.js`):
```
GET incidents/active → POST containment → POST recommendations
→ POST decision(approved) → POST corrections → DELETE containment
→ POST verifications/unauthorized_blocked + POST verifications/legitimate_app (parallel)
→ all passed: done
→ any failed: POST containment (restore) → POST corrections/{recId}/rollback
             → POST recommendations {feedback: {type: "failed", ...}} → ...
Reject path: POST decision(rejected) → POST recommendations {feedback: {type: "rejected", version}}
```

---

## Endpoints added for real mode

Not called by the current dashboard; added in plan section 2.2.

### `GET /api/status`
```json
{
  "backend": "ok",
  "lab": "up",
  "app": "ok",
  "database": "ok",
  "aiMode": "mock",
  "aiModel": "Mock AI (scenario A)",
  "aiReachable": true,
  "incident": null
}
```
`lab`: `"up"`, `"down"` or `"error"`. `app`/`database`: `"ok"` or `"error"`. `incident`: open incident id or `null`. `aiReachable` checks `GET {OLLAMA_URL}/api/tags` in real mode, always `true` in mock mode.

### `POST /api/lab/attack`
Runs one connection attempt from the employee namespace to the database (no password). Returns immediately; detection happens in the background.
- `200` → `{"started": true, "reached": true}` (`reached`: whether the TCP connection got through)

### `POST /api/lab/reset`
Restores the vulnerable baseline: reloads the firewall table (rule-14 back, no temp block), zeroes the counter, clears incidents and recommendations.
- `200` → `{"status": "reset"}`

### Static files
`GET /` serves `dashboard/index.html`; `GET /css/...` and `GET /js/...` serve the dashboard's files.
