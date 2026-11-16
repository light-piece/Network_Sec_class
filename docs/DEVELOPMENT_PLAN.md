# Development Plan: AI-Assisted Firewall Misconfiguration Detection and Remediation

*Stripped-down showcase version. Hand this file to the coding agents; put it in the repo as `docs/DEVELOPMENT_PLAN.md`.*

---

## 1. Goal

Build a working showcase of one idea:

> A firewall misconfiguration (**rule #14**) lets a hacked employee workstation connect straight to the company database. The system **detects** it, **temporarily blocks** the attacker, asks a **local AI** for a permanent fix, lets an **admin approve** it, **applies** it, and **verifies** that the attacker is blocked *and* the company app still works. If verification fails, it **rolls back** and the AI **retries with the failed test results** as feedback.

The retry-with-feedback loop is the project's research question. It must be in the demo.

**Priority order:** working demo > reliability > reproducibility > polish. Avoid anything not needed for the demo.

---

## 2. What already exists (verified, not assumed)

The project lives at `~/cybersec/` on Sergio's Mac:

```
cybersec/
├── .claude/launch.json        # serves dashboard/ on port 8080 (python http.server)
└── dashboard/
    ├── index.html             # page shell: demo bar, app bar, empty <main>
    ├── README.md
    ├── css/styles.css
    └── js/
        ├── config.js          # USE_MOCK switch + API_BASE ('http://localhost:8000/api')
        ├── mock-service.js    # data contracts (shapes at top of file) + MockResponseService
        ├── api-service.js     # ApiResponseService: same methods, real fetch() calls
        ├── workflow.js        # incident state machine
        ├── view.js            # state -> HTML (no logic, no network)
        └── main.js            # wiring: picks service, re-renders, routes clicks
```

Facts the agents must respect:

- **Plain HTML/CSS/JavaScript. No framework, no build step, no npm.** Do not introduce one. FastAPI serves the `dashboard/` folder as static files.
- **Keep the folder name `dashboard/`.** Do not rename it to `frontend/`.
- **Git:** the repo is https://github.com/light-piece/Network_Sec_class (public). Milestone 1 connected `~/cybersec` to it.
- The dashboard's workflow is already built and must be preserved:
  `detect → contain (temporary block) → recommend (AI) → approve/reject → apply → lift block → verify (2 checks) → resolve`, or on failure `→ restore block → roll back → recommend again with feedback`.
- `mock-service.js` and `api-service.js` expose **the same nine methods**. `workflow.js` calls them and does not care which one is active.

### 2.1 The API contract is already defined: implement it, don't invent a new one

`js/api-service.js` calls these endpoints (relative to `API_BASE`). **The backend must implement exactly these paths**, returning the **same JSON shapes that `MockResponseService` returns** (read the shapes documented at the top of `mock-service.js` and the mock return values):

| Service method | HTTP call |
|---|---|
| `getActiveIncident()` | `GET /incidents/active` |
| `activateContainment(incidentId)` | `POST /incidents/{id}/containment` |
| `liftContainment(incidentId)` | `DELETE /incidents/{id}/containment` |
| `restoreContainment(incidentId)` | `POST /incidents/{id}/containment` |
| `requestRecommendation(incidentId, feedback)` | `POST /incidents/{id}/recommendations` body `{feedback}` |
| `submitDecision(recId, decision)` | `POST /recommendations/{recId}/decision` body `{decision}` |
| `applyCorrection(incidentId, rec)` | `POST /incidents/{id}/corrections` body `{recommendationId}` |
| `rollbackCorrection(incidentId, rec)` | `POST /incidents/{id}/corrections/{recId}/rollback` |
| `runCheck(incidentId, checkId, rec)` | `POST /incidents/{id}/verifications/{checkId}` body `{recommendationId}` |

Additional endpoints the backend may add (dashboard does not call them yet):

- `GET /status`: backend, lab, company app, database, AI mode and AI reachability
- `POST /lab/attack`: runs the attack from the employee namespace (demo trigger)
- `POST /lab/reset`: returns the lab to the vulnerable baseline

### 2.2 Known dashboard gaps to fix (small, targeted edits only)

1. **Hard-coded demo values in `view.js` and `workflow.js`**: about a dozen literal strings in `view.js` (`WS-FIN-042`, `10.20.0.42`, `DB-PRIMARY-01`, `APP-01`, `10.30.0.10`, `rule #14` text, "local model (simulated)") and the log messages in `workflow.js` (`WS-FIN-042 → DB-PRIMARY-01`, `Rule T-1`). Replace them with values from the incident (`source.name`, `source.ip`, `target.name`, `app.name`, `policy.ruleId`), the containment response (`ruleId`) and the recommendation (`model`). In mock mode the mock data supplies the same fields, so the text stays as it is today.
6. **Real timestamps.** `workflow.js` uses the fake clock `TCC.SIM_START`. In real mode use `incident.detectedAt` and `Date.now()`.
7. **Errors.** `api-service.js` throws on any non-2xx; `workflow.safely()` only logs to the console, so the screen freezes. Show the error's `detail` text in the incident card with a **Reset** option. No other UI change.
8. **Footnote** in `index.html` ("Demo mode — simulated data…"): show it only in mock mode.
2. **Starting an incident in real mode.** No background polling loop. The **Run attack** button calls `POST /lab/attack`, then calls the existing `workflow.start()`, whose first step is `getActiveIncident()`. The backend holds that request open (long-poll, up to 15 s) until the detector has created the incident, then returns it. This reuses the existing workflow unchanged.
3. **Demo bar** always shows "DEMO MODE, SIMULATED DATA" and the Simulate A/B buttons. In real mode, replace them with **Run attack** (`POST /lab/attack`) and **Reset lab** (`POST /lab/reset`), and show **AI: mock / AI: qwen3:4b** so the mode is always visible.
4. **`config.js`**: `API_BASE` should default to a relative `/api` so the dashboard works from whatever address FastAPI is served on.
5. Keep `USE_MOCK: true` working exactly as today (offline demo fallback).

**Do not add new panels** (network overview, firewall rule browser, system status page). The existing incident card already shows before/after rules. Only add what is listed above.

---

## 3. Target environment

### 3.1 Isaac's Mac (final demo machine, Apple Silicon, 24 GB)

- **UTM** running the Ubuntu VM
- **Ollama** on macOS (not inside the VM) with `qwen3:4b`
- Browser for the dashboard

### 3.2 Ubuntu VM

- Ubuntu Server **24.04 LTS ARM64**, 4 GB RAM, 2–4 vCPUs, 20 GB disk
- UTM network mode: **Shared Network**
- Everything below runs inside it

### 3.3 Development environment for the agents

**There is no local Linux VM.** Sergio's Mac does not have the disk space for one. The agents split the work like this:

| Where | What runs there |
|---|---|
| **Sergio's Mac (macOS)** | Editing code; Python unit tests (AI validation, API with the lab layer faked); the dashboard in `USE_MOCK: true` mode; `bash -n` syntax checks of the scripts |
| **GitHub Actions (Ubuntu 24.04 runners with sudo)** | **Everything that needs Linux:** `install.sh`, namespaces, nftables, PostgreSQL, Flask, the full backend, the integration tests and a dashboard smoke test |
| **Isaac's Mac** | The final real-AI run with Ollama and the demo |

The GitHub repository and the CI workflow (section 9A) are therefore built **first**, in milestone 1, because CI is the only place the lab can be tested. After milestone 1, three agents work in parallel (section 12). Only the lab agent depends on CI for its feedback; the backend and AI/dashboard agents test on the Mac against a fake lab.

Rules for agents:
- Never mark Linux behavior as working until a CI run has passed it. Quote the run URL when reporting.
- Keep pushes small, one change at a time, so a failing run points at one thing.
- If an agent cannot reach GitHub, it writes the code and tests, says plainly what is unverified, and does not report those tests as passing.

---

## 4. Lab network design (decided: implement this)

### 4.1 Topology

Four network namespaces. A dedicated **router namespace** holds the firewall, so lab rules never touch the VM's own networking (SSH, the dashboard, Ollama access).

```
        employee ns                app ns                  db ns
   10.10.10.10/24 (attacker)  10.10.20.10/24 (Flask)  10.10.30.10/24 (PostgreSQL)
            │                        │                        │
       veth pair                veth pair                veth pair
            │                        │                        │
            └────────────── router ns (10.10.x.1 on each side) ┘
                     ip_forward = 1, nftables table "inet lab"
```

| Namespace | Address | Runs |
|---|---|---|
| `employee` | `10.10.10.10/24`, gw `10.10.10.1` | nothing; used to launch the attack and checks |
| `app` | `10.10.20.10/24`, gw `10.10.20.1` | Flask company app on port **8080** |
| `db` | `10.10.30.10/24`, gw `10.10.30.1` | PostgreSQL lab instance on port **5432** |
| `router` | `10.10.10.1`, `10.10.20.1`, `10.10.30.1` | forwarding + nftables |

FastAPI runs in the **root namespace** of the VM (reachable from the Mac) and operates the lab with `ip netns exec <ns> …`.

All names and addresses come from configuration (section 8).

### 4.2 Firewall policy (nftables, table `inet lab`, chain `forward`, policy `drop`)

Each rule carries a stable ID in its `comment`. Look rules up by comment, never by handle number.

| ID | Rule | Purpose |
|---|---|---|
| `est` | `ct state established,related accept` | return traffic |
| `rule-10` | employee net → app `10.10.20.10` tcp **8080** accept | employees use the app |
| `rule-12` | app `10.10.20.10` → db `10.10.30.10` tcp **5432** accept | app reads the database |
| **`rule-14`** | **employee net `10.10.10.0/24` → db `10.10.30.10` tcp 5432 accept, with `counter`** | **the deliberate mistake** |
| (policy) | everything else dropped | default deny |

**Use this exact `lab/baseline.nft`** (addresses templated from `.env` by `setup_lab.sh`; values shown are the defaults). Load it inside the router namespace with `ip netns exec router nft -f lab/baseline.nft`. The first two lines make reloading idempotent and touch only the lab's own table:

```
add table inet lab
delete table inet lab
table inet lab {
  chain forward {
    type filter hook forward priority 0; policy drop;
    ct state established,related accept comment "est"
    ip saddr 10.10.10.0/24 ip daddr 10.10.20.10 tcp dport 8080 accept comment "rule-10"
    ip saddr 10.10.20.10 ip daddr 10.10.30.10 tcp dport 5432 accept comment "rule-12"
    ip saddr 10.10.10.0/24 ip daddr 10.10.30.10 tcp dport 5432 counter accept comment "rule-14"
  }
}
```

Because `est` comes first, the `rule-14` counter only counts **new** connections, which is exactly what detection needs. Enable forwarding with `ip netns exec router sysctl -w net.ipv4.ip_forward=1`, and bring `lo` up in every namespace.

Temporary block (inserted at the very top, above `est`, so it also stops replies on any open connection):
```
ip netns exec router nft insert rule inet lab forward ip saddr 10.10.10.10 ip daddr 10.10.30.10 tcp dport 5432 drop comment "temp-block"
ip netns exec router conntrack -D -s 10.10.10.10 -d 10.10.30.10   # ignore "0 flow entries" exit code
```
Rules are found by comment via `nft -j -a list chain inet lab forward` (gives handles), then deleted by handle.

### 4.3 Company app and database

- **PostgreSQL: run a private instance directly inside the `db` namespace.** Do **not** use or modify Ubuntu's system service/cluster (it can't bind to a namespace address, and fighting it wastes time). Exact approach:
  ```
  PGBIN=/usr/lib/postgresql/$(ls /usr/lib/postgresql | sort -V | tail -1)/bin   # version-independent
  LABDIR=/var/lib/cybersec-lab          # pgdata/, pg.log
  SOCKDIR=/var/run/cybersec-lab         # owned by postgres
  # once (skip if $LABDIR/pgdata exists):
  sudo -u postgres $PGBIN/initdb -D $LABDIR/pgdata --auth-local=peer --auth-host=scram-sha-256
  # pg_hba.conf: add  host company app_user 10.10.0.0/16 scram-sha-256
  # start (idempotent: skip if pg_ctl status says running):
  ip netns exec db sudo -u postgres $PGBIN/pg_ctl -D $LABDIR/pgdata -l $LABDIR/pg.log -w \
    -o "-c listen_addresses=10.10.30.10 -c port=5432 -c unix_socket_directories=$SOCKDIR" start
  # seed (idempotent SQL: CREATE ... IF NOT EXISTS, upsert rows):
  ip netns exec db sudo -u postgres psql -h $SOCKDIR -v ON_ERROR_STOP=1 -f lab/seed.sql
  ```
  Database `company`, table `records` with ~25 fake rows. Least-privileged role `app_user` (SELECT only; password from `.env`). The firewall, not PostgreSQL, is what blocks the attacker. On teardown: `pg_ctl stop -m fast`.
- **Flask** (`company_app/app.py`) in the `app` namespace on `10.10.20.10:8080`:
  - `GET /health` → `{"ok": true}`
  - `GET /api/records` → reads `records` from PostgreSQL and returns them (this is the "app still works" proof)
- The attacker is **never** given the database password.

---

## 5. Backend behavior (FastAPI)

One FastAPI app with small modules. No separate watcher, helper or test processes.

```
backend/
├── main.py          # app, routes, static dashboard, background poller            (B)
├── config.py        # settings from .env, validated at startup                     (B)
├── models.py        # Pydantic API models from docs/API_CONTRACT.md                (B)
├── detection.py     # rule-14 counter poller -> incidents                          (B)
├── workflow.py      # incidents, recommendations, apply/verify/rollback/retry      (B)
├── display.py       # Rule rows, before/after (dry run on a FakeLab copy), CheckResult text (B)
├── lab_types.py     # SHARED CONTRACT (milestone 1): types + LabControl protocol
├── fake_lab.py      # SHARED CONTRACT (milestone 1): in-memory reference lab
├── lab.py           # real lab: the ONLY code that runs commands, nft templates      (A)
└── ai/
    ├── models.py    # SHARED CONTRACT (milestone 1): AIRecommendation + actions
    ├── validate.py  # lab-specific checks; assigns AddDeny rule_id                  (C)
    ├── mock.py      # deterministic mock AI, scenarios A and B                      (C)
    └── ollama.py    # real AI client                                                (C)
```

Files marked SHARED CONTRACT were written in milestone 1. Change them only if all affected agents agree; record the change in `docs/STATUS.md`.

### 5.1 Detection

A background task reads the **packet counter on `rule-14`** (`ip netns exec router nft -j list chain inet lab forward`) every 2 seconds. If the counter increases and no incident is open, create an incident: source = attacker address (from config; there is one employee host), target = db address/port, matched rule = `rule-14`, timestamp. `GET /incidents/active` long-polls: it returns the open incident, or waits up to 15 s for one before returning `404`.

### 5.2 Temporary block (containment)

- **On:** insert at the top of `forward`: `ip saddr <attacker> ip daddr <db> tcp dport 5432 drop comment "temp-block"`, then clear existing tracked connections for that pair with `conntrack -D` inside the router namespace (existing connections must not survive the block).
- **Off:** delete the rule found by comment `temp-block`.
- It must block **only** attacker → database. Attacker → app keeps working.

### 5.3 AI recommendation: a small, closed set of actions

The AI never writes commands. It returns JSON matching `AIRecommendation` in `backend/ai/models.py` (written in milestone 1): **1–3 actions applied in order**, plus display text. Allowed actions:

| `action` | Fields | Effect |
|---|---|---|
| `set_rule_verdict` | `rule_id`, `verdict` (`accept`/`drop`) | change a rule's verdict |
| `delete_rule` | `rule_id` | remove a rule |
| `narrow_source` | `rule_id`, `source_cidr` | restrict a rule's source |
| `add_deny` | `source_cidr`, `dest_ip`, `dest_port` (5432/8080), `position` (`top`, `before:<rule_id>` or `after:<rule_id>`) | insert a drop rule |

Display text fields: `summary`, `change`, `affects`, `unaffected`, `what_changed` (these map directly to the dashboard's Recommendation fields).

**Validation** (`ai/validate.py`): every `rule_id` must exist in `lab.rules()` and may not be `temp-block`; CIDRs and IPs must be inside the lab ranges; ports 5432/8080 only; the validator assigns each `add_deny` a new `rule_id` that sorts into its position (e.g. `rule-11` before rule-12, `rule-13` after it). Failures are reported to the dashboard as an invalid recommendation. `lab.render()`/`lab.apply()` turn valid actions into `nft` commands from fixed templates (docs/LAB_INTERFACE.md). **Nothing from the AI is ever passed to a shell.**

The action set allows both a correct fix (e.g. `set_rule_verdict rule-14 drop`) and a plausible wrong one (e.g. `delete_rule rule-14` + `add_deny 10.0.0.0/8 → db before:rule-12`, which also blocks the app). That is what makes verification and retry meaningful. The dashboard's mock recommendations (`good`, `alt`, `flawed`, `fixed` in `mock-service.js`) are exactly these four cases.

**Before/after:** the backend copies `lab.rules()` into a `FakeLab`, applies the actions there (dry run), and turns both rule lists into the dashboard's Rule rows. `commands` = `lab.render(actions)`.

### 5.4 Apply, verify, roll back

1. On approval: save the current `inet lab` ruleset to a backup, apply the action.
2. Lift the temporary block (so only the permanent fix is tested).
3. Run both checks (section 5.5).
4. Both pass: incident resolved.
5. Any fail: put the temporary block back, restore the backup, mark the recommendation failed, and pass the failed check results as `feedback` to the next recommendation request (up to 3 attempts total).

### 5.5 The two checks (real traffic, not just a port probe)

| Check | How | Pass when |
|---|---|---|
| `unauthorized_blocked` | from `employee` ns: `pg_isready -h 10.10.30.10 -p 5432 -t 3` (PostgreSQL protocol-level) | **not** reachable |
| `legitimate_app` | from `employee` ns: `curl -s -m 5 http://10.10.20.10:8080/api/records` | HTTP 200 with records (proves app → db still works) |

The check IDs must be exactly these two strings: they are the dashboard's `TCC.CHECK_IDS`.

Return the evidence (command, exit code, short output) in the shape `runCheck` expects.

### 5.6 AI modes

- **Mock (`AI_MODE=mock`)**: no Ollama needed. `MOCK_AI_SCENARIO=A` returns the correct fix. `MOCK_AI_SCENARIO=B` returns the too-broad `add_deny` first and the correct fix when called with feedback. Only the AI is mocked; network, firewall and checks stay real.
- **Real (`AI_MODE=ollama`)**: use exactly this request (non-streaming chat, structured output, thinking off):
  ```
  POST {OLLAMA_URL}/api/chat
  {
    "model": "qwen3:4b",
    "stream": false,
    "think": false,
    "format": <Recommendation.model_json_schema() from ai/models.py>,
    "options": {"temperature": 0.2, "num_ctx": 4096},
    "messages": [
      {"role": "system", "content": "<policy: only the app may reach the database; the allowed actions and their fields; reply with JSON only>"},
      {"role": "user",   "content": "<incident JSON> + <current inet lab rules with IDs> + <feedback: failed check results, if any>"}
    ]
  }
  ```
  Parse `response["message"]["content"]` as JSON, then validate with Pydantic. Timeout 120 s. On invalid JSON or a schema failure, retry the call **once**, then report an invalid recommendation to the dashboard. Connection errors and timeouts are clear errors, never a crash. If the installed Ollama rejects `think`, drop it and append `/no_think` to the user message instead.

### 5.7 Privileges

For speed, the backend runs as **root** (it must run `ip netns` and `nft`). All command execution is confined to `lab.py`, using fixed argument lists (no `shell=True`) and only templates. Document this risk in the README. It is acceptable for a lab VM. Do not build a separate privileged service.

---

## 6. Scripts

All scripts are bash, idempotent (safe to rerun), and read `.env`.

| Script | Does |
|---|---|
| `scripts/install.sh` | Checks Ubuntu 24.04 ARM64; installs `git python3 python3-venv python3-pip nftables postgresql postgresql-client conntrack curl iproute2`; creates `.venv`; `pip install -r requirements.txt`; copies `.env.example` → `.env` if missing; creates the PostgreSQL lab cluster, role and seed data; runs `setup_lab.sh`; prints next steps. |
| `scripts/setup_lab.sh` | Creates namespaces, veths, addresses, routes; enables forwarding in `router`; loads `inet lab` with rule-14; starts PostgreSQL in `db` and Flask in `app`; runs a self-check (app works = yes, attacker reaches db = **yes**). |
| `scripts/reset_lab.sh` | Reloads the baseline ruleset (rule-14 back, no temp-block), zeroes the counter, clears backend incident state via `POST /api/lab/reset` if the backend is running, reruns the self-check. Touches only the lab's own namespaces, table and cluster. |
| `scripts/teardown_lab.sh` | Stops lab services, deletes the lab namespaces and `inet lab` table. |
| `scripts/attack.sh` | From `employee` ns, attempts a PostgreSQL connection to the db (no password; it only proves reachability). |
| `scripts/start.sh` | Runs `setup_lab.sh` if the lab is down, then starts FastAPI on `0.0.0.0:${APP_PORT}` serving `/api` and the `dashboard/` folder at `/`. |

---

## 7. Repository layout

```
cybersec/
├── dashboard/              # existing, keep in place
├── backend/                # section 5
├── company_app/app.py
├── lab/
│   ├── baseline.nft        # inet lab ruleset with rule-14 (templated from .env)
│   └── seed.sql
├── scripts/                # section 6
├── tests/
├── .github/workflows/ci.yml   # section 9A
├── docs/
│   ├── DEVELOPMENT_PLAN.md # this file
│   ├── TOPOLOGY.md
│   └── DEMO.md
├── requirements.txt        # fastapi, uvicorn[standard], flask, psycopg[binary], httpx, pydantic-settings, pytest
├── .env.example
├── .gitignore              # .venv/, __pycache__/, .env, *.log, .DS_Store, lab runtime dirs
└── README.md
```

---

## 8. Configuration (`.env.example`)

```
APP_HOST=0.0.0.0
APP_PORT=8000

AI_MODE=mock                 # mock | ollama
MOCK_AI_SCENARIO=A           # A = correct first try, B = wrong then fixed with feedback
OLLAMA_URL=http://192.168.64.1:11434   # UTM shared-network gateway = the Mac; confirm with `ip route` in the VM
OLLAMA_MODEL=qwen3:4b
OLLAMA_TIMEOUT=120

NS_EMPLOYEE=employee
NS_APP=app
NS_DB=db
NS_ROUTER=router
EMPLOYEE_IP=10.10.10.10
EMPLOYEE_NET=10.10.10.0/24
APP_IP=10.10.20.10
APP_SERVICE_PORT=8080
DB_IP=10.10.30.10
DB_PORT=5432

DB_NAME=company
DB_USER=app_user
DB_PASSWORD=change-me

POLL_INTERVAL_SECONDS=2
MAX_ATTEMPTS=3
LOG_LEVEL=INFO
```

Validated at startup (pydantic-settings). No machine-specific paths or Isaac-specific IPs in code.

---

## 9. Tests (keep it lean)

- **`tests/test_ai_validation.py`** (runs anywhere): valid actions accepted; bad rule IDs, out-of-range CIDRs, wrong ports, extra fields, shell-looking strings and malformed JSON rejected; the translator only ever produces template commands.
- **`tests/test_api_mock.py`** (runs anywhere): with the `lab.py` layer faked, every endpoint in 2.1 returns the shapes `mock-service.js` returns; scenario A and B flows complete.
- **`tests/integration.sh`** (GitHub Actions or Isaac's VM, sudo): setup → attacker reaches db → app works → containment blocks attacker but not app → apply correct fix → both checks pass → reset restores the hole. Then scenario B: wrong fix → app check fails → rollback restores the previous state. Run setup/reset 3× in a row.
- **Fresh-clone test:** every CI run *is* a fresh-clone test. The runner starts clean, runs `install.sh` from the README, then the tests.
- **`tests/api_flow.sh`** (CI): drives the full workflow over HTTP with `curl`, in the same order `workflow.js` calls it (attack → active incident → containment → recommendation → decision → correction → lift containment → both checks), for scenario A and scenario B. This replaces a browser test: the dashboard only renders what these responses contain. Also checks that `GET /` serves `dashboard/index.html`.

Report what was actually run, where. Never claim an Ubuntu test passed without a passing CI run.

---

## 9A. Continuous integration (GitHub Actions): the test machine

File: `.github/workflows/ci.yml`. Runs on every push and pull request, and manually (`workflow_dispatch`).

**Runner:** `ubuntu-24.04-arm` (matches Isaac's ARM64 VM; free for **public** repositories). If the repository is **private**, use `ubuntu-24.04` (x86) instead and note it in the README: the scripts must not depend on CPU architecture, so both should behave the same. Make the runner a single matrix value so it can be switched in one line.

**Job `unit`** (fast, runs first):
1. Checkout, set up Python 3.12, `pip install -r requirements.txt`
2. `pytest tests/test_ai_validation.py tests/test_api_mock.py`
3. `bash -n scripts/*.sh tests/*.sh` and `shellcheck` on the scripts

**Job `lab`** (needs `unit`):
1. Checkout
2. `sudo CI=1 ./scripts/install.sh`. With `CI=1` it is fully non-interactive and uses `.env.example` defaults (`AI_MODE=mock`). Note that GitHub's runners already have PostgreSQL installed but stopped, and Docker's firewall rules loaded; the installer must cope with both, which is also a good idempotency test.
3. `sudo ./scripts/install.sh` a **second time** (proves it is safe to rerun)
4. `sudo tests/integration.sh` (scenario A and B, setup/reset three times)
5. Start the backend in the background with `sudo ./scripts/start.sh &`, wait for `GET /api/status`
6. `tests/api_flow.sh` for `MOCK_AI_SCENARIO=A` and `B`
7. **Always** (pass or fail): dump `ip netns list`, `ip netns exec router nft list ruleset`, backend log, Flask log, PostgreSQL log, and upload them with `actions/upload-artifact`

**Speed settings:**
- Cache pip downloads (`actions/setup-python` with `cache: pip`).
- The `lab` job only runs when `scripts/`, `lab/`, `backend/`, `company_app/`, `tests/`, `requirements.txt` or `ci.yml` change (`paths` filter on push; always on `workflow_dispatch`). Dashboard-only or docs-only pushes run just the `unit` job.
- `concurrency` group per branch with `cancel-in-progress: true`, so a new push cancels an outdated run.

**Job `real-ai`** (manual only, `workflow_dispatch` with input `real_ai: true`; optional):
Install Ollama on the runner, `ollama pull qwen3:4b`, run the backend with `AI_MODE=ollama OLLAMA_URL=http://127.0.0.1:11434`, run scenario A once, and report whether the model's output validated and the fix passed. This gives an early read on the real model before Isaac's machine. It is slow (model download), so it only runs when asked.

**How agents use it:**
- Push a branch, then `gh run watch` to follow it and `gh run view --log-failed` to read failures.
- Make `integration.sh` print a clear `=== STEP n: ... ===` marker before each step, and stop at the first failure (`set -euo pipefail`), so logs point straight at the problem.
- For a problem the logs can't explain, temporarily add an interactive debugging step (for example `mxschmitt/action-tmate`, limited to the actor, removed afterward) to get a shell on the runner.
- Keep addresses in `.env` so a clash with the runner's own network can be fixed by configuration alone.

**Required repo settings:** Actions enabled. The agents need `gh` authenticated on Sergio's Mac (`gh auth login`) to create the repo, push and read run logs.

---

## 10. Isaac's setup (goes in the README)

**One time, on the Mac:**
1. Install UTM, download Ubuntu Server 24.04 **ARM64**, create the VM (4 GB / 2–4 CPU / 20 GB / Shared Network, tick "Install OpenSSH server").
2. Install Ollama, then `ollama pull qwen3:4b`.
3. `launchctl setenv OLLAMA_HOST "0.0.0.0"` and restart Ollama so the VM can reach it. To restore the default afterward: `launchctl unsetenv OLLAMA_HOST` and restart Ollama.

**In the VM:**
```
git clone <repo-url> cybersec && cd cybersec
sudo ./scripts/install.sh
nano .env                    # set AI_MODE=ollama, check OLLAMA_URL
sudo ./scripts/start.sh
```
Then open `http://<VM IP>:8000` on the Mac (`ip -4 addr` in the VM shows the address).

---

## 11. Demo script (~8 minutes, goes in `docs/DEMO.md`)

1. **Setup (1 min):** dashboard idle; explain the three zones and that rule-14 wrongly lets employees reach the database.
2. **Attack (1 min):** click **Run attack**. The incident appears and the temporary block turns on automatically.
3. **AI fix (1–2 min):** the AI recommendation appears with an explanation and a before/after rule view.
4. **Approve (1 min):** approve; the fix is applied and the temporary block lifted.
5. **Verify (1 min):** both checks pass: attacker blocked, app works.
6. **Retry with feedback (2 min):** reset, set `MOCK_AI_SCENARIO=B` (or rely on the real model's attempts): the first fix breaks the app, rollback happens, the AI gets the failed results and the second fix passes.
7. **Limitations (1 min):** a small simulated lab; the AI can still be wrong (hence human approval and verification); runs as root in a lab VM; no data theft shown, only reachability.
8. **Reset.**

---

## 12. Milestones (parallel after milestone 1)

**All development happens on Sergio's Mac and GitHub Actions.** Isaac does nothing until handoff: he installs the Mac prerequisites, clones the repo, runs the install script and does the demo run.

### How the work is split

Milestone 1 is done by **one agent** and creates the shared contracts. After that, **three agents work at the same time**, each in its own Git worktree and branch, so they never edit the same files:

```
cd ~/cybersec
git worktree add ../cybersec-lab     -b lab
git worktree add ../cybersec-backend -b backend
git worktree add ../cybersec-ai      -b ai-dashboard
# open one Claude Code session in each folder
```

| Agent | Branch | Owns (only edits these) | Tests where |
|---|---|---|---|
| **A: Lab** | `lab` | `scripts/`, `lab/`, `company_app/`, `tests/integration.sh`, `backend/lab.py`, `.env.example`, `ci.yml` `lab` job | GitHub Actions |
| **B: Backend** | `backend` | `backend/` files marked (B) in section 5, `tests/test_api_mock.py` | Mac (fake lab) |
| **C: AI + dashboard** | `ai-dashboard` | `backend/ai/` except `models.py`, `dashboard/` edits from 2.2, `tests/test_ai_validation.py` | Mac |

Nobody edits the SHARED CONTRACT files (`lab_types.py`, `fake_lab.py`, `ai/models.py`, `docs/API_CONTRACT.md`, `docs/LAB_INTERFACE.md`) on a parallel branch. If one needs to change, stop and say so in the PR.

Each agent opens a pull request into `main` when its part is green. Merge in the order **A, B, C**. The integration milestone then runs on `main`. The three worktree folders are small (source only) and can be deleted afterward with `git worktree remove`.

### Keeping sessions continuous

- `CLAUDE.md` (repo root) holds the standing rules; Claude Code reads it automatically.
- `docs/STATUS.md` is the shared progress log. Agents working on `main` update it at the end of every session. Parallel agents (A, B, C) put their status in their pull request description instead, to avoid merge conflicts; the integration agent copies it into `STATUS.md`.
- `docs/AGENT_PROMPTS.md` has the exact prompts for starting each step and for resuming.
- `docs/ISAAC_SETUP.md` is Isaac's setup guide; the README's install section must match it.

### Milestones

Commit after each verified step. Don't stop to ask between milestones unless credentials, a destructive action, or a real architectural blocker comes up.

| # | Milestone | Done when |
|---|---|---|
| 1 | **Repo and shared contracts. DONE 2026-11-15.** Existing work committed to the GitHub repo (Isaac's September OPNsense planning moved to `docs/archive/`). Written: `docs/API_CONTRACT.md`, `docs/LAB_INTERFACE.md`, `backend/lab_types.py`, `backend/fake_lab.py` (rule-evaluating reference lab), `backend/lab.py` (stub), `backend/ai/models.py`, unit tests, `ci.yml` (`unit` job + `lab` capability probe on `ubuntu-24.04-arm`). | Existing work on GitHub; contracts and stubs on `main`; first CI run green. |
| 2A | **Lab** (agent A). **DONE 2026-11-16.** `install.sh`, `setup_lab.sh`, `reset_lab.sh`, `teardown_lab.sh`, `attack.sh`, `baseline.nft`, `seed.sql`, `.env.example`, Flask app, real `lab.py` (all methods and templates in LAB_INTERFACE.md), `integration.sh`, `docs/TOPOLOGY.md`; replace the CI probe with the real `lab` job (9A). | In CI: install runs twice; the expected-outcomes table in LAB_INTERFACE.md holds against the real lab; reset repeatable. |
| 2B | **Backend** (agent B). **DONE 2026-11-16.** `config.py`, `models.py`, `detection.py`, `workflow.py`, `display.py`, `main.py`: every endpoint in API_CONTRACT.md including `/status`, `/lab/attack`, `/lab/reset`, long-poll, apply/verify/rollback/retry, static dashboard serving; `scripts/start.sh` is A's, so B documents the uvicorn command it needs. Tested against `FakeLab` and a stand-in AI that returns fixed `AIRecommendation`s. | `pytest` passes on the Mac; scenario A and B flows complete against `FakeLab` with responses matching API_CONTRACT.md. |
| 2C | **AI + dashboard** (agent C). **DONE 2026-11-16.** `ai/validate.py`, `ai/mock.py` (A = `good` then `alt`; B = `flawed` then `fixed`, matching `mock-service.js`), `ai/ollama.py` (5.6); dashboard edits 1–8 from 2.2. | `pytest` passes on the Mac; mock recommendations validate and give the expected outcomes on `FakeLab`; dashboard still works with `USE_MOCK: true`. |
| 3 | **Integration** (one agent, on `main` after merging A, B, C). **DONE 2026-11-16** (CI on GitHub to confirm). Wire real `lab.py` into the backend; `tests/api_flow.sh`; fix mismatches. | In CI: install, `integration.sh` and `api_flow.sh` (A and B) all pass on a clean runner. |
| 4 | **Handoff.** README (section 10), `docs/DEMO.md`; one manual `real-ai` CI run with its result reported honestly; final green run on `main`. | The README steps match exactly what CI runs. Isaac then installs and does the first run on his Mac. |

**Expected time:** milestone 1 a few hours; 2A/2B/2C in parallel about 1–1.5 days; integration about half a day; handoff a few hours. **About 2.5–3.5 days in total**, plus Isaac's first run.

---

## 13. Out of scope (do not build)

- Second laptop or Ethernet link (the attacker is the `employee` namespace)
- Log parsing (the rule counter replaces it)
- Separate watcher / rule-helper / test processes, or a dedicated service account
- Multiple firewall mistakes, the 30-run evaluation, SQLite run records
- New dashboard panels, a frontend framework, or a dashboard redesign
- Authentication for the dashboard (lab VM only; note it in limitations)
