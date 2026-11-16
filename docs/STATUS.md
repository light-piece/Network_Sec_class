# Project status

*Agents on `main` update this file at the end of every session. Newest log entries first.*

Repo: https://github.com/light-piece/Network_Sec_class (public)

## Current state

| Milestone | Status | Notes |
|---|---|---|
| 1 Repo and shared contracts | **Done** | CI green on GitHub (2026-11-16) |
| 2A Lab | **Done** | Verified in a root Linux container (x86_64); ARM runner pending CI |
| 2B Backend | **Done** | |
| 2C AI + dashboard | **Done** | |
| 3 Integration | **Done, CI to confirm** | Full flow verified against the real lab locally |
| 4 Handoff | **Next** | README run section, `docs/DEMO.md`, Isaac's first run with real Ollama |

## Verified (2026-11-16, Ubuntu 24.04 x86_64 container, root)

- `python3 -m pytest -q`: **128 passed** (schema, fake lab, validator, mock AI, Ollama client with mocked HTTP, full API against the fake lab).
- `CI=1 scripts/install.sh` twice: both runs clean; lab up; attacker reaches the database on the baseline.
- `tests/integration.sh`: **3 rounds passed**: the expected-outcomes table in `docs/LAB_INTERFACE.md` holds on the real lab, plus snapshot/restore, reset and counter.
- `tests/api_flow.sh A` and `B` against `scripts/start.sh` on the real lab: **both passed** (B: too-broad fix fails the app check → block restored → rollback → v2 with feedback passes).
- Dashboard in headless Chromium against the real lab: scenarios A and B reach **Resolved**; real evidence shown (pg_isready no response after ~3 s; HTTP 200 with 25 records).
- shellcheck clean; dashboard JS parses.

## Not yet verified

- GitHub Actions `lab` job on `ubuntu-24.04-arm` (needs the push).
- Real AI: qwen3:4b via Ollama has only been tested with mocked HTTP. First real run is on Isaac's Mac.

## Known behaviours

- `/api/lab/reset` (or `scripts/reset_lab.sh`) between demo runs: after a resolved incident, a new attack can open a new incident because rule-14's counter keeps counting dropped packets when the fix sets it to drop.
- `health()` and the checks take about 3 s when the database path is blocked (`pg_isready -t 3`); they are not on the 2 s poll.
- `add_deny` with position `top` is placed directly after `est` in the real lab; `FakeLab` puts it at index 0. Display order differs only while the temporary block is on.
- The real lab returns `/32` hosts as bare IPs (nft's format); FakeLab keeps `x/32`.
- Lab state lives in `/var/lib/cybersec-lab` (one lab per machine). Everything runs as root.

## Blockers

- None. Pushing from the cloud session is not possible (GitHub not linked to Claude); uploads go through a script Sergio double-clicks.

## Log

- **2026-11-16 · milestones 2 and 3.** Three agents built the lab (2A), the backend (2B) and the AI + dashboard work (2C) in parallel; merged into `main` in that order with no conflicts. Integration: backend uses the real AI factory and validator (stand-ins removed), real `Lab` gets DB settings, `tests/api_flow.sh` added, CI `lab` job now runs install twice, integration, and the API flow for A and B, then uploads diagnostics.
- **2026-11-15 · milestone 1.** Repo connected; September OPNsense planning archived; contracts, stubs, tests and CI added.
