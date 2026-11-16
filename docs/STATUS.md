# Project status

*Agents on `main` update this file at the end of every session. Parallel agents (A, B, C) put their status in their PR description; the integration agent copies it here. Newest log entries first.*

Repo: https://github.com/light-piece/Network_Sec_class (public)

## Current state

| Milestone | Owner | Status | Notes |
|---|---|---|---|
| 1 Repo and shared contracts | single agent | **Done, CI to confirm** | See log. Green CI run on `main` needed before step 2. |
| 2A Lab | agent A (`lab` branch) | **Next** | Start after milestone 1's CI is green |
| 2B Backend | agent B (`backend` branch) | **Next** | Can start immediately after 1 |
| 2C AI + dashboard | agent C (`ai-dashboard` branch) | **Next** | Can start immediately after 1 |
| 3 Integration | single agent on `main` | Not started | After A, B, C merged in that order |
| 4 Handoff | single agent on `main` | Not started | Then Isaac's first run |

## Known facts

- Dashboard: `dashboard/` (plain HTML/CSS/JS, mock mode works). `.claude/launch.json` serves it on port 8080.
- No local Linux VM: Linux is tested only in GitHub Actions (`ubuntu-24.04-arm`, free for public repos).
- Final demo machine: Isaac's Apple Silicon Mac, Ubuntu Server 24.04 ARM64 VM in UTM, Ollama with `qwen3:4b` on macOS.
- Check IDs are `unauthorized_blocked` and `legitimate_app` (from the dashboard), not the names in early drafts of the plan.
- A recommendation is 1–3 actions; the dashboard's four mock recommendations (`good`, `alt`, `flawed`, `fixed`) map to the action examples in `docs/LAB_INTERFACE.md`.

## Blockers

- None.

## Log

- **2026-11-15 · milestone 1.** Connected the project to GitHub. Moved Isaac's September OPNsense planning (AGENTS.md, CONTEXT.md, PDF, prototype, docs/agents) unchanged into `docs/archive/opnsense-plan-sep2026/`; new root `AGENTS.md` points to `CLAUDE.md`. Added `.gitignore`, README, `docs/API_CONTRACT.md`, `docs/LAB_INTERFACE.md`, `backend/lab_types.py`, `backend/fake_lab.py` (first-match rule evaluator), `backend/lab.py` (stub), `backend/ai/models.py`, `tests/test_models.py`, `tests/test_fake_lab.py` (22 tests, passing locally on Python 3.13), `requirements.txt`, `.github/workflows/ci.yml`. Plan updated: check IDs, multi-action recommendations, file ownership, dashboard fixes 6–8 (fake clock, error display, mock-only footnote), hard-coded text in `workflow.js`.
  - **Not yet verified:** the CI run (needs the first push). The `lab` job is a capability probe: namespaces, veth, nftables inside a namespace, conntrack, on the ARM runner.
- **2026-11-15 · plan finalized** (`docs/DEVELOPMENT_PLAN.md`).

## Next step

Push milestone 1, confirm both CI jobs are green, then start agents A, B and C (`docs/AGENT_PROMPTS.md`, Step 2).
