# Project instructions for coding agents

This repo is a COMP 424 cybersecurity project: an AI-assisted firewall misconfiguration detection and remediation demo.

## Read first, every session

1. `docs/DEVELOPMENT_PLAN.md`: the full plan. It is the source of truth.
2. `docs/STATUS.md`: what is done, what is in progress, and what is next. Start from here.
3. `docs/API_CONTRACT.md` and `docs/LAB_INTERFACE.md`, once they exist (created in milestone 1).

## Rules

- **Do not rebuild, redesign or rename the dashboard** in `dashboard/`. It is plain HTML/CSS/JS with no build step. Only the small edits listed in plan section 2.2 are allowed.
- **Implement the API the dashboard already calls** (`dashboard/js/api-service.js`), returning the shapes `dashboard/js/mock-service.js` returns. Don't invent new endpoint names for existing calls.
- **Never pass AI output to a shell.** AI returns validated actions (`backend/ai/models.py`); `backend/lab.py` turns them into fixed `nft` templates and is the only code that runs commands.
- **Shared contract files** (`backend/lab_types.py`, `backend/fake_lab.py`, `backend/ai/models.py`, `docs/API_CONTRACT.md`, `docs/LAB_INTERFACE.md`) are not edited on parallel branches. If one must change, say so in your PR.
- `docs/archive/` is an earlier design (OPNsense). Don't follow it.
- **There is no local Linux machine.** Linux behavior (namespaces, nftables, PostgreSQL, the lab) is only verified by **GitHub Actions**. Never report it as working without a passing run, and include the run URL.
- **Git:** never force-push, never rewrite `main` history, keep commits small. Work on your own branch when running in parallel (plan section 12) and only edit the files your agent row owns.
- **Keep scope small.** Plan section 13 lists what not to build.
- **Before ending a session, update `docs/STATUS.md`**: what you finished (with commit and CI links), what's in progress, blockers, and the exact next step.
