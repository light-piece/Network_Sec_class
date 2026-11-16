# Prompts for starting agent sessions

Copy these into Claude Code. Replace the parts in **[brackets]**.

---

## Step 1: Milestone 1 (one agent) — DONE 2026-11-15

Kept for reference. Milestone 1 is complete; continue at Step 2 once its CI run is green.

Open Claude Code in `~/cybersec`:

```
cd ~/cybersec
claude
```

Send:

> Read `CLAUDE.md`, `docs/DEVELOPMENT_PLAN.md` and `docs/STATUS.md`.
>
> The GitHub repo already exists: **https://github.com/light-piece/Network_Sec_class** (**public**). Don't create a new one.
>
> Do milestone 1:
> 1. Give me a short summary of the existing project and any assumptions before changing anything.
> 2. Connect this folder to that repo over HTTPS. Check what's on GitHub first. If it has files (like a README), bring them in with `git pull origin main --allow-unrelated-histories` and keep both sides. Never force-push.
> 3. Add `.gitignore`, commit the existing work unchanged, push.
> 4. Create `docs/API_CONTRACT.md`, `docs/LAB_INTERFACE.md`, stub `backend/lab.py` and `backend/fake_lab.py`, and `backend/ai/models.py` as described in milestone 1.
> 5. Add `.github/workflows/ci.yml` (the `unit` job and a placeholder `lab` job) using the runner for a **public** repo.
> 6. Push and watch the run with `gh run watch`.
> 7. Update `docs/STATUS.md`.
>
> Stop when milestone 1 is done and CI is green. Send me the run link and a list of what you changed.

**Check before moving on:** the repo on GitHub has the dashboard and docs, and the Actions tab shows a green run.

---

## Step 2: Milestones 2A, 2B, 2C (three agents at once)

```
cd ~/cybersec
git pull
git worktree add ../cybersec-lab     -b lab
git worktree add ../cybersec-backend -b backend
git worktree add ../cybersec-ai      -b ai-dashboard
```

Open a separate Claude Code session in each folder (`cd ../cybersec-lab && claude`, and so on) and send:

> Read `CLAUDE.md`, `docs/DEVELOPMENT_PLAN.md` and `docs/STATUS.md`. You are **agent [A: Lab / B: Backend / C: AI + dashboard]**. Do milestone **[2A / 2B / 2C]** only, and edit only the files your row in section 12 owns. When the done-criteria pass, push your branch, open a pull request into `main` with `gh pr create`, and send me the PR link and test results (with CI run links for anything Linux). Don't edit `docs/STATUS.md` on your branch; put your status update in the PR description instead.

Agent A will take the longest because every Linux test is a GitHub run. B and C usually finish first.

**Check before moving on:** three open pull requests; A's shows green CI.

---

## Step 3: Merge, then milestones 3 and 4 (one agent)

Merge the pull requests on GitHub in the order **A, then B, then C** (if a later one has conflicts, ask its agent to rebase on `main` first). Then:

```
cd ~/cybersec
git checkout main && git pull
git worktree remove ../cybersec-lab
git worktree remove ../cybersec-backend
git worktree remove ../cybersec-ai
claude
```

Send:

> Read `CLAUDE.md`, `docs/DEVELOPMENT_PLAN.md` and `docs/STATUS.md`. The A, B and C pull requests are merged into `main`. Copy their status notes from the merged PR descriptions into `docs/STATUS.md`. Then do milestone 3 (integration) and, once CI is green, milestone 4 (handoff). Report CI run links for everything Linux. Update `docs/STATUS.md` when done.

**Done when:** `main` has a green CI run, the README matches `docs/ISAAC_SETUP.md`, and `STATUS.md` says ready for handoff.

---

## Resuming any time

If a session ends partway, start a new one in the same folder with:

> Read `CLAUDE.md`, `docs/DEVELOPMENT_PLAN.md` and `docs/STATUS.md`, check `git log` and the latest CI run, then continue from where the status says we stopped.

## After Isaac's first run

If something fails on his Mac, paste his error or logs into a session on `main`:

> Isaac ran the project on his Mac and got this: **[paste]**. Find the cause, fix it, confirm CI is green, push, and update `docs/STATUS.md` with what changed and whether he needs to rerun `install.sh`.
