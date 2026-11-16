# AI-Assisted Firewall Misconfiguration Detection and Remediation

COMP 424 Computer System Security project · Sergio Macias and Isaac Lares

A simulated company network has a firewall mistake (**rule #14**) that lets a hacked employee workstation connect straight to the company database. The system detects the connection, temporarily blocks the attacker, asks a local AI model (qwen3:4b via Ollama) for a permanent fix, lets an administrator approve it, applies it, and verifies that the attacker is blocked **and** the company app still works. If verification fails it rolls back and the AI retries using the failed test results.

## Status

In development. See [`docs/STATUS.md`](docs/STATUS.md).

| Part | State |
|---|---|
| Dashboard (`dashboard/`) | Built; runs on simulated data |
| Lab network, backend, AI integration | In progress |
| Install scripts | In progress |

## Try the dashboard now (simulated data)

```
python3 -m http.server 8080 --directory dashboard
```
Open http://localhost:8080 and use **Simulate A** or **Simulate B** in the top bar.

## Running the full project

Instructions for the Ubuntu VM setup are in [`docs/ISAAC_SETUP.md`](docs/ISAAC_SETUP.md). They will be finalized here when the install scripts are done.

## Documents

| File | Contents |
|---|---|
| [`docs/DEVELOPMENT_PLAN.md`](docs/DEVELOPMENT_PLAN.md) | Full design and build plan |
| [`docs/API_CONTRACT.md`](docs/API_CONTRACT.md) | The HTTP API the dashboard calls |
| [`docs/LAB_INTERFACE.md`](docs/LAB_INTERFACE.md) | The functions the backend uses to control the lab |
| [`docs/STATUS.md`](docs/STATUS.md) | Progress log |
| [`docs/AGENT_PROMPTS.md`](docs/AGENT_PROMPTS.md) | Prompts for the coding agents |
| [`docs/archive/`](docs/archive/) | Earlier planning (OPNsense design, Sept 2026), kept for reference |
