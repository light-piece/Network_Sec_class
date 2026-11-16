# AI-Assisted Firewall Misconfiguration Detection and Remediation

COMP 424 Computer System Security project · Sergio Macias and Isaac Lares

A simulated company network has a firewall mistake (**rule #14**) that lets a hacked employee workstation connect straight to the company database. The system detects the connection, temporarily blocks the attacker, asks a local AI model (qwen3:4b via Ollama) for a permanent fix, lets an administrator approve it, applies it, and verifies that the attacker is blocked **and** the company app still works. If verification fails it rolls back and the AI retries using the failed test results.

## Status

In development. See [`docs/STATUS.md`](docs/STATUS.md).

| Part | State |
|---|---|
| Dashboard (`dashboard/`) | Built; live mode with the backend, simulated mode on its own |
| Lab network (namespaces, nftables, PostgreSQL, Flask) | Built and tested |
| Backend API and AI (mock + Ollama) | Built and tested with the mock AI; real Ollama run pending |
| Install scripts | Built |

## Try the dashboard now (simulated data)

```
python3 -m http.server 8080 --directory dashboard
```
Open http://localhost:8080 and use **Simulate A** or **Simulate B** in the top bar.

## Running the full project (Ubuntu 24.04 VM, as root)

```
git clone https://github.com/light-piece/Network_Sec_class.git cybersec
cd cybersec
sudo ./scripts/install.sh      # packages, .venv, PostgreSQL, lab network; safe to rerun
nano .env                      # AI_MODE=ollama and OLLAMA_URL for the real model (default: mock AI)
sudo ./scripts/start.sh        # backend + dashboard on port 8000
```
Open `http://<VM IP>:8000`, click **Run attack**, approve the fix. **Reset lab** puts the vulnerable rule back.

Other scripts: `scripts/attack.sh`, `scripts/reset_lab.sh`, `scripts/teardown_lab.sh`. Mac and VM setup: [`docs/ISAAC_SETUP.md`](docs/ISAAC_SETUP.md). Network layout: [`docs/TOPOLOGY.md`](docs/TOPOLOGY.md).

## Tests

```
python3 -m pytest -q                 # unit tests, any OS
sudo tests/integration.sh            # real lab, Linux root
tests/api_flow.sh A                  # with the backend running (MOCK_AI_SCENARIO=A)
```

## Documents

| File | Contents |
|---|---|
| [`docs/DEVELOPMENT_PLAN.md`](docs/DEVELOPMENT_PLAN.md) | Full design and build plan |
| [`docs/API_CONTRACT.md`](docs/API_CONTRACT.md) | The HTTP API the dashboard calls |
| [`docs/LAB_INTERFACE.md`](docs/LAB_INTERFACE.md) | The functions the backend uses to control the lab |
| [`docs/STATUS.md`](docs/STATUS.md) | Progress log |
| [`docs/TOPOLOGY.md`](docs/TOPOLOGY.md) | Lab network layout |
| [`docs/AGENT_PROMPTS.md`](docs/AGENT_PROMPTS.md) | Prompts for the coding agents |
| [`docs/archive/`](docs/archive/) | Earlier planning (OPNsense design, Sept 2026), kept for reference |
