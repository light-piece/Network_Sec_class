# Lab topology

The lab is four Linux network namespaces on the Ubuntu VM, built by `scripts/setup_lab.sh`.
All names, addresses and ports come from `.env` (defaults from `.env.example` shown here).
The VM's own networking, firewall and system PostgreSQL are never touched: every lab
interface lives inside a lab namespace, and every lab firewall rule lives in table
`inet lab` inside the `router` namespace.

## Diagram

```
  root namespace (the VM): SSH, FastAPI backend :8000, Ollama access. Not wired to the lab;
  the backend reaches the lab only through `ip netns exec <ns> ...` (backend/lab.py).

   employee ns                      app ns                         db ns
   10.10.10.10/24                   10.10.20.10/24                 10.10.30.10/24
   "hacked workstation"             Flask company app :8080        PostgreSQL :5432 (lab cluster)
   lab0                             lab0                           lab0
     |  default via 10.10.10.1        |  default via 10.10.20.1      |  default via 10.10.30.1
     |  veth                          |  veth                        |  veth
   lab-emp 10.10.10.1/24 --------- lab-app 10.10.20.1/24 -------- lab-db 10.10.30.1/24
   +------------------------------------------------------------------------------------+
   |  router ns: net.ipv4.ip_forward=1                                                   |
   |  nftables table inet lab, chain forward (hook forward, policy drop)                 |
   |    [temp-block]  10.10.10.10 -> 10.10.30.10:5432 drop     (only while contained)    |
   |    est           ct state established,related accept                               |
   |    rule-10       10.10.10.0/24 -> 10.10.20.10:8080 accept                           |
   |    rule-12       10.10.20.10   -> 10.10.30.10:5432 accept                           |
   |    rule-14       10.10.10.0/24 -> 10.10.30.10:5432 counter accept   <- the mistake  |
   +------------------------------------------------------------------------------------+
```

## Addresses and interfaces

| Namespace | Interface | Address | Gateway | Runs |
|---|---|---|---|---|
| `employee` | `lab0` | `10.10.10.10/24` | `10.10.10.1` | nothing; attack and checks are launched here |
| `app` | `lab0` | `10.10.20.10/24` | `10.10.20.1` | Flask `company_app/app.py` on `:8080` (pidfile `/var/lib/cybersec-lab/flask.pid`) |
| `db` | `lab0` | `10.10.30.10/24` | `10.10.30.1` | PostgreSQL lab cluster on `:5432` (data `/var/lib/cybersec-lab/pgdata`) |
| `router` | `lab-emp`, `lab-app`, `lab-db` | `10.10.10.1`, `10.10.20.1`, `10.10.30.1` (/24) | none | forwarding + `inet lab` |

Every lab subnet is a /24 and the router is `.1` on it (derived from `EMPLOYEE_IP`, `APP_IP`, `DB_IP`).
Interface names are fixed (`lab0` in a leaf, `lab-<role>` in the router) and are created
directly inside their namespaces, so nothing appears in the root namespace even briefly.

Runtime state lives in `LAB_STATE_DIR` (default `/var/lib/cybersec-lab`), outside the repo:
`pgdata/` (cluster), `run/` (PostgreSQL socket), `logs/flask.log`, `logs/postgres.log`,
`baseline.rendered.nft` (the rendered firewall), `flask.pid`.

## Trust boundaries

| Zone | Trust | May reach |
|---|---|---|
| employee (10.10.10.0/24) | untrusted (assume compromised) | the app on 8080 only |
| app (10.10.20.10) | trusted service | the database on 5432 |
| db (10.10.30.10) | most sensitive | nothing (replies only) |

Policy: **only the app may reach the database.** `rule-14` breaks it by letting the whole
employee subnet open connections to PostgreSQL. PostgreSQL itself accepts `app_user` from
`10.10.0.0/16` with a password (`pg_hba.conf`), so the firewall, not the database, is what
decides who reaches it. The attacker never has the password; a password prompt is enough
to prove reachability.

## Traffic flows

| Flow | Path | Matched by | Baseline result |
|---|---|---|---|
| Employee uses the app | employee -> router -> app :8080 | `rule-10` | allowed |
| App reads the database | app -> router -> db :5432 | `rule-12` | allowed |
| Replies to both | reverse direction | `est` | allowed |
| **Attacker -> database** | employee -> router -> db :5432 | **`rule-14`** (counted) | **allowed (the bug)** |
| Anything else | | policy | dropped |

Because `est` is first, the `rule-14` counter counts only new connections; the backend's
detection polls it. `temp-block` is inserted above `est` so it also cuts replies on an
open connection (its conntrack entries are deleted at the same time). Rules added by a fix
with position `top` go directly after `est`.

The two verification checks use real traffic from the `employee` namespace:

- `unauthorized_blocked`: `pg_isready -h 10.10.30.10 -p 5432 -t 3`; passes on "no response" (exit 2).
- `legitimate_app`: `curl -s -m 5 http://10.10.20.10:8080/api/records`; passes on HTTP 200 with
  records, which proves employee -> app and app -> db both work.

## Inspecting the lab

```bash
sudo ip netns list                                         # router, employee, app, db
sudo ip netns exec router ip -br addr                      # lab-emp / lab-app / lab-db
sudo ip netns exec employee ip route                       # default via 10.10.10.1
sudo ip netns exec router nft -a list table inet lab       # rules with handles and the rule-14 counter
sudo ip netns exec router nft -j -a list chain inet lab forward   # what backend/lab.py parses
sudo ip netns exec router conntrack -L                     # tracked flows through the router
sudo ip netns exec employee curl -s http://10.10.20.10:8080/api/records | head -c 300
sudo ip netns exec employee pg_isready -h 10.10.30.10 -p 5432 -t 3
sudo ./scripts/attack.sh                                   # attacker tries PostgreSQL, prints REACHED/BLOCKED
sudo ip netns pids app                                     # the Flask process
sudo nft list tables                                       # host tables: the lab table is NOT here
```

## Scripts

| Script | Does |
|---|---|
| `scripts/install.sh` | packages, `.venv`, `.env`, then `setup_lab.sh` (`CI=1`: non-interactive defaults) |
| `scripts/setup_lab.sh` | builds or repairs everything above, loads the baseline, self-check |
| `scripts/reset_lab.sh` | baseline firewall, counter 0, no `temp-block`; `POST /api/lab/reset` if the backend runs |
| `scripts/attack.sh` | one PostgreSQL connection attempt from `employee` without a password |
| `scripts/teardown_lab.sh` | stops Flask and the lab PostgreSQL, deletes the namespaces (`--purge` also deletes `LAB_STATE_DIR`) |
| `scripts/start.sh` | `setup_lab.sh` if the lab is down, then the FastAPI backend |
