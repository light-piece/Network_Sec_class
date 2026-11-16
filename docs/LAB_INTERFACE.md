# Lab interface

The contract between the **backend** (agent B) and the **lab** (agent A). The backend only talks to the lab through these methods. Code: `backend/lab_types.py` (types and the `LabControl` protocol), `backend/lab.py` (real, Linux), `backend/fake_lab.py` (in-memory, for tests).

`fake_lab.py` is the **reference behaviour**: for the same rules and actions, the real lab must produce the same pass/fail results.

## Topology (defaults; all from `.env`)

| Namespace | Address | Service |
|---|---|---|
| `employee` | 10.10.10.10/24 (net 10.10.10.0/24) | attacker / employee workstation |
| `app` | 10.10.20.10/24 | Flask on 8080 |
| `db` | 10.10.30.10/24 | PostgreSQL on 5432 |
| `router` | .1 on each subnet | forwarding + nftables `inet lab` |

## Firewall model

The forward chain, in order. `est` (established/related accept) is always first in the real chain and is **not** returned by `rules()`.

| `rule_id` (nft comment) | verdict | src | dst | dport | counter |
|---|---|---|---|---|---|
| `rule-10` | accept | employee net | app ip | 8080 | |
| `rule-12` | accept | app ip | db ip | 5432 | |
| `rule-14` | accept | employee net | db ip | 5432 | yes |
| *(policy)* | drop | | | | |

`temp-block` (drop, employee ip → db ip:5432) is inserted at the **very top**, above `est`, when containment is on.

## Methods

| Method | Must do | Returns |
|---|---|---|
| `health()` | Namespaces and `inet lab` exist; Flask `/health` answers; PostgreSQL accepts a connection from the app namespace | `LabHealth` |
| `rules()` | Current forward-chain rules in order, without `est`, including `temp-block` if present | `list[FirewallRule]` |
| `rule14_counter()` | Packet count on `rule-14` (0 if the rule is gone) | `int` |
| `block_on()` | Insert `temp-block` at the top and delete conntrack entries employee ip → db ip. Idempotent. | the `FirewallRule` |
| `block_off()` | Delete `temp-block`. Idempotent. | — |
| `block_active()` | Is `temp-block` present? | `bool` |
| `render(actions)` | The exact nft commands `apply()` would run, for display. No side effects. | `list[str]` |
| `apply(actions)` | Apply validated actions in order (see below) | — |
| `snapshot()` | Opaque text that `restore()` can reload (real lab: `nft list table inet lab`) | `str` |
| `restore(snapshot)` | Reload the table exactly as snapshotted | — |
| `check_unauthorized_blocked()` | From `employee`: `pg_isready -h <db> -p 5432 -t 3`. **passed = not reachable.** | `CheckOutcome` |
| `check_legitimate_app()` | From `employee`: `curl -s -m 5 http://<app>:8080/api/records`. **passed = HTTP 200 with records** (proves app → db works too). | `CheckOutcome` |
| `run_attack()` | From `employee`: one TCP connection attempt to db:5432 (no password). Counts on `rule-14` when allowed. | `AttackResult` |
| `reset()` | Reload `lab/baseline.nft` (rule-14 back, no temp-block, counter 0) | — |

All methods raise `LabError` with a readable message on failure.

## Actions → nftables templates

Actions come from `backend/ai/models.py`, already validated (rule exists, addresses inside the lab, `AddDeny.rule_id` assigned). The real lab renders them with these templates only (handles looked up by comment first):

| Action | Template |
|---|---|
| `set_rule_verdict(rule_id, v)` | `nft replace rule inet lab forward handle <h> <same match> [counter] <accept\|drop> comment "<rule_id>"` |
| `delete_rule(rule_id)` | `nft delete rule inet lab forward handle <h>` |
| `narrow_source(rule_id, cidr)` | `nft replace rule inet lab forward handle <h> ip saddr <cidr> <rest of match> <verdict> comment "<rule_id>"` |
| `add_deny(src, dst, port, position, rule_id)` | top: `nft insert rule inet lab forward position <handle of first rule after est> ...`; before X: `nft insert rule ... position <h of X> ...`; after X: `nft add rule ... position <h of X> ...`; body: `ip saddr <src> ip daddr <dst> tcp dport <port> drop comment "<rule_id>"` |

"top" means directly after `est`, so established replies still work; only `temp-block` sits above `est`.

## Expected outcomes (both labs)

| Situation | `check_unauthorized_blocked` | `check_legitimate_app` |
|---|---|---|
| Baseline | fail | pass |
| `temp-block` on | pass | pass |
| `set_rule_verdict rule-14 drop` | pass | pass |
| `delete_rule rule-14` | pass | pass |
| `delete_rule rule-14` + `add_deny 10.0.0.0/8 → db:5432 before:rule-12` | pass | **fail** |
| `delete_rule rule-14` + `add_deny 10.10.10.0/24 → db:5432 after:rule-12` | pass | pass |

`tests/test_fake_lab.py` checks this table against the fake. Agent A's `tests/integration.sh` must check the same table against the real lab in CI.
