"""Real lab control: the ONLY module that runs system commands.

Rules this implementation follows:
- Commands run with ``subprocess.run([...], shell=False, timeout=...)`` and fixed
  argument lists. No shell strings; no AI text ever reaches a command.
- nftables commands come only from the templates below (docs/LAB_INTERFACE.md)
  and the baseline file ``lab/baseline.nft``. Values come from validated
  ``Action`` objects (typed IPs/networks, literal ports, regex-checked rule IDs)
  and ``LabAddresses``, and are re-checked here before use.
- Firewall work happens in the router namespace:
  ``ip netns exec <router> nft ...`` on table ``inet lab``, chain ``forward``.
- Rules are found by their comment (``rule-14``, ``temp-block``) using
  ``nft -j -a list chain inet lab forward``, then changed by handle.
- Failures raise ``LabError`` with a readable message.

The process must run as root (it uses ``ip netns exec``); see plan section 5.7.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, replace
from ipaddress import ip_network
from pathlib import Path
from typing import Mapping, Optional, Sequence

from pydantic import TypeAdapter

from backend.ai.models import Action, AddDeny, DeleteRule, NarrowSource, SetRuleVerdict
from backend.lab_types import (
    AttackResult,
    CheckOutcome,
    FirewallRule,
    LabAddresses,
    LabError,
    LabHealth,
)

TABLE = ("inet", "lab")
CHAIN = "forward"
EST = "est"
TEMP_BLOCK = "temp-block"
REPO_DIR = Path(__file__).resolve().parent.parent

_RULE_ID_RE = re.compile(r"^rule-\d{1,3}$")
_POSITION_RE = re.compile(r"^(top|(before|after):(rule-\d{1,3}))$")
_ACTIONS = TypeAdapter(list[Action])
def _env(extra: Optional[Mapping[str, str]] = None, minimal: bool = False) -> dict[str, str]:
    """Environment for commands, with the sbin directories (ip, nft, conntrack) on PATH."""
    path = [p for p in os.environ.get("PATH", "").split(":") if p]
    for p in ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"):
        if p not in path:
            path.append(p)
    env = {"PATH": ":".join(path), "LANG": "C", "LC_ALL": "C"} if minimal else dict(os.environ, PATH=":".join(path))
    if extra:
        env.update(extra)
    return env


def _short(text: str, limit: int = 300) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


@dataclass
class _NftRule:
    """One rule of the forward chain as nftables reports it."""
    handle: Optional[int]          # None only in render()'s simulation, for rules not yet added
    comment: Optional[str]
    verdict: Optional[str] = None  # "accept" / "drop"
    src: Optional[str] = None
    dst: Optional[str] = None
    dport: Optional[int] = None
    has_counter: bool = False
    packets: int = 0
    simple: bool = True            # only ip saddr/daddr, tcp dport, counter, verdict

    def match_args(self) -> list[str]:
        args: list[str] = []
        if self.src:
            args += ["ip", "saddr", self.src]
        if self.dst:
            args += ["ip", "daddr", self.dst]
        if self.dport is not None:
            args += ["tcp", "dport", str(self.dport)]
        return args

    def to_firewall_rule(self) -> FirewallRule:
        return FirewallRule(
            rule_id=self.comment or f"handle-{self.handle}",
            verdict=self.verdict or "accept",  # type: ignore[arg-type]
            src=self.src, dst=self.dst, dport=self.dport,
            counter=self.packets if self.has_counter else None,
        )


def _parse_rule(r: dict) -> _NftRule:
    rule = _NftRule(handle=r.get("handle"), comment=r.get("comment"))
    for e in r.get("expr", []):
        if "match" in e:
            m = e["match"]
            payload = m.get("left", {}).get("payload") if isinstance(m.get("left"), dict) else None
            right = m.get("right")
            if m.get("op") != "==" or not payload:
                rule.simple = False
                continue
            key = (payload.get("protocol"), payload.get("field"))
            if isinstance(right, dict) and "prefix" in right:
                p = right["prefix"]
                value = f"{p['addr']}/{p['len']}"
            else:
                value = right
            if key == ("ip", "saddr") and isinstance(value, str):
                rule.src = value
            elif key == ("ip", "daddr") and isinstance(value, str):
                rule.dst = value
            elif key == ("tcp", "dport") and isinstance(value, int):
                rule.dport = value
            else:
                rule.simple = False
        elif "counter" in e:
            rule.has_counter = True
            c = e["counter"]
            rule.packets = int(c.get("packets", 0)) if isinstance(c, dict) else 0
        elif "accept" in e:
            rule.verdict = "accept"
        elif "drop" in e:
            rule.verdict = "drop"
        else:
            rule.simple = False
    return rule


class Lab:
    """The real lab: four network namespaces and nftables table ``inet lab`` in the router."""

    def __init__(self, addresses: LabAddresses | None = None,
                 router_ns: str = "router", employee_ns: str = "employee",
                 app_ns: str = "app", db_ns: str = "db",
                 repo_dir: str | Path | None = None,
                 db_name: str = "company", db_user: str = "app_user",
                 command_timeout: float = 20.0) -> None:
        self.addresses = addresses or LabAddresses()
        self.router_ns, self.employee_ns, self.app_ns, self.db_ns = router_ns, employee_ns, app_ns, db_ns
        self.repo_dir = Path(repo_dir) if repo_dir else REPO_DIR
        self.baseline_path = self.repo_dir / "lab" / "baseline.nft"
        self.db_name, self.db_user = db_name, db_user
        self.command_timeout = command_timeout
        for name in (router_ns, employee_ns, app_ns, db_ns):
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
                raise LabError(f"invalid namespace name {name!r}")

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None, repo_dir: str | Path | None = None) -> "Lab":
        """Build a Lab from .env-style keys (plan section 8): ``env`` if given, else
        the process environment, then ``.env``, then ``.env.example`` in the repo."""
        repo = Path(repo_dir) if repo_dir else REPO_DIR
        values: dict[str, str] = {}
        for f in (repo / ".env.example", repo / ".env"):
            values.update(_read_env_file(f))
        values.update(env if env is not None else os.environ)
        g = values.get
        emp_ip, app_ip, db_ip = g("EMPLOYEE_IP", "10.10.10.10"), g("APP_IP", "10.10.20.10"), g("DB_IP", "10.10.30.10")
        addresses = LabAddresses(
            employee_ip=emp_ip,
            employee_net=g("EMPLOYEE_NET", "10.10.10.0/24"),
            app_ip=app_ip,
            app_net=str(ip_network(f"{app_ip}/24", strict=False)),
            app_port=int(g("APP_SERVICE_PORT", "8080")),
            db_ip=db_ip,
            db_net=str(ip_network(f"{db_ip}/24", strict=False)),
            db_port=int(g("DB_PORT", "5432")),
        )
        return cls(addresses, router_ns=g("NS_ROUTER", "router"), employee_ns=g("NS_EMPLOYEE", "employee"),
                   app_ns=g("NS_APP", "app"), db_ns=g("NS_DB", "db"), repo_dir=repo,
                   db_name=g("DB_NAME", "company"), db_user=g("DB_USER", "app_user"))

    # ---- command running ----------------------------------------------------
    def _run(self, args: Sequence[str], *, what: str, check: bool = True, timeout: Optional[float] = None,
             stdin: Optional[str] = None, env: Optional[dict[str, str]] = None) -> subprocess.CompletedProcess:
        try:
            proc = subprocess.run(list(args), shell=False, capture_output=True, text=True,
                                  timeout=timeout or self.command_timeout, input=stdin,
                                  env=env or _env())
        except FileNotFoundError as exc:
            raise LabError(f"{what}: command not found ({exc.filename}). Is the lab installed?") from exc
        except subprocess.TimeoutExpired as exc:
            raise LabError(f"{what}: timed out after {exc.timeout:.0f} s") from exc
        except OSError as exc:
            raise LabError(f"{what}: {exc}") from exc
        if check and proc.returncode != 0:
            msg = _short(proc.stderr or proc.stdout or "", 400)
            if "Operation not permitted" in msg or "Permission denied" in msg:
                msg += " (the backend must run as root)"
            raise LabError(f"{what} failed (exit {proc.returncode}): {msg}")
        return proc

    def _ns(self, ns: str, *args: str) -> list[str]:
        return ["ip", "netns", "exec", ns, *args]

    def _nft(self, *args: str, what: str, check: bool = True, stdin: Optional[str] = None) -> subprocess.CompletedProcess:
        return self._run(self._ns(self.router_ns, "nft", *args), what=what, check=check, stdin=stdin)

    # ---- reading the chain ----------------------------------------------------
    def _chain(self) -> list[_NftRule]:
        proc = self._nft("-j", "-a", "list", "chain", *TABLE, CHAIN, what="reading the lab firewall")
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise LabError(f"could not parse nft JSON output: {exc}") from exc
        return [_parse_rule(item["rule"]) for item in data.get("nftables", []) if "rule" in item]

    @staticmethod
    def _find(chain: list[_NftRule], rule_id: str) -> Optional[_NftRule]:
        return next((r for r in chain if r.comment == rule_id), None)

    # ---- inspection -----------------------------------------------------------
    def health(self) -> LabHealth:
        a = self.addresses
        problems: list[str] = []
        try:
            listed = self._run(["ip", "netns", "list"], what="listing namespaces").stdout
        except LabError as exc:
            return LabHealth(up=False, app_ok=False, db_ok=False, detail=str(exc))
        present = {line.split()[0] for line in listed.splitlines() if line.strip()}
        missing = [ns for ns in (self.router_ns, self.employee_ns, self.app_ns, self.db_ns) if ns not in present]
        if missing:
            return LabHealth(up=False, app_ok=False, db_ok=False,
                             detail=f"lab namespaces missing: {', '.join(missing)} (run scripts/setup_lab.sh)")
        table = self._nft("list", "table", *TABLE, what="checking the firewall table", check=False)
        up = table.returncode == 0
        if not up:
            problems.append("nftables table inet lab is missing")
        app = self._run(self._ns(self.app_ns, "curl", "-fsS", "-m", "3", "-o", "/dev/null",
                                 f"http://{a.app_ip}:{a.app_port}/health"),
                        what="checking the company app", check=False)
        app_ok = app.returncode == 0
        if not app_ok:
            problems.append(f"company app /health not answering (curl exit {app.returncode})")
        db = self._run(self._ns(self.app_ns, "pg_isready", "-h", a.db_ip, "-p", str(a.db_port), "-t", "3"),
                       what="checking PostgreSQL", check=False)
        db_ok = db.returncode == 0
        if not db_ok:
            problems.append(f"PostgreSQL not accepting connections from the app ({_short(db.stdout or db.stderr, 120)})")
        return LabHealth(up=up, app_ok=app_ok, db_ok=db_ok, detail="; ".join(problems) or "lab ok")

    def rules(self) -> list[FirewallRule]:
        return [r.to_firewall_rule() for r in self._chain() if r.comment != EST]

    def rule14_counter(self) -> int:
        r = self._find(self._chain(), "rule-14")
        return r.packets if r and r.has_counter else 0

    # ---- temporary block --------------------------------------------------------
    def _temp_block_rule(self) -> FirewallRule:
        a = self.addresses
        return FirewallRule(TEMP_BLOCK, "drop", a.employee_ip, a.db_ip, a.db_port)

    def block_on(self) -> FirewallRule:
        a = self.addresses
        existing = self._find(self._chain(), TEMP_BLOCK)
        if existing is None:
            # `insert` without a position puts it first: above `est`, so it also
            # stops replies on any connection that is already open.
            self._nft("insert", "rule", *TABLE, CHAIN, "ip", "saddr", a.employee_ip, "ip", "daddr", a.db_ip,
                      "tcp", "dport", str(a.db_port), "drop", "comment", f'"{TEMP_BLOCK}"',
                      what="inserting the temporary block")
        # Existing tracked connections must not survive the block.
        ct = self._run(self._ns(self.router_ns, "conntrack", "-D", "-s", a.employee_ip, "-d", a.db_ip),
                       what="clearing tracked attacker connections", check=False)
        if ct.returncode not in (0, 1):  # 1 = "0 flow entries have been deleted"
            raise LabError(f"clearing tracked attacker connections failed: {_short(ct.stderr)}")
        rule = self._find(self._chain(), TEMP_BLOCK)
        return rule.to_firewall_rule() if rule else self._temp_block_rule()

    def block_off(self) -> None:
        for r in self._chain():
            if r.comment == TEMP_BLOCK:
                self._nft("delete", "rule", *TABLE, CHAIN, "handle", str(r.handle),
                          what="removing the temporary block")

    def block_active(self) -> bool:
        return self._find(self._chain(), TEMP_BLOCK) is not None

    # ---- corrections: templates ---------------------------------------------------
    @staticmethod
    def _check_rule_id(rule_id: Optional[str]) -> str:
        if not rule_id or not _RULE_ID_RE.fullmatch(rule_id):
            raise LabError(f"invalid rule id {rule_id!r} (expected rule-N)")
        return rule_id

    def _editable(self, chain: list[_NftRule], rule_id: str) -> _NftRule:
        self._check_rule_id(rule_id)
        r = self._find(chain, rule_id)
        if r is None:
            raise LabError(f"rule {rule_id} not found in the firewall")
        if not r.simple or r.verdict is None:
            raise LabError(f"rule {rule_id} has a form the lab templates cannot rewrite")
        return r

    @staticmethod
    def _handle_ref(r: _NftRule) -> str:
        return str(r.handle) if r.handle is not None else f"<handle of {r.comment}>"

    def _command_for(self, chain: list[_NftRule], act: Action) -> tuple[list[str], list[_NftRule]]:
        """nft arguments (after ``nft``) for one action against ``chain``, and the chain
        as it will look afterwards (used to render multi-action sequences)."""
        base = [*TABLE, CHAIN]
        new_chain = list(chain)
        if isinstance(act, SetRuleVerdict):
            r = self._editable(chain, act.rule_id)
            if act.verdict not in ("accept", "drop"):
                raise LabError(f"invalid verdict {act.verdict!r}")
            args = ["replace", "rule", *base, "handle", self._handle_ref(r), *r.match_args(),
                    *(["counter"] if r.has_counter else []), act.verdict, "comment", f'"{act.rule_id}"']
            new_chain[chain.index(r)] = replace(r, verdict=act.verdict, packets=0)
        elif isinstance(act, DeleteRule):
            r = self._editable(chain, act.rule_id)
            args = ["delete", "rule", *base, "handle", self._handle_ref(r)]
            new_chain.remove(r)
        elif isinstance(act, NarrowSource):
            r = self._editable(chain, act.rule_id)
            src = str(ip_network(str(act.source_cidr)))
            narrowed = replace(r, src=src, packets=0)
            args = ["replace", "rule", *base, "handle", self._handle_ref(r), *narrowed.match_args(),
                    *(["counter"] if r.has_counter else []), str(r.verdict), "comment", f'"{act.rule_id}"']
            new_chain[chain.index(r)] = narrowed
        elif isinstance(act, AddDeny):
            rule_id = self._check_rule_id(act.rule_id)
            if self._find(chain, rule_id):
                raise LabError(f"rule {rule_id} already exists")
            if act.dest_port not in (5432, 8080):
                raise LabError(f"port {act.dest_port} is not allowed")
            src = str(ip_network(str(act.source_cidr)))
            body = ["ip", "saddr", src, "ip", "daddr", str(act.dest_ip), "tcp", "dport", str(int(act.dest_port)),
                    "drop", "comment", f'"{rule_id}"']
            new = _NftRule(handle=None, comment=rule_id, verdict="drop", src=src, dst=str(act.dest_ip),
                           dport=int(act.dest_port))
            m = _POSITION_RE.fullmatch(act.position)
            if not m:
                raise LabError(f"invalid position {act.position!r}")
            if m.group(1) == "top":
                est = self._find(chain, EST)
                start = chain.index(est) + 1 if est else 0
                after_est = [r for r in chain[start:] if r.comment != TEMP_BLOCK]
                if after_est:
                    anchor = after_est[0]
                    args = ["insert", "rule", *base, "position", self._handle_ref(anchor), *body]
                    new_chain.insert(chain.index(anchor), new)
                elif est:
                    args = ["add", "rule", *base, "position", self._handle_ref(est), *body]
                    new_chain.insert(chain.index(est) + 1, new)
                else:
                    args = ["add", "rule", *base, *body]
                    new_chain.append(new)
            else:
                where, target_id = m.group(2), m.group(3)
                target = self._find(chain, target_id)
                if target is None:
                    raise LabError(f"position refers to missing rule {target_id}")
                if where == "before":
                    args = ["insert", "rule", *base, "position", self._handle_ref(target), *body]
                    new_chain.insert(chain.index(target), new)
                else:
                    args = ["add", "rule", *base, "position", self._handle_ref(target), *body]
                    new_chain.insert(chain.index(target) + 1, new)
        else:
            raise LabError(f"unknown action {act!r}")
        return args, new_chain

    @staticmethod
    def _coerce(actions: Sequence) -> list:
        if any(isinstance(a, dict) for a in actions):
            return _ACTIONS.validate_python(list(actions))
        return list(actions)

    def render(self, actions: list[Action]) -> list[str]:
        chain = self._chain()
        out = []
        for act in self._coerce(actions):
            args, chain = self._command_for(chain, act)
            out.append("nft " + " ".join(args))
        return out

    def apply(self, actions: list[Action]) -> None:
        """Apply actions in order. All or nothing: on any failure the table is
        restored to how it was before the call, and LabError is raised."""
        actions = self._coerce(actions)
        before = self.snapshot()
        done = 0
        try:
            for act in actions:
                args, _ = self._command_for(self._chain(), act)  # fresh handles for every step
                self._nft(*args, what=f"applying {act.action} ({'nft ' + ' '.join(args)})")
                done += 1
        except LabError as exc:
            try:
                self.restore(before)
                note = "the firewall was restored to its previous state"
            except LabError as exc2:
                note = f"restoring the previous firewall ALSO failed: {exc2}"
            raise LabError(f"{exc} (step {done + 1} of {len(actions)}; {note})") from exc

    # ---- snapshot / restore -------------------------------------------------------
    def snapshot(self) -> str:
        return self._nft("list", "table", *TABLE, what="saving the firewall").stdout

    def restore(self, snapshot: str) -> None:
        text = snapshot.strip()
        if not text.startswith("table inet lab {") or len(re.findall(r"(?m)^\s*table\s", text)) != 1:
            raise LabError("not a snapshot of table inet lab")
        # Replace the table in one atomic transaction (`add` makes the `delete` safe).
        self._nft("-f", "-", what="restoring the firewall",
                  stdin=f"add table inet lab\ndelete table inet lab\n{text}\n")

    # ---- checks -------------------------------------------------------------------
    def check_unauthorized_blocked(self) -> CheckOutcome:
        a = self.addresses
        args = ["pg_isready", "-h", a.db_ip, "-p", str(a.db_port), "-t", "3"]
        t0 = time.monotonic()
        proc = self._run(self._ns(self.employee_ns, *args), what="unauthorized_blocked check",
                         check=False, timeout=15)
        ms = int((time.monotonic() - t0) * 1000)
        out = _short(proc.stdout or proc.stderr or "", 200)
        # pg_isready: 0 accepting, 1 rejecting (still reachable), 2 no response, 3 bad arguments.
        if proc.returncode not in (0, 1, 2):
            raise LabError(f"pg_isready could not run (exit {proc.returncode}): {out}")
        return CheckOutcome(passed=proc.returncode == 2, command=" ".join(args) + f" (from {self.employee_ns})",
                            exit_code=proc.returncode, output=out, duration_ms=ms)

    def check_legitimate_app(self) -> CheckOutcome:
        a = self.addresses
        url = f"http://{a.app_ip}:{a.app_port}/api/records"
        args = ["curl", "-s", "-m", "5", "-w", "\n%{http_code}", url]
        t0 = time.monotonic()
        proc = self._run(self._ns(self.employee_ns, *args), what="legitimate_app check", check=False, timeout=15)
        ms = int((time.monotonic() - t0) * 1000)
        body, _, code = proc.stdout.rpartition("\n")
        passed = False
        if proc.returncode != 0:
            out = f"no response from the app (curl exit {proc.returncode})"
        else:
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                data = None
            if code == "200" and isinstance(data, dict) and isinstance(data.get("records"), list) and data["records"]:
                passed = True
                out = f"HTTP 200 · {len(data['records'])} records"
            elif isinstance(data, dict) and data.get("error"):
                out = f"HTTP {code} · {_short(str(data['error']), 160)}"
            else:
                out = f"HTTP {code} · {_short(body, 160)}"
        return CheckOutcome(passed=passed, command=f"curl -s -m 5 {url} (from {self.employee_ns})",
                            exit_code=proc.returncode, output=out, duration_ms=ms)

    # ---- demo ---------------------------------------------------------------------
    def run_attack(self) -> AttackResult:
        """One PostgreSQL connection attempt from the employee namespace, without a
        password. A password request from the server proves the database is reachable."""
        a = self.addresses
        conninfo = (f"host={a.db_ip} port={a.db_port} dbname={self.db_name} user={self.db_user} "
                    "connect_timeout=3 sslmode=disable gssencmode=disable")
        args = ["psql", "-X", "-w", conninfo, "-c", "SELECT 1"]
        proc = self._run(self._ns(self.employee_ns, *args), what="attack", check=False, timeout=15,
                         env=_env({"PGPASSFILE": "/nonexistent/pgpass"}, minimal=True))
        text = _short((proc.stderr or "") + " " + (proc.stdout or ""), 240)
        reached = proc.returncode == 0 or bool(re.search(r"password|authentication|pg_hba", text, re.I))
        if proc.returncode not in (0, 1, 2):
            raise LabError(f"attack command could not run (exit {proc.returncode}): {text}")
        summary = ("database answered (asked for a password): reachable" if reached
                   else "no answer from the database: blocked")
        return AttackResult(reached=reached,
                            command=f"psql -h {a.db_ip} -p {a.db_port} -U {self.db_user} (from {self.employee_ns}, no password)",
                            output=f"{summary} · {text}")

    def reset(self) -> None:
        a = self.addresses
        try:
            template = self.baseline_path.read_text()
        except OSError as exc:
            raise LabError(f"cannot read {self.baseline_path}: {exc}") from exc
        text = template
        for key, value in {"EMPLOYEE_NET": a.employee_net, "APP_IP": a.app_ip, "APP_SERVICE_PORT": str(a.app_port),
                           "DB_IP": a.db_ip, "DB_PORT": str(a.db_port)}.items():
            text = text.replace("${" + key + "}", value)
        if "${" in text:
            raise LabError("lab/baseline.nft has a placeholder the lab does not know")
        self._nft("-f", "-", what="reloading the baseline firewall", stdin=text)
        # No tracked flows from before the reset (conntrack is per namespace: router only).
        self._run(self._ns(self.router_ns, "conntrack", "-F"), what="flushing tracked connections", check=False)


def _read_env_file(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return out
    for line in lines:
        m = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$", line)
        if not m:
            continue
        value = re.split(r"\s+#", m.group(2), maxsplit=1)[0].strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        out[m.group(1)] = value
    return out
