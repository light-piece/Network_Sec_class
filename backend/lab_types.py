"""Types shared by the real lab (``lab.py``), the fake lab (``fake_lab.py``) and the backend.

Shared contract created in milestone 1. Change it only with agreement from
the lab agent (A) and the backend agent (B); see docs/LAB_INTERFACE.md.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional, Protocol

from backend.ai.models import Action

Verdict = Literal["accept", "drop"]


@dataclass(frozen=True)
class LabAddresses:
    """Lab topology. Defaults match .env.example; the backend builds this from config."""
    employee_ip: str = "10.10.10.10"
    employee_net: str = "10.10.10.0/24"
    app_ip: str = "10.10.20.10"
    app_net: str = "10.10.20.0/24"
    app_port: int = 8080
    db_ip: str = "10.10.30.10"
    db_net: str = "10.10.30.0/24"
    db_port: int = 5432


@dataclass
class FirewallRule:
    """One rule in the lab's forward chain, in evaluation order.

    ``rule_id`` is the nftables comment ("rule-14", "temp-block").
    ``None`` in src/dst/dport means "any". The "est" rule is not listed.
    """
    rule_id: str
    verdict: Verdict
    src: Optional[str] = None      # CIDR or single IP
    dst: Optional[str] = None      # single IP
    dport: Optional[int] = None
    counter: Optional[int] = None  # packets, only for rules with a counter


@dataclass
class CheckOutcome:
    """Result of one verification check. ``passed`` already accounts for the expectation
    (for the unauthorized check, passed means the connection was refused)."""
    passed: bool
    command: str          # what was run, for the evidence line
    exit_code: int
    output: str           # short, trimmed
    duration_ms: int


@dataclass
class AttackResult:
    reached: bool         # did the attacker's connection get through?
    command: str
    output: str


@dataclass
class LabHealth:
    up: bool              # namespaces + firewall table present
    app_ok: bool          # Flask /health answered
    db_ok: bool           # PostgreSQL accepted a connection from the app namespace
    detail: str = ""


class LabControl(Protocol):
    """Everything the backend may ask of the lab. ``lab.Lab`` and ``fake_lab.FakeLab`` implement it."""

    addresses: LabAddresses

    def health(self) -> LabHealth: ...
    def rules(self) -> list[FirewallRule]: ...
    def rule14_counter(self) -> int: ...

    def block_on(self) -> FirewallRule: ...
    def block_off(self) -> None: ...
    def block_active(self) -> bool: ...

    def render(self, actions: list[Action]) -> list[str]: ...
    def apply(self, actions: list[Action]) -> None: ...
    def snapshot(self) -> str: ...
    def restore(self, snapshot: str) -> None: ...

    def check_unauthorized_blocked(self) -> CheckOutcome: ...
    def check_legitimate_app(self) -> CheckOutcome: ...

    def run_attack(self) -> AttackResult: ...
    def reset(self) -> None: ...


class LabError(RuntimeError):
    """A lab command failed. The message is shown to the administrator."""
