"""Real lab control: the ONLY module that runs system commands.

Stub created in milestone 1. Agent A implements it in milestone 2A.

Rules for the implementation:
- Run commands with ``subprocess.run([...], shell=False, timeout=...)`` and fixed
  argument lists. Never build a shell string, never pass AI text to a command.
- nftables commands come only from the templates in ``render()`` and the
  baseline file ``lab/baseline.nft``; values are taken from validated
  ``Action`` objects and ``LabAddresses``.
- Firewall work happens in the router namespace:
  ``ip netns exec <router> nft ...`` on table ``inet lab``, chain ``forward``.
- Rules are found by their comment (``rule-14``, ``temp-block``) using
  ``nft -j -a list chain inet lab forward``, then changed by handle.
- Raise ``LabError`` with a readable message when a command fails.

See docs/LAB_INTERFACE.md for what each method must do, and
backend/fake_lab.py for a reference behaviour the real lab must match.
"""
from __future__ import annotations

from backend.ai.models import Action
from backend.lab_types import (
    AttackResult,
    CheckOutcome,
    FirewallRule,
    LabAddresses,
    LabHealth,
)


class Lab:
    def __init__(self, addresses: LabAddresses | None = None,
                 router_ns: str = "router", employee_ns: str = "employee",
                 app_ns: str = "app", db_ns: str = "db") -> None:
        self.addresses = addresses or LabAddresses()
        self.router_ns, self.employee_ns, self.app_ns, self.db_ns = router_ns, employee_ns, app_ns, db_ns

    def health(self) -> LabHealth:
        raise NotImplementedError("milestone 2A")

    def rules(self) -> list[FirewallRule]:
        raise NotImplementedError("milestone 2A")

    def rule14_counter(self) -> int:
        raise NotImplementedError("milestone 2A")

    def block_on(self) -> FirewallRule:
        raise NotImplementedError("milestone 2A")

    def block_off(self) -> None:
        raise NotImplementedError("milestone 2A")

    def block_active(self) -> bool:
        raise NotImplementedError("milestone 2A")

    def render(self, actions: list[Action]) -> list[str]:
        raise NotImplementedError("milestone 2A")

    def apply(self, actions: list[Action]) -> None:
        raise NotImplementedError("milestone 2A")

    def snapshot(self) -> str:
        raise NotImplementedError("milestone 2A")

    def restore(self, snapshot: str) -> None:
        raise NotImplementedError("milestone 2A")

    def check_unauthorized_blocked(self) -> CheckOutcome:
        raise NotImplementedError("milestone 2A")

    def check_legitimate_app(self) -> CheckOutcome:
        raise NotImplementedError("milestone 2A")

    def run_attack(self) -> AttackResult:
        raise NotImplementedError("milestone 2A")

    def reset(self) -> None:
        raise NotImplementedError("milestone 2A")
