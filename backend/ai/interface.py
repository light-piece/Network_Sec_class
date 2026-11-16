"""How the backend calls the AI (shared contract, added at the start of milestone 2).

Agent C implements these in backend/ai/ (validate.py, mock.py, ollama.py, factory.py).
Agent B calls them only through this interface and uses its own stand-in in tests.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional, Protocol

from backend.ai.models import AIRecommendation
from backend.lab_types import FirewallRule, LabAddresses


@dataclass
class Feedback:
    """Mirrors the dashboard's feedback object (docs/API_CONTRACT.md)."""
    type: Literal["rejected", "failed"]
    version: int
    summary: Optional[str] = None


@dataclass
class IncidentFacts:
    """What the AI is told about the incident. Plain data, built by the backend."""
    source_ip: str
    target_ip: str
    target_port: int
    matched_rule: str          # e.g. "rule-14"
    policy: str                # e.g. "Only the company app (10.10.20.10) may reach the database (10.10.30.10:5432)."


class AIUnavailable(RuntimeError):
    """Ollama unreachable or timed out. Message is shown to the administrator."""


class InvalidRecommendation(ValueError):
    """The AI's output failed schema or lab validation. Message is shown to the administrator."""


class AIProvider(Protocol):
    model_name: str            # shown as the recommendation's "model", e.g. "qwen3:4b via Ollama"

    def recommend(self, facts: IncidentFacts, rules: list[FirewallRule],
                  feedback: Optional[Feedback], attempt: int) -> AIRecommendation:
        """Return a schema-valid recommendation (NOT yet lab-validated).
        ``attempt`` starts at 1. Raise AIUnavailable or InvalidRecommendation."""
        ...


# Implemented by agent C in backend/ai/validate.py:
#   def validate(rec: AIRecommendation, rules: list[FirewallRule], addresses: LabAddresses) -> AIRecommendation
#       Checks every rule_id exists in ``rules`` and is not "temp-block"; CIDRs/IPs inside the lab
#       ranges in ``addresses``; positions refer to existing rules; returns a copy with each AddDeny
#       given a new rule_id that sorts into its position (e.g. rule-11 before rule-12, rule-13 after).
#       Raises InvalidRecommendation.
#
# Implemented by agent C in backend/ai/factory.py:
#   def get_provider(ai_mode: str, mock_scenario: str, ollama_url: str, ollama_model: str,
#                    ollama_timeout: float) -> AIProvider
#       ai_mode "mock" -> mock provider (scenario "A" or "B"); "ollama" -> Ollama provider.

__all__ = ["Feedback", "IncidentFacts", "AIUnavailable", "InvalidRecommendation", "AIProvider", "LabAddresses"]
