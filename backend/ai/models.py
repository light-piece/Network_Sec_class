"""AI recommendation schema (shared contract, created in milestone 1).

The local model must return JSON matching ``AIRecommendation``. Its JSON
schema is passed to Ollama as ``format`` so the model is constrained to it.

The model never writes commands. It picks 1-3 actions from a closed set;
the backend validates them against the lab (``backend/ai/validate.py``,
milestone 2C) and ``backend/lab.py`` turns them into fixed nftables templates.

Static checks live here (types, formats, lengths, allowed values).
Lab-specific checks (rule exists, addresses inside the lab ranges, no edits
to protected rules) need configuration and live in ``validate.py``.
"""
from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network
from typing import Annotated, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field

# Lab rule IDs as stored in nftables comments: "rule-10", "rule-12", "rule-14", "rule-13"...
RuleId = Annotated[str, Field(pattern=r"^rule-\d{1,3}$", description="Lab rule ID, e.g. 'rule-14'")]

# Where an added rule goes: the top of the chain, or directly before/after an existing rule.
Position = Annotated[
    str,
    Field(pattern=r"^(top|before:rule-\d{1,3}|after:rule-\d{1,3})$",
          description="'top', 'before:rule-N' or 'after:rule-N'"),
]

ShortText = Annotated[str, Field(min_length=1, max_length=400)]


class _Action(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SetRuleVerdict(_Action):
    """Change an existing rule's verdict, e.g. rule-14 from accept to drop."""
    action: Literal["set_rule_verdict"]
    rule_id: RuleId
    verdict: Literal["accept", "drop"]


class DeleteRule(_Action):
    """Remove an existing rule (traffic then falls through to later rules / default drop)."""
    action: Literal["delete_rule"]
    rule_id: RuleId


class NarrowSource(_Action):
    """Restrict an existing rule's source to a smaller network."""
    action: Literal["narrow_source"]
    rule_id: RuleId
    source_cidr: IPv4Network


class AddDeny(_Action):
    """Insert a new drop rule for one destination and port."""
    action: Literal["add_deny"]
    source_cidr: IPv4Network
    dest_ip: IPv4Address
    dest_port: Literal[5432, 8080]
    position: Position
    # Assigned by the backend validator (e.g. "rule-13"); anything the model puts here is overwritten.
    rule_id: Optional[RuleId] = None


Action = Annotated[
    Union[SetRuleVerdict, DeleteRule, NarrowSource, AddDeny],
    Field(discriminator="action"),
]


class AIRecommendation(BaseModel):
    """What the model returns. Display text is shown to the administrator, never executed."""
    model_config = ConfigDict(extra="forbid")

    actions: list[Action] = Field(min_length=1, max_length=3,
                                  description="Applied in order, top to bottom.")
    summary: ShortText = Field(description="One sentence the administrator reads first.")
    change: ShortText = Field(description="What changes, in plain words.")
    affects: ShortText = Field(description="Who loses access because of the change.")
    unaffected: ShortText = Field(description="Who keeps access.")
    what_changed: Annotated[str, Field(max_length=400)] = Field(
        default="", description="For a revised version: how it differs from the previous one.")


def ollama_format_schema() -> dict:
    """JSON schema to send as Ollama's ``format`` field."""
    return AIRecommendation.model_json_schema()
