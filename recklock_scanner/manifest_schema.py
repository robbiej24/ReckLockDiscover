"""
YAML manifest validation compatible with ReckLock Registry imports.

Derived from the ReckLock Registry manifest model so exported drafts validate
the same way as hand-written manifests.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator

AGENT_ID_PATTERN = re.compile(r"^agt_[a-z0-9]+(?:-[a-z0-9]+)*_[a-f0-9]{6,12}$")

AgentType = Literal[
    "assistant",
    "workflow_agent",
    "transaction_agent",
    "security_agent",
    "research_agent",
    "coding_agent",
    "financial_agent",
    "compliance_agent",
    "other",
]

RiskLevel = Literal["low", "medium", "high", "critical"]


class Developer(BaseModel):
    """Developer attribution."""

    name: str = Field(..., min_length=1)


class Metadata(BaseModel):
    """Manifest metadata."""

    created_at: str = Field(..., min_length=1)
    updated_at: str = Field(..., min_length=1)
    registry_version: str = Field(..., min_length=1)
    observation_mode: bool | None = None
    governance_status: str | None = None
    source_path: str | None = None
    discovered_at: str | None = None


class ManifestSignature(BaseModel):
    """Detached signature metadata (optional until signing is implemented)."""

    signed_by_key_id: str = Field(..., min_length=1)
    signature_base64: str = Field(..., min_length=1)
    signed_at: str = Field(..., min_length=1)


class PublicKeyEntry(BaseModel):
    """Embedded public key reference for future verification."""

    key_id: str = Field(..., min_length=1)
    algorithm: str = Field(..., min_length=1)
    public_key_base64: str = Field(..., min_length=1)
    created_at: str = Field(..., min_length=1)
    expires_at: str | None = None


class AgentManifest(BaseModel):
    """Agent identity manifest (unsigned YAML in Phase 1A–1B)."""

    agent_id: str
    name: str = Field(..., min_length=1)
    version: str = Field(..., min_length=1)
    developer: Developer
    description: str = Field(..., min_length=1)
    agent_type: AgentType
    model_providers: list[str]
    capabilities: list[str]
    permission_scopes: list[str]
    risk_level: RiskLevel
    requires_human_approval: bool
    metadata: Metadata
    signature: ManifestSignature | None = None
    public_keys: list[PublicKeyEntry] | None = None
    discovery: dict[str, Any] | None = None

    @field_validator("agent_id")
    @classmethod
    def agent_id_format(cls, v: str) -> str:
        if not AGENT_ID_PATTERN.match(v):
            raise ValueError(
                "agent_id must match agt_<lowercase-slug>_<shorthash> "
                "(slug: lowercase letters, digits, hyphens; shorthash: 6–12 hex chars)"
            )
        return v

    @field_validator("model_providers", "capabilities", "permission_scopes")
    @classmethod
    def non_empty_string_lists(cls, v: list[str]) -> list[str]:
        for item in v:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("list items must be non-empty strings")
        return v


def load_manifest(path: str | Path) -> AgentManifest:
    """Load and parse a manifest file; raise on invalid YAML or schema."""
    p = Path(path)
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    if raw is None or not isinstance(raw, dict):
        raise ValueError("manifest must be a YAML mapping")
    return AgentManifest.model_validate(raw)


def manifest_json_schema() -> dict[str, Any]:
    """JSON Schema for ``AgentManifest`` (Pydantic-generated)."""
    return AgentManifest.model_json_schema()


def canonicalize_manifest(manifest: AgentManifest) -> str:
    """Deterministic JSON representation for hashing and future signing."""
    data = manifest.model_dump(
        mode="json",
        exclude={"signature"},
        exclude_none=True,
    )
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
