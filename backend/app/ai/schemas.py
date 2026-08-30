"""
app/ai/schemas.py
-----------------
Pydantic schemas for the AI Security Analyst module (Ollama-backed).

Defines structured output models for:
  - Overall scan analysis (summary, priorities, relationships, remediation, verification)
  - Single finding explanation (meaning, impact, severity justification, remediation)
  - Scan-scoped security chat messages and responses
  - AI engine health and status indicators
"""

from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Structured Scan Analysis Schemas
# ---------------------------------------------------------------------------


class PriorityFinding(BaseModel):
    """Represents a prioritized finding within the overall scan analysis."""

    finding_id: int = Field(..., description="ID of the finding in ShadowScan.")
    priority: int = Field(..., ge=1, description="Numerical priority order (1 = highest urgency).")
    title: str = Field("", description="Vulnerability title.")
    reason: str = Field(..., description="Technical rationale for this priority ranking.")


class FindingRelationship(BaseModel):
    """Explains how multiple discovered vulnerabilities interact or chain together."""

    finding_ids: list[int] = Field(..., description="List of related ShadowScan finding IDs.")
    explanation: str = Field(..., description="How these findings correlate or amplify attack risk.")


class RemediationStep(BaseModel):
    """Actionable step in the recommended remediation plan."""

    priority: int = Field(..., ge=1, description="Recommended remediation sequence number.")
    action: str = Field(..., description="Specific technical fix or configuration adjustment.")
    reason: str = Field(..., description="Security rationale for taking this action.")


class ScanAIAnalysisResponse(BaseModel):
    """Structured AI analysis of an entire completed vulnerability scan."""

    overall_assessment: str = Field(..., description="High-level security evaluation of the target.")
    risk_level: str = Field(
        ...,
        description="Overall risk tier: CRITICAL, HIGH, MEDIUM, LOW, or INFORMATIONAL/CLEAN.",
    )
    executive_summary: str = Field(..., description="Concise summary for technical and executive stakeholders.")
    priority_findings: list[PriorityFinding] = Field(
        default_factory=list,
        description="Ordered list of findings requiring immediate attention.",
    )
    relationships: list[FindingRelationship] = Field(
        default_factory=list,
        description="Correlations and attack chain possibilities among findings.",
    )
    remediation_plan: list[RemediationStep] = Field(
        default_factory=list,
        description="Sequenced remediation roadmap.",
    )
    verification_steps: list[str] = Field(
        default_factory=list,
        description="Concrete steps the security engineer should take to verify fixes.",
    )
    ai_status: Literal["ready", "unavailable", "disabled", "error"] = Field(
        "ready",
        description="Operational status of the AI analyst.",
    )
    model_used: str = Field("", description="Ollama model that generated this analysis.")


# ---------------------------------------------------------------------------
# Single Finding Explanation Schemas
# ---------------------------------------------------------------------------


class FindingAIExplanationResponse(BaseModel):
    """Structured explanation and remediation guide for an individual finding."""

    finding_id: int = Field(..., description="ShadowScan finding ID.")
    title: str = Field(..., description="Title of the vulnerability finding.")
    severity: str = Field(..., description="Severity level assigned by ShadowScan.")
    meaning: str = Field(..., description="Plain-English explanation of what this vulnerability means.")
    impact_analysis: str = Field(..., description="Potential consequences if exploited by an attacker.")
    severity_justification: str = Field(..., description="Why ShadowScan classified this issue at its severity tier.")
    remediation_guide: str = Field(..., description="Step-by-step instructions to remediate the vulnerability.")
    verification_method: str = Field(..., description="How to confirm the issue has been successfully resolved.")
    ai_status: Literal["ready", "unavailable", "disabled", "error"] = Field(
        "ready",
        description="Status of the AI explanation generation.",
    )
    model_used: str = Field("", description="Ollama model used.")


# ---------------------------------------------------------------------------
# Scan-Scoped AI Chat Schemas
# ---------------------------------------------------------------------------


class AIChatMessage(BaseModel):
    """Chat message in a security analyst conversation."""

    role: Literal["user", "assistant", "system"] = Field(..., description="Message author role.")
    content: str = Field(..., description="Message text.")


class AIChatRequest(BaseModel):
    """Incoming user chat query scoped to the current scan."""

    message: str = Field(..., min_length=1, max_length=2000, description="User's security question.")
    history: list[AIChatMessage] = Field(
        default_factory=list,
        description="Prior conversation turns in this scan session.",
    )


class AIChatResponse(BaseModel):
    """AI Security Analyst response to a scan-scoped question."""

    response: str = Field(..., description="Security analyst's response.")
    is_refusal: bool = Field(
        False,
        description="True if query was off-topic/non-security and politely declined.",
    )
    ai_status: Literal["ready", "unavailable", "disabled", "error"] = Field("ready")
    model_used: str = Field("")


# ---------------------------------------------------------------------------
# Service Status Schemas
# ---------------------------------------------------------------------------


class AIStatusResponse(BaseModel):
    """Operational health status of the Ollama AI service."""

    enabled: bool = Field(..., description="Whether AI features are enabled in configuration.")
    provider: str = Field("ollama", description="AI provider backend.")
    available: bool = Field(..., description="Whether Ollama is currently reachable and responding.")
    model: str = Field(..., description="Configured Ollama model identifier.")
    base_url: str = Field(..., description="Configured Ollama endpoint URL.")
