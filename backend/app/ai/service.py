"""
app/ai/service.py
-----------------
Core AI Security Analyst Orchestration Service.

Coordinates:
  - Sanitization / Redaction of finding evidence.
  - Safe invocation of Ollama local AI model.
  - Pydantic validation of structured JSON responses.
  - Anti-hallucination and finding ID integrity verification.
  - Fail-safe fallback when AI is disabled or Ollama is offline.
"""

from __future__ import annotations

import logging
from typing import Any

from app.ai.ollama import OllamaClient, OllamaError
from app.ai.prompts import (
    SYSTEM_PROMPT,
    build_chat_system_context,
    build_finding_explanation_prompt,
    build_scan_analysis_prompt,
)
from app.ai.redaction import sanitize_finding_for_ai
from app.ai.schemas import (
    AIChatMessage,
    AIChatRequest,
    AIChatResponse,
    AIStatusResponse,
    FindingAIExplanationResponse,
    FindingRelationship,
    PriorityFinding,
    RemediationStep,
    ScanAIAnalysisResponse,
)
from app.core.config import settings

logger = logging.getLogger(__name__)

# Common non-security / off-topic keywords for fast deterministic refusal
_OFF_TOPIC_KEYWORDS: frozenset[str] = frozenset({
    "joke",
    "poem",
    "recipe",
    "weather",
    "pewdiepie",
    "celebrity",
    "horoscope",
    "movie review",
    "football",
    "cricket score",
    "song lyrics",
})


class AIService:
    """Service orchestrating AI Security Analyst capabilities."""

    def __init__(self, ollama_client: OllamaClient | None = None) -> None:
        self.client = ollama_client or OllamaClient()

    async def get_status(self) -> AIStatusResponse:
        """Check operational availability of the AI module."""
        if not settings.ai_enabled:
            return AIStatusResponse(
                enabled=False,
                provider=settings.ai_provider,
                available=False,
                model=settings.ollama_model,
                base_url=settings.ollama_base_url,
            )

        is_up = await self.client.is_available()
        return AIStatusResponse(
            enabled=True,
            provider=settings.ai_provider,
            available=is_up,
            model=settings.ollama_model,
            base_url=settings.ollama_base_url,
        )

    # ------------------------------------------------------------------
    # 1. Explain Entire Scan
    # ------------------------------------------------------------------

    async def analyze_scan(
        self,
        scan: Any,
        findings: list[Any],
    ) -> ScanAIAnalysisResponse:
        """
        Generate a comprehensive, structured AI analysis of all findings in a scan.
        """
        # Fail-safe check: AI disabled
        if not settings.ai_enabled:
            return self._build_fallback_scan_analysis(
                scan,
                findings,
                status="disabled",
                reason="AI Security Analyst is disabled in application settings.",
            )

        # Sanitize findings
        sanitized = [sanitize_finding_for_ai(f) for f in findings]
        valid_finding_ids = {f["finding_id"] for f in sanitized if f["finding_id"]}

        # Handle zero findings (clean target)
        if not sanitized:
            return ScanAIAnalysisResponse(
                overall_assessment="Target appears clean. No vulnerabilities were detected by the 45 active scanner plugins.",
                risk_level="CLEAN",
                executive_summary="The automated assessment completed with zero discovered security flaws. All baseline checks and headers were evaluated.",
                priority_findings=[],
                relationships=[],
                remediation_plan=[
                    RemediationStep(
                        priority=1,
                        action="Maintain continuous monitoring and periodic re-scanning.",
                        reason="Ensure newly introduced endpoints or dependencies remain secure.",
                    )
                ],
                verification_steps=["Run regression scans during CI/CD builds."],
                ai_status="ready",
                model_used=self.client.model,
            )

        prompt = build_scan_analysis_prompt(
            target_url=str(scan.target_url),
            scan_id=scan.id,
            risk_score=getattr(scan, "risk_score", None),
            sanitized_findings=sanitized,
        )

        try:
            raw_data = await self.client.generate_json(prompt, system=SYSTEM_PROMPT)
            return self._validate_and_sanitize_scan_response(raw_data, valid_finding_ids)
        except OllamaError as exc:
            logger.warning("Ollama analysis unavailable: %s", exc)
            return self._build_fallback_scan_analysis(
                scan,
                findings,
                status="unavailable",
                reason=f"AI service unavailable ({exc}). Scanner results and PDF report remain unaffected.",
            )
        except Exception as exc:
            logger.error("Unexpected error during AI scan analysis: %s", exc)
            return self._build_fallback_scan_analysis(
                scan,
                findings,
                status="error",
                reason=f"AI parsing error: {exc}",
            )

    # ------------------------------------------------------------------
    # 2. Explain Individual Finding
    # ------------------------------------------------------------------

    async def explain_finding(
        self,
        scan: Any,
        finding: Any,
    ) -> FindingAIExplanationResponse:
        """
        Generate a detailed AI explanation, impact analysis, and remediation guide for a single finding.
        """
        sanitized = sanitize_finding_for_ai(finding)

        if not settings.ai_enabled:
            return FindingAIExplanationResponse(
                finding_id=sanitized["finding_id"],
                title=sanitized["title"],
                severity=sanitized["severity"],
                meaning=f"Vulnerability '{sanitized['title']}' detected by {sanitized['plugin']} plugin.",
                impact_analysis="AI analysis is currently disabled in configuration.",
                severity_justification=f"Classified as {sanitized['severity']} by ShadowScan rule definitions.",
                remediation_guide=sanitized["recommendation"] or "Refer to standard security documentation.",
                verification_method="Re-run the scan to verify remediation.",
                ai_status="disabled",
                model_used="none",
            )

        prompt = build_finding_explanation_prompt(
            target_url=str(scan.target_url),
            finding=sanitized,
        )

        try:
            raw_data = await self.client.generate_json(prompt, system=SYSTEM_PROMPT)
            return FindingAIExplanationResponse(
                finding_id=sanitized["finding_id"],
                title=sanitized["title"],
                severity=sanitized["severity"],  # Preserve scanner severity ground truth
                meaning=str(raw_data.get("meaning", sanitized["description"] or "Security issue detected.")),
                impact_analysis=str(raw_data.get("impact_analysis", "May expose application to unauthorized access or data leakage.")),
                severity_justification=str(raw_data.get("severity_justification", f"Rated {sanitized['severity']} based on potential impact.")),
                remediation_guide=str(raw_data.get("remediation_guide", sanitized["recommendation"] or "Apply standard hardening fixes.")),
                verification_method=str(raw_data.get("verification_method", "Re-run ShadowScan to confirm resolution.")),
                ai_status="ready",
                model_used=self.client.model,
            )
        except OllamaError as exc:
            logger.warning("Ollama finding explanation unavailable: %s", exc)
            return FindingAIExplanationResponse(
                finding_id=sanitized["finding_id"],
                title=sanitized["title"],
                severity=sanitized["severity"],
                meaning=sanitized["description"] or f"Vulnerability detected by {sanitized['plugin']} plugin.",
                impact_analysis="AI explanation unavailable at this time.",
                severity_justification=f"Assigned {sanitized['severity']} by ShadowScan scanner engine.",
                remediation_guide=sanitized["recommendation"] or "Apply security best practices.",
                verification_method="Re-scan target to verify fix.",
                ai_status="unavailable",
                model_used=self.client.model,
            )

    # ------------------------------------------------------------------
    # 3. Security AI Chat
    # ------------------------------------------------------------------

    async def chat(
        self,
        scan: Any,
        findings: list[Any],
        request: AIChatRequest,
    ) -> AIChatResponse:
        """
        Handle a multi-turn conversation with the AI Security Analyst scoped to the scan.
        """
        user_query = request.message.strip()

        # Fast rejection of off-topic queries
        query_lower = user_query.lower()
        if any(kw in query_lower for kw in _OFF_TOPIC_KEYWORDS) and not any(
            sec in query_lower for sec in ["security", "vulnerability", "xss", "sqli", "csrf", "scan", "finding", "header"]
        ):
            return AIChatResponse(
                response=(
                    "I am ShadowScan AI Security Analyst, dedicated solely to application security "
                    "analysis, vulnerability remediation, and your scan assessment. Please ask a security-related question."
                ),
                is_refusal=True,
                ai_status="ready",
                model_used=self.client.model,
            )

        if not settings.ai_enabled:
            return AIChatResponse(
                response="AI Security Analyst is currently disabled in system settings.",
                is_refusal=False,
                ai_status="disabled",
                model_used="none",
            )

        sanitized = [sanitize_finding_for_ai(f) for f in findings]
        system_context = build_chat_system_context(
            target_url=str(scan.target_url),
            scan_id=scan.id,
            risk_score=getattr(scan, "risk_score", None),
            sanitized_findings=sanitized,
        )

        messages: list[dict[str, str]] = [{"role": "system", "content": system_context}]

        # Include bounded chat history (last 8 turns)
        for msg in (request.history or [])[-8:]:
            messages.append({"role": msg.role, "content": msg.content})

        messages.append({"role": "user", "content": user_query})

        try:
            reply = await self.client.chat(messages)
            return AIChatResponse(
                response=reply,
                is_refusal=False,
                ai_status="ready",
                model_used=self.client.model,
            )
        except OllamaError as exc:
            logger.warning("Ollama chat unavailable: %s", exc)
            return AIChatResponse(
                response="The AI Security Analyst is currently unavailable. Your scan findings remain unaffected.",
                is_refusal=False,
                ai_status="unavailable",
                model_used=self.client.model,
            )

    # ------------------------------------------------------------------
    # Private Validation & Anti-Hallucination Helpers
    # ------------------------------------------------------------------

    def _validate_and_sanitize_scan_response(
        self,
        data: dict[str, Any],
        valid_finding_ids: set[int],
    ) -> ScanAIAnalysisResponse:
        """
        Validate raw Ollama JSON output against Pydantic schema and filter out
        any hallucinated finding IDs.
        """
        # Validate priority findings & filter hallucinated IDs
        raw_priorities = data.get("priority_findings", [])
        priority_findings: list[PriorityFinding] = []
        for i, item in enumerate(raw_priorities, start=1):
            if not isinstance(item, dict):
                continue
            fid = item.get("finding_id")
            # Only keep findings that genuinely exist in ShadowScan data
            if fid in valid_finding_ids or (isinstance(fid, str) and fid.isdigit() and int(fid) in valid_finding_ids):
                priority_findings.append(
                    PriorityFinding(
                        finding_id=int(fid),
                        priority=item.get("priority", i),
                        title=str(item.get("title", "")),
                        reason=str(item.get("reason", "High risk security vulnerability.")),
                    )
                )

        # Validate relationships
        raw_relationships = data.get("relationships", [])
        relationships: list[FindingRelationship] = []
        for item in raw_relationships:
            if not isinstance(item, dict):
                continue
            raw_ids = item.get("finding_ids", [])
            filtered_ids = [
                int(fid)
                for fid in raw_ids
                if (isinstance(fid, int) and fid in valid_finding_ids)
                or (isinstance(fid, str) and fid.isdigit() and int(fid) in valid_finding_ids)
            ]
            if filtered_ids:
                relationships.append(
                    FindingRelationship(
                        finding_ids=filtered_ids,
                        explanation=str(item.get("explanation", "Findings correlate in attack surface.")),
                    )
                )

        # Validate remediation plan
        raw_remediation = data.get("remediation_plan", [])
        remediation_plan: list[RemediationStep] = []
        for i, item in enumerate(raw_remediation, start=1):
            if isinstance(item, dict):
                remediation_plan.append(
                    RemediationStep(
                        priority=item.get("priority", i),
                        action=str(item.get("action", "")),
                        reason=str(item.get("reason", "")),
                    )
                )
            elif isinstance(item, str):
                remediation_plan.append(
                    RemediationStep(
                        priority=i,
                        action=item,
                        reason="Security hardening recommendation.",
                    )
                )

        # Verification steps
        verification_steps = [str(s) for s in data.get("verification_steps", []) if s]

        return ScanAIAnalysisResponse(
            overall_assessment=str(data.get("overall_assessment", "Automated scan analysis complete.")),
            risk_level=str(data.get("risk_level", "MEDIUM")).upper(),
            executive_summary=str(data.get("executive_summary", "Security assessment completed.")),
            priority_findings=priority_findings,
            relationships=relationships,
            remediation_plan=remediation_plan,
            verification_steps=verification_steps,
            ai_status="ready",
            model_used=self.client.model,
        )

    def _build_fallback_scan_analysis(
        self,
        scan: Any,
        findings: list[Any],
        status: str,
        reason: str,
    ) -> ScanAIAnalysisResponse:
        """Construct a deterministic fallback summary when AI is unavailable."""
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = getattr(f, "severity", "LOW")
            if hasattr(sev, "value"):
                sev = sev.value
            s_str = str(sev).upper()
            if s_str in sev_counts:
                sev_counts[s_str] += 1

        overall = (
            f"Automated analysis fallback: {len(findings)} findings discovered "
            f"({sev_counts['CRITICAL']} Critical, {sev_counts['HIGH']} High, {sev_counts['MEDIUM']} Medium, {sev_counts['LOW']} Low)."
        )

        return ScanAIAnalysisResponse(
            overall_assessment=overall,
            risk_level="CRITICAL" if sev_counts["CRITICAL"] > 0 else "HIGH" if sev_counts["HIGH"] > 0 else "MEDIUM" if sev_counts["MEDIUM"] > 0 else "LOW",
            executive_summary=reason,
            priority_findings=[],
            relationships=[],
            remediation_plan=[
                RemediationStep(
                    priority=1,
                    action="Review individual findings in the findings table and PDF report.",
                    reason="Deterministic recommendations are available for each finding.",
                )
            ],
            verification_steps=["Re-run scan after applying fixes."],
            ai_status=status,  # type: ignore
            model_used="none",
        )
