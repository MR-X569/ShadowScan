"""
app/api/v1/ai.py
----------------
REST API endpoints for the ShadowScan AI Security Analyst (Ollama-backed).

Endpoints:
  - GET  /api/v1/ai/status                             -> Operational status of Ollama AI service
  - GET  /api/v1/scans/{scan_id}/ai/analysis           -> Comprehensive structured AI scan analysis
  - POST /api/v1/scans/{scan_id}/ai/analysis           -> Request / regenerate AI scan analysis
  - POST /api/v1/scans/{scan_id}/ai/findings/{fid}/explain -> Explain individual finding with AI
  - POST /api/v1/scans/{scan_id}/ai/chat               -> Scan-scoped AI security chat
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.ai.schemas import (
    AIChatRequest,
    AIChatResponse,
    AIStatusResponse,
    FindingAIExplanationResponse,
    ScanAIAnalysisResponse,
)
from app.ai.service import AIService
from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.crud.finding import get_findings_by_scan
from app.models.user import User
from app.services.scan_service import ScanService

router = APIRouter(tags=["AI Security Analyst"])


# ---------------------------------------------------------------------------
# GET /api/v1/ai/status — AI Engine Health & Availability
# ---------------------------------------------------------------------------


@router.get(
    "/ai/status",
    response_model=AIStatusResponse,
    summary="Get AI engine status",
    description="Returns whether the Ollama AI Security Analyst is enabled and reachable.",
)
async def get_ai_status() -> AIStatusResponse:
    service = AIService()
    return await service.get_status()


# ---------------------------------------------------------------------------
# GET / POST /api/v1/scans/{scan_id}/ai/analysis — Full Scan AI Analysis
# ---------------------------------------------------------------------------


@router.get(
    "/scans/{scan_id}/ai/analysis",
    response_model=ScanAIAnalysisResponse,
    summary="Get AI scan analysis",
    description=(
        "Returns a structured AI analysis, risk evaluation, prioritized findings, "
        "and remediation roadmap for the given scan."
    ),
)
@router.post(
    "/scans/{scan_id}/ai/analysis",
    response_model=ScanAIAnalysisResponse,
    summary="Generate AI scan analysis",
    description="Generates or refreshes the structured AI analysis for the given scan.",
)
async def get_scan_ai_analysis(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScanAIAnalysisResponse:
    # 1. Authorize: Ensure user owns this scan
    scan_service = ScanService(db)
    scan = scan_service._get_scan_or_404(scan_id)
    scan_service._assert_owner(scan, current_user)

    # 2. Retrieve findings
    findings = get_findings_by_scan(db, scan_id)

    # 3. Generate AI analysis
    ai_service = AIService()
    return await ai_service.analyze_scan(scan, findings)


# ---------------------------------------------------------------------------
# POST /api/v1/scans/{scan_id}/ai/findings/{finding_id}/explain — Explain Finding
# ---------------------------------------------------------------------------


@router.post(
    "/scans/{scan_id}/ai/findings/{finding_id}/explain",
    response_model=FindingAIExplanationResponse,
    summary="Explain finding with AI",
    description=(
        "Provides an in-depth AI explanation, technical impact, severity justification, "
        "and remediation guide for a specific finding."
    ),
)
async def explain_finding_with_ai(
    scan_id: int,
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> FindingAIExplanationResponse:
    # 1. Authorize scan ownership
    scan_service = ScanService(db)
    scan = scan_service._get_scan_or_404(scan_id)
    scan_service._assert_owner(scan, current_user)

    # 2. Retrieve target finding
    findings = get_findings_by_scan(db, scan_id)
    target_finding = next((f for f in findings if f.id == finding_id), None)
    if target_finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding #{finding_id} not found in scan #{scan_id}.",
        )

    # 3. Generate explanation
    ai_service = AIService()
    return await ai_service.explain_finding(scan, target_finding)


# ---------------------------------------------------------------------------
# POST /api/v1/scans/{scan_id}/ai/chat — Scan-Scoped Security Chat
# ---------------------------------------------------------------------------


@router.post(
    "/scans/{scan_id}/ai/chat",
    response_model=AIChatResponse,
    summary="Scan-scoped AI security chat",
    description="Interactive conversational interface with ShadowScan AI Security Analyst scoped to the scan.",
)
async def scan_ai_chat(
    scan_id: int,
    payload: AIChatRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AIChatResponse:
    # 1. Authorize scan ownership
    scan_service = ScanService(db)
    scan = scan_service._get_scan_or_404(scan_id)
    scan_service._assert_owner(scan, current_user)

    # 2. Retrieve findings
    findings = get_findings_by_scan(db, scan_id)

    # 3. Process chat query
    ai_service = AIService()
    return await ai_service.chat(scan, findings, payload)
