"""
app/ai
------
ShadowScan AI Security Analyst Module (Ollama-backed).
"""

from app.ai.service import AIService
from app.ai.ollama import OllamaClient
from app.ai.schemas import (
    ScanAIAnalysisResponse,
    FindingAIExplanationResponse,
    AIChatRequest,
    AIChatResponse,
    AIStatusResponse,
)

__all__ = [
    "AIService",
    "OllamaClient",
    "ScanAIAnalysisResponse",
    "FindingAIExplanationResponse",
    "AIChatRequest",
    "AIChatResponse",
    "AIStatusResponse",
]
