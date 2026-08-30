"""
app/ai/ollama.py
----------------
Async HTTP Client for Local Ollama AI Engine.

Communicates with Ollama's REST API (/api/generate, /api/chat, /api/tags)
with strict timeouts, connection pooling, and structured JSON parsing.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


class OllamaError(Exception):
    """Base exception for Ollama communication or parsing failures."""


class OllamaConnectionError(OllamaError):
    """Raised when Ollama is unreachable or refused connection."""


class OllamaTimeoutError(OllamaError):
    """Raised when Ollama request exceeds configured timeout."""


class OllamaResponseError(OllamaError):
    """Raised when Ollama returns an error status or invalid output."""


class OllamaClient:
    """Async client for interacting with the local Ollama daemon."""

    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float | None = None,
    ) -> None:
        self.base_url = (base_url or settings.ollama_base_url).rstrip("/")
        self.model = model or settings.ollama_model
        self.timeout = timeout if timeout is not None else settings.ollama_timeout

    async def is_available(self) -> bool:
        """Check if Ollama service is reachable and running."""
        url = f"{self.base_url}/api/version"
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                resp = await client.get(url)
                return resp.status_code == 200
        except Exception:
            return False

    async def generate_json(
        self,
        prompt: str,
        system: str | None = None,
    ) -> dict[str, Any]:
        """
        Invoke Ollama /api/generate with JSON mode enabled and parse the structured output.
        """
        url = f"{self.base_url}/api/generate"
        payload: dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.2,
                "top_p": 0.9,
            },
        }
        if system:
            payload["system"] = system

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(url, json=payload)
        except httpx.ConnectError as exc:
            logger.warning("Ollama connection error at %s: %s", self.base_url, exc)
            raise OllamaConnectionError(f"Cannot connect to Ollama at {self.base_url}.") from exc
        except httpx.TimeoutException as exc:
            logger.warning("Ollama request timed out after %.1fs: %s", self.timeout, exc)
            raise OllamaTimeoutError(f"Ollama generation timed out after {self.timeout}s.") from exc
        except Exception as exc:
            logger.error("Unexpected error contacting Ollama: %s", exc)
            raise OllamaError(f"Failed to communicate with Ollama: {exc}") from exc

        if response.status_code != 200:
            logger.error("Ollama returned HTTP %d: %s", response.status_code, response.text)
            raise OllamaResponseError(f"Ollama returned HTTP {response.status_code}: {response.text[:200]}")

        try:
            data = response.json()
            raw_text = data.get("response", "").strip()
            if not raw_text:
                raise OllamaResponseError("Ollama returned an empty response body.")
            return json.loads(raw_text)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse JSON from Ollama response: %s", raw_text if 'raw_text' in locals() else response.text)
            raise OllamaResponseError(f"Malformed JSON from Ollama: {exc}") from exc

    async def chat(
        self,
        messages: list[dict[str, str]],
    ) -> str:
        """
        Invoke Ollama /api/chat with a multi-turn message list.
        """
        url = f"{self.base_url}/api/chat"
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": 0.3,
            },
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(url, json=payload)
        except httpx.ConnectError as exc:
            logger.warning("Ollama chat connection error at %s: %s", self.base_url, exc)
            raise OllamaConnectionError(f"Cannot connect to Ollama at {self.base_url}.") from exc
        except httpx.TimeoutException as exc:
            logger.warning("Ollama chat timed out after %.1fs: %s", self.timeout, exc)
            raise OllamaTimeoutError(f"Ollama chat timed out after {self.timeout}s.") from exc
        except Exception as exc:
            logger.error("Unexpected error during Ollama chat: %s", exc)
            raise OllamaError(f"Ollama chat failed: {exc}") from exc

        if response.status_code != 200:
            raise OllamaResponseError(f"Ollama chat returned HTTP {response.status_code}")

        data = response.json()
        message_obj = data.get("message", {})
        return message_obj.get("content", "").strip()
