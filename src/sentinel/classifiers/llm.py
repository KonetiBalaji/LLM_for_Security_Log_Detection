"""LLM-based classifier with real API integration and simulation fallback."""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

import requests

from sentinel.classifiers.base import Classifier
from sentinel.core.config import SentinelSettings, get_settings
from sentinel.core.enums import ClassificationMethod
from sentinel.core.exceptions import LLMError

logger = logging.getLogger(__name__)

_CLASSIFICATION_PROMPT = """Analyze this log message and classify it into exactly one category:
1. Security Alert
2. Critical Error
3. System Notification
4. HTTP Status
5. Resource Usage
6. User Action
7. Workflow Error
8. Deprecation Warning
9. Error

If you cannot determine a category, respond with "Unclassified".

Put the category inside <category></category> tags.
Provide technical reasoning inside <reasoning></reasoning> tags.

Log message: {log_message}"""

_CATEGORY_RE = re.compile(r"<category>(.*?)</category>", re.DOTALL)
_REASONING_RE = re.compile(r"<reasoning>(.*?)</reasoning>", re.DOTALL)

# Retry configuration
_MAX_RETRIES = 2
_RETRY_BACKOFF = 1.5


class LLMClassifier(Classifier):
    """Classify using a remote LLM API (OpenAI-compatible).

    Falls back to :class:`SimulatedLLMClassifier` when no API key is configured.
    """

    def __init__(self, settings: SentinelSettings | None = None) -> None:
        self._settings = settings or get_settings()
        self._api_url = "https://api.openai.com/v1/chat/completions"

    @property
    def method(self) -> ClassificationMethod:
        return ClassificationMethod.LLM

    def classify(self, log_message: str) -> tuple[str | None, float]:
        if not self._settings.has_llm_key:
            return SimulatedLLMClassifier().classify(log_message)
        return self._call_api(log_message)

    def classify_with_reasoning(self, log_message: str) -> dict[str, Any]:
        """Return full classification including reasoning text."""
        if not self._settings.has_llm_key:
            return SimulatedLLMClassifier().classify_with_reasoning(log_message)
        return self._call_api_full(log_message)

    # ------------------------------------------------------------------
    # API interaction
    # ------------------------------------------------------------------
    def _call_api(self, log_message: str) -> tuple[str | None, float]:
        result = self._call_api_full(log_message)
        return result.get("category"), result.get("confidence", 0.8)

    def _call_api_full(self, log_message: str) -> dict[str, Any]:
        prompt = _CLASSIFICATION_PROMPT.format(log_message=log_message)
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self._settings.openai_api_key}",
        }
        payload = {
            "model": self._settings.llm_model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self._settings.llm_temperature,
            "max_tokens": self._settings.llm_max_tokens,
        }

        last_error: Exception | None = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                response = requests.post(
                    self._api_url,
                    headers=headers,
                    json=payload,
                    timeout=self._settings.llm_timeout_seconds,
                )
                if response.status_code == 429:
                    wait = _RETRY_BACKOFF * (2 ** attempt)
                    logger.warning("Rate limited, waiting %.1fs", wait)
                    time.sleep(wait)
                    continue

                if response.status_code != 200:
                    raise LLMError(
                        f"LLM API returned {response.status_code}",
                        details={"body": response.text[:500]},
                    )

                content = response.json()["choices"][0]["message"]["content"]
                return self._parse_response(content)

            except requests.RequestException as exc:
                last_error = exc
                logger.warning("LLM API attempt %d failed: %s", attempt + 1, exc)
                if attempt < _MAX_RETRIES:
                    time.sleep(_RETRY_BACKOFF * (2 ** attempt))

        logger.error("All LLM API attempts failed, falling back to simulation")
        if last_error:
            logger.debug("Last error: %s", last_error)
        return SimulatedLLMClassifier().classify_with_reasoning(log_message)

    @staticmethod
    def _parse_response(response_text: str) -> dict[str, Any]:
        category_match = _CATEGORY_RE.search(response_text)
        reasoning_match = _REASONING_RE.search(response_text)

        category = category_match.group(1).strip() if category_match else "Unclassified"
        reasoning = reasoning_match.group(1).strip() if reasoning_match else ""

        return {
            "category": category,
            "confidence": 0.85,
            "reasoning": reasoning,
            "raw_response": response_text,
        }


class SimulatedLLMClassifier(Classifier):
    """Deterministic keyword-based fallback when no LLM API key is available.

    Clearly labelled as simulation — never presented as real LLM output.
    """

    _KEYWORD_MAP: list[tuple[list[str], str, str]] = [
        (
            ["authentication fail", "unauthorized", "suspicious", "brute force"],
            "Security Alert",
            "Log indicates a potential security threat.",
        ),
        (
            ["error", "exception", "crash", "critical"],
            "Critical Error",
            "Log indicates a system error that may affect functionality.",
        ),
        (
            ["backup", "update", "reboot", "restart"],
            "System Notification",
            "Log describes a routine system operation.",
        ),
        (
            ["http", "get /", "post /", "status: "],
            "HTTP Status",
            "Log contains HTTP request information.",
        ),
        (
            ["memory", "cpu", "disk", "usage", "resource"],
            "Resource Usage",
            "Log reports system resource utilization.",
        ),
        (
            ["user", "login", "logged in", "logged out"],
            "User Action",
            "Log describes a user-initiated action.",
        ),
        (
            ["workflow", "process", "task", "failed"],
            "Workflow Error",
            "Log indicates a workflow or process failure.",
        ),
        (
            ["deprecated", "will be removed", "outdated", "retired"],
            "Deprecation Warning",
            "Log warns about deprecated functionality.",
        ),
    ]

    @property
    def method(self) -> ClassificationMethod:
        return ClassificationMethod.LLM

    def classify(self, log_message: str) -> tuple[str | None, float]:
        result = self.classify_with_reasoning(log_message)
        return result["category"], result["confidence"]

    def classify_with_reasoning(self, log_message: str) -> dict[str, Any]:
        lower = log_message.lower()
        for keywords, category, reasoning in self._KEYWORD_MAP:
            if any(kw in lower for kw in keywords):
                return {
                    "category": category,
                    "confidence": 0.70,
                    "reasoning": f"[Simulated] {reasoning}",
                    "raw_response": "",
                }
        return {
            "category": "Unclassified",
            "confidence": 0.0,
            "reasoning": "[Simulated] Unable to classify this log message.",
            "raw_response": "",
        }
