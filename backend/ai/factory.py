"""Pick the AI provider from configuration (``AI_MODE``), milestone 2C."""
from __future__ import annotations

from backend.ai.interface import AIProvider
from backend.ai.mock import MockProvider
from backend.ai.ollama import OllamaProvider


def get_provider(ai_mode: str, mock_scenario: str, ollama_url: str, ollama_model: str,
                 ollama_timeout: float) -> AIProvider:
    """``ai_mode`` "mock" -> MockProvider(scenario "A"/"B"); "ollama" -> OllamaProvider."""
    mode = (ai_mode or "").strip().lower()
    if mode == "mock":
        return MockProvider(mock_scenario)
    if mode == "ollama":
        return OllamaProvider(ollama_url, ollama_model, ollama_timeout)
    raise ValueError(f"AI_MODE must be 'mock' or 'ollama', not {ai_mode!r}")


__all__ = ["get_provider"]
