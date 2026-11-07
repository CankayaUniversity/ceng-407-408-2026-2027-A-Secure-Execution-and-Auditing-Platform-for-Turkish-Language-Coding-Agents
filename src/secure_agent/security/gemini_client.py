"""Gemini adapter for the existing Supervisor protocol; no tools are exposed."""

import math
import os
from pathlib import Path
import re

import httpx
from dotenv import dotenv_values

from secure_agent.security.supervisor import MAX_RESPONSE_BYTES, _LLMVerdict

DEFAULT_MODEL = "gemini-3.1-flash-lite"


class GeminiClient:
    def __init__(self, *, model: str = DEFAULT_MODEL, env_file: str | Path | None = None,
                 timeout: float = 30.0):
        if not isinstance(model, str) or not re.fullmatch(r"gemini-[a-zA-Z0-9._-]+", model):
            raise ValueError("An explicit Gemini model ID is required.")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a finite positive number.")
        path = Path(env_file) if env_file is not None else Path(__file__).resolve().parents[3] / ".env"
        key = os.getenv("GEMINI_API_KEY") or dotenv_values(path).get("GEMINI_API_KEY")
        if not key or not key.strip():
            raise ValueError("Set GEMINI_API_KEY in the project .env file.")
        self._model = model
        self._client = httpx.Client(timeout=timeout, headers={"x-goog-api-key": key.strip()})

    def complete(self, *, system_prompt: str, user_prompt: str) -> str:
        try:
            response = self._client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{self._model}:generateContent",
                json={
                    "systemInstruction": {"parts": [{"text": system_prompt}]},
                    "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
                    "generationConfig": {
                        "responseMimeType": "application/json",
                        "responseJsonSchema": _LLMVerdict.model_json_schema(),
                        "maxOutputTokens": 2048,
                    },
                },
            )
            if response.status_code != 200:
                raise ValueError("Gemini request failed.")
            if len(response.content) > 65_536:
                raise ValueError("Gemini response is too large.")
            candidates = response.json().get("candidates", [])
            if len(candidates) != 1 or candidates[0].get("finishReason") != "STOP":
                raise ValueError("Gemini response did not complete.")
            parts = candidates[0]["content"]["parts"]
            text = "".join(part["text"] for part in parts if not part.get("thought"))
            if not text.strip() or len(text.encode("utf-8")) > MAX_RESPONSE_BYTES:
                raise ValueError("Gemini returned invalid text.")
            return text
        except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError):
            # Avoid exposing credentials, provider bodies, or untrusted text in errors.
            raise ValueError("Gemini Supervisor request failed or returned an incomplete response.") from None

    def close(self) -> None:
        self._client.close()
