"""LLM provider abstraction. Credentials stay on the server; the browser never sees them.

Two HTTP providers are supported:
  * openai_compatible: any server exposing /v1/chat/completions (OpenAI, a local Ollama or LM Studio)
  * anthropic: the Anthropic Messages API

Providers have no tools and no ability to act: they receive text and return text.
"""

import httpx


class ProviderError(Exception):
    pass


class LLMProvider:
    name = "base"

    def complete(self, system: str, user: str) -> str:
        raise NotImplementedError


class OpenAICompatibleProvider(LLMProvider):
    name = "openai_compatible"

    def __init__(self, base_url: str, api_key: str | None, model: str, timeout: float, transport=None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.transport = transport

    def complete(self, system: str, user: str) -> str:
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        body = {"model": self.model, "temperature": 0.1, "max_tokens": 1200,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        try:
            with httpx.Client(timeout=self.timeout, transport=self.transport) as client:
                response = client.post(f"{self.base_url}/chat/completions", json=body, headers=headers)
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"]
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            raise ProviderError(type(exc).__name__) from exc


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, api_key: str, model: str, timeout: float, base_url: str | None = None, transport=None):
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.base_url = (base_url or "https://api.anthropic.com").rstrip("/")
        self.transport = transport

    def complete(self, system: str, user: str) -> str:
        headers = {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"}
        body = {"model": self.model, "max_tokens": 1200, "system": system,
                "messages": [{"role": "user", "content": user}]}
        try:
            with httpx.Client(timeout=self.timeout, transport=self.transport) as client:
                response = client.post(f"{self.base_url}/v1/messages", json=body, headers=headers)
            response.raise_for_status()
            return "".join(block.get("text", "") for block in response.json()["content"])
        except (httpx.HTTPError, KeyError, ValueError, TypeError) as exc:
            raise ProviderError(type(exc).__name__) from exc
