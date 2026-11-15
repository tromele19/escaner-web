"""Adaptadores de proveedor del modelo de lenguaje.

- ``ollama`` (por defecto): modelo local servido por Ollama. Nada sale del equipo.
- ``api``: cualquier API compatible con el formato de OpenAI (alternativa).

La configuración se lee de variables de entorno o del fichero ``.env`` del
directorio actual (que nunca se sube al repositorio). El modelo no tiene
herramientas ni permisos: solo recibe texto y devuelve texto.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import requests

ENV_KEYS = {
    "ESCANER_AI_PROVIDER",
    "ESCANER_OLLAMA_URL",
    "ESCANER_OLLAMA_MODEL",
    "ESCANER_API_BASE_URL",
    "ESCANER_API_KEY",
    "ESCANER_API_MODEL",
}


class AIError(Exception):
    """El proveedor de IA no está disponible o ha fallado."""


class Provider(Protocol):
    name: str

    def chat(self, system: str, user: str, schema: dict | None = None) -> str: ...


def load_env(path: Path | None = None) -> dict[str, str]:
    """Lee ``.env`` (solo claves conocidas). Las variables de entorno tienen prioridad."""
    values: dict[str, str] = {}
    path = path or Path.cwd() / ".env"
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            key, sep, value = line.strip().partition("=")
            if sep and key.strip() in ENV_KEYS:
                values[key.strip()] = value.strip().strip("\"'")
    values.update({k: os.environ[k] for k in ENV_KEYS if os.environ.get(k)})
    return values


@dataclass
class OllamaProvider:
    url: str = "http://localhost:11434"
    model: str = "qwen2.5:3b"
    timeout: float = 180.0
    name: str = "ollama"

    def chat(self, system: str, user: str, schema: dict | None = None) -> str:
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "options": {"temperature": 0.2},
        }
        if schema:
            body["format"] = schema  # salida estructurada: el modelo debe cumplir el esquema
        try:
            resp = requests.post(
                f"{self.url.rstrip('/')}/api/chat", json=body, timeout=self.timeout
            )
            resp.raise_for_status()
            return resp.json()["message"]["content"]
        except (requests.exceptions.RequestException, KeyError, ValueError) as exc:
            raise AIError(f"Ollama no responde en {self.url}: {exc}") from exc


@dataclass
class OpenAICompatibleProvider:
    base_url: str
    api_key: str
    model: str
    timeout: float = 120.0
    name: str = "api"

    def chat(self, system: str, user: str, schema: dict | None = None) -> str:
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": 0.2,
        }
        if schema:
            body["response_format"] = {"type": "json_object"}
        try:
            resp = requests.post(
                f"{self.base_url.rstrip('/')}/chat/completions",
                json=body,
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
        except (requests.exceptions.RequestException, KeyError, IndexError, ValueError) as exc:
            raise AIError(f"La API de IA ha fallado: {exc}") from exc


def get_provider(env: dict[str, str] | None = None) -> Provider:
    env = load_env() if env is None else env
    if env.get("ESCANER_AI_PROVIDER", "ollama") == "api":
        missing = [
            k
            for k in ("ESCANER_API_BASE_URL", "ESCANER_API_KEY", "ESCANER_API_MODEL")
            if not env.get(k)
        ]
        if missing:
            raise AIError(f"Falta configurar en .env: {', '.join(missing)}")
        return OpenAICompatibleProvider(
            env["ESCANER_API_BASE_URL"], env["ESCANER_API_KEY"], env["ESCANER_API_MODEL"]
        )
    return OllamaProvider(
        url=env.get("ESCANER_OLLAMA_URL") or "http://localhost:11434",
        model=env.get("ESCANER_OLLAMA_MODEL") or "qwen2.5:3b",
    )


def describe(provider: Provider) -> str:
    return f"{provider.name}:{getattr(provider, 'model', '?')}"


def dumps(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, indent=1)
