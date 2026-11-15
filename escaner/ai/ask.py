"""Modo «pregunta al informe» (RF-13).

El modelo solo ve el resultado saneado y el informe ya generado; la pregunta
del usuario se limita de longitud. La respuesta se marca si cita
identificadores que no existen en el informe.
"""

from __future__ import annotations

import re

from escaner.ai.prompts import SYSTEM_ASK
from escaner.ai.providers import Provider, dumps
from escaner.ai.report import clean
from escaner.ai.sanitizer import allowed_ids
from escaner.rules import RULES

MAX_QUESTION = 300
MAX_ANSWER = 2500
RULE_LIKE = re.compile(r"\b[A-Z][A-Z0-9]+(?:_[A-Z0-9]+)+\b")


def ask(sanitized: dict, report: dict | None, question: str, provider: Provider) -> dict:
    question = clean(question, MAX_QUESTION)
    if not question:
        raise ValueError("La pregunta está vacía")
    context = {"resultado": sanitized, "informe": report or {}}
    answer = clean(
        provider.chat(SYSTEM_ASK, "INFORME:\n" + dumps(context) + "\n\nPREGUNTA:\n" + question),
        MAX_ANSWER,
        keep_newlines=True,
    )
    allowed = allowed_ids(sanitized)
    invented = sorted({m for m in RULE_LIKE.findall(answer) if m in RULES and m not in allowed})
    return {"pregunta": question, "respuesta": answer, "citas_no_validas": invented}
