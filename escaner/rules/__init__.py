"""Catálogo de reglas: cada comprobación definida como datos (RNF-06).

Cada regla tiene un identificador de una **lista cerrada** (``HSTS_MISSING``,
``CSP_UNSAFE_INLINE``...). Los motores solo deciden *si* se cumple una regla;
la severidad, el título y la referencia salen de aquí, de modo que ajustar la
rúbrica no obliga a tocar el código de los motores.

Esa misma lista cerrada es la que usará la capa de IA: el modelo solo recibe
identificadores de este catálogo, nunca texto procedente del sitio analizado.
"""

from __future__ import annotations

from dataclasses import dataclass

from escaner.models import Category, Finding, Severity

RUBRIC_VERSION = "1.0"


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    category: Category
    severity: Severity
    title: str
    reference: str = ""
    bonus: int = 0


RULES: dict[str, Rule] = {}

MAX_EVIDENCE = 120


def register(*rules: Rule) -> None:
    for rule in rules:
        if rule.rule_id in RULES:
            raise ValueError(f"Regla duplicada: {rule.rule_id}")
        RULES[rule.rule_id] = rule


def finding(rule_id: str, evidence: str = "") -> Finding:
    """Crea un ``Finding`` a partir de una regla del catálogo."""
    rule = RULES[rule_id]  # KeyError si el motor usa una regla inexistente
    evidence = " ".join(evidence.split())
    if len(evidence) > MAX_EVIDENCE:
        evidence = evidence[: MAX_EVIDENCE - 1] + "…"
    return Finding(
        category=rule.category,
        rule_id=rule.rule_id,
        severity=rule.severity,
        title=rule.title,
        evidence=evidence,
        reference=rule.reference,
        bonus=rule.bonus,
    )


# Importar los módulos de reglas los registra en RULES.
from escaner.rules import cookies as _cookies  # noqa: E402,F401
from escaner.rules import headers as _headers  # noqa: E402,F401
