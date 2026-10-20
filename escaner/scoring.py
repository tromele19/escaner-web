"""Motor de puntuación: nota por categoría y nota global A–F (RF-09).

Rúbrica (apartado 8.5 de la memoria):
- Cada categoría parte de 100. Cada hallazgo resta según su severidad
  (crítica −40, alta −25, media −10, baja −5, informativa 0) y las buenas
  prácticas suman una bonificación pequeña, sin pasar nunca de 100 ni bajar de 0.
- La nota global es la media ponderada de las categorías **evaluables**; las
  que no aplican (p. ej. cookies en un sitio sin cookies, o rutas sensibles en
  modo pasivo) no cuentan y su peso se reparte entre el resto.
- Reglas de límite: con algún hallazgo crítico la nota no puede ser mejor que D.

El cálculo es determinista: misma entrada, misma nota (RF-09).
"""

from __future__ import annotations

from collections.abc import Iterable

from escaner.models import Category, Finding, ScanResult, Severity
from escaner.rules import RUBRIC_VERSION

WEIGHTS: dict[Category, int] = {
    Category.TLS: 25,
    Category.HEADERS: 20,
    Category.COOKIES: 15,
    Category.TECH: 15,
    Category.PATHS: 15,
    Category.CONTENT: 10,
}

GRADES: list[tuple[int, str]] = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (50, "E"), (0, "F")]

CRITICAL_CAP = 69  # con un hallazgo crítico, como mucho D


def category_score(findings: Iterable[Finding]) -> int:
    """Nota de 0 a 100 de una categoría a partir de sus hallazgos."""
    score = 100
    bonus = 0
    for f in findings:
        score -= f.severity.penalty
        bonus += f.bonus
    return max(0, min(100, score + bonus))


def grade_for(score: float) -> str:
    for minimum, letter in GRADES:
        if score >= minimum:
            return letter
    return "F"


def score_result(result: ScanResult) -> ScanResult:
    """Rellena ``category_scores``, ``global_score`` y ``grade`` del resultado."""
    evaluated = [c for c in WEIGHTS if c in result.evaluated_categories]
    result.category_scores = {c: category_score(result.findings_for(c)) for c in evaluated}
    result.rubric_version = RUBRIC_VERSION

    if not evaluated:
        result.global_score = None
        result.grade = None
        return result

    total_weight = sum(WEIGHTS[c] for c in evaluated)
    weighted = sum(result.category_scores[c] * WEIGHTS[c] for c in evaluated) / total_weight
    if any(f.severity is Severity.CRITICAL for f in result.findings):
        weighted = min(weighted, CRITICAL_CAP)

    result.global_score = round(weighted, 1)
    result.grade = grade_for(result.global_score)
    return result
