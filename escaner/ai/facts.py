"""Partes del informe que se calculan en código, no con IA.

La explicación de la nota y la lista de hallazgos que el plan no cubre se
generan de forma determinista a partir del resultado técnico: son cifras y
deben ser exactas, cosa que un modelo pequeño no garantiza.
"""

from __future__ import annotations

from escaner.rules.tls import FAIL_GRADE_RULES
from escaner.scoring import CRITICAL_CAP, HIGH_CAP, NO_VALID_HTTPS_CAP

SEVERITY_ORDER = ["critica", "alta", "media", "baja", "informativa"]
PLAN_SEVERITIES = {"critica", "alta", "media"}


def explain_score(data: dict) -> str:
    cats = sorted(data.get("categorias", {}).items(), key=lambda kv: kv[1])
    problems = [h for h in data["hallazgos"] if not h["buena_practica"]]
    counts = {
        s: sum(h.get("veces", 1) for h in problems if h["severidad"] == s) for s in SEVERITY_ORDER
    }
    parts = [
        f"Nota {data.get('letra')} ({data.get('nota_global')}/100), media ponderada de "
        f"{len(cats)} categorías."
    ]
    weak = [f"{c} {v}" for c, v in cats if v < 100][:3]
    if weak:
        parts.append("Las que más restan: " + ", ".join(weak) + ".")
    summary = ", ".join(f"{n} {s}" for s, n in counts.items() if n and s != "informativa")
    if summary:
        parts.append(f"Problemas encontrados: {summary}.")
    ids = {h["id"] for h in problems}
    if ids & FAIL_GRADE_RULES:
        parts.append(f"Sin HTTPS válido la nota se limita a {NO_VALID_HTTPS_CAP} (F).")
    elif counts["critica"]:
        parts.append(
            f"Hay al menos un hallazgo crítico, así que la nota se limita a "
            f"{CRITICAL_CAP} (D) aunque el resto esté bien."
        )
    elif counts["alta"] and (data.get("nota_global") or 0) >= HIGH_CAP:
        parts.append(
            f"Hay hallazgos de severidad alta, así que la nota se limita a {HIGH_CAP} (B) "
            "aunque el resto esté bien."
        )
    if data.get("modo") == "pasivo":
        parts.append("Modo pasivo: no se han comprobado rutas sensibles.")
    return " ".join(parts)


def uncovered(data: dict, plan: list[dict]) -> list[dict]:
    """Hallazgos de severidad media o superior que el plan de la IA no cita."""
    cited = {rid for step in plan for rid in step["hallazgos"]}
    pending = [
        h
        for h in data["hallazgos"]
        if not h["buena_practica"] and h["severidad"] in PLAN_SEVERITIES and h["id"] not in cited
    ]
    return sorted(pending, key=lambda h: SEVERITY_ORDER.index(h["severidad"]))
