"""Informe explicativo y plan de remediación priorizado con IA (RF-12).

La salida del modelo es un dato NO confiable, así que se valida antes de
usarla:
- tiene que ser JSON con la estructura esperada;
- cada paso del plan solo puede citar identificadores que estén en el
  resultado técnico (si cita uno inventado, ese paso se descarta);
- los textos se limitan de longitud y se eliminan caracteres de control.
Si la respuesta no es válida se reintenta una vez; si vuelve a fallar no hay
informe de IA, pero la nota y el informe técnico siguen disponibles
(degradación controlada, RNF-04).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from escaner.ai.prompts import PROFILES, REPORT_SCHEMA, SYSTEM_REPORT
from escaner.ai.providers import AIError, Provider, dumps
from escaner.ai.sanitizer import allowed_ids

MAX_TEXT = 1200
MAX_CONFIG = 1500
MAX_STEPS = 10


@dataclass
class ReportResult:
    report: dict | None
    attempts: int
    discarded: list[str] = field(default_factory=list)  # motivos de lo descartado
    error: str | None = None


def generate_report(
    sanitized: dict, provider: Provider, profile: str = "divulgativo", max_attempts: int = 2
) -> ReportResult:
    if profile not in PROFILES:
        raise ValueError(f"Perfil desconocido: {profile}")
    system = SYSTEM_REPORT.format(lector=PROFILES[profile])
    user = (
        "Esquema de la respuesta:\n" + json.dumps(REPORT_SCHEMA) + "\n\nDATOS:\n" + dumps(sanitized)
    )
    result = ReportResult(report=None, attempts=0)
    for _ in range(max_attempts):
        result.attempts += 1
        try:
            raw = provider.chat(system, user, schema=REPORT_SCHEMA)
        except AIError as exc:
            result.error = str(exc)
            return result  # sin conexión con el modelo: no tiene sentido reintentar
        report, problems = validate_report(raw, allowed_ids(sanitized))
        result.discarded.extend(problems)
        if report is not None:
            result.report = report
            return result
    result.error = "El modelo no devolvió un informe válido"
    return result


def validate_report(raw: str, allowed: set[str]) -> tuple[dict | None, list[str]]:
    """Valida la respuesta del modelo. Devuelve (informe o None, problemas)."""
    problems: list[str] = []
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return None, ["la respuesta no es JSON"]
    if (
        not isinstance(data, dict)
        or not all(isinstance(data.get(k), str) for k in ("resumen", "nota_explicada"))
        or not isinstance(data.get("plan"), list)
    ):
        return None, ["la respuesta no tiene la estructura esperada"]

    steps = []
    for step in data["plan"][:MAX_STEPS]:
        if not isinstance(step, dict) or not isinstance(step.get("hallazgos"), list):
            problems.append("paso del plan mal formado")
            continue
        cited = [h for h in step["hallazgos"] if isinstance(h, str)]
        invented = [h for h in cited if h not in allowed]
        if invented or not cited:
            problems.append(f"paso que cita hallazgos inexistentes: {', '.join(invented) or '-'}")
            continue
        steps.append(
            {
                "prioridad": len(steps) + 1,
                "hallazgos": cited,
                "accion": clean(step.get("accion"), MAX_TEXT),
                "por_que": clean(step.get("por_que"), MAX_TEXT),
                "esfuerzo": step.get("esfuerzo")
                if step.get("esfuerzo") in {"bajo", "medio", "alto"}
                else "medio",
                "configuracion": clean(step.get("configuracion"), MAX_CONFIG, keep_newlines=True),
            }
        )
    if allowed - {"SECURITY_TXT_PRESENT"} and not steps:
        return None, [*problems, "plan vacío"]
    return {
        "resumen": clean(data["resumen"], MAX_TEXT),
        "nota_explicada": clean(data["nota_explicada"], MAX_TEXT),
        "plan": steps,
    }, problems


def clean(value, limit: int, keep_newlines: bool = False) -> str:
    if not isinstance(value, str):
        return ""
    allowed = {"\n", "\t"} if keep_newlines else set()
    text = "".join(ch if ch.isprintable() or ch in allowed else " " for ch in value).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"
