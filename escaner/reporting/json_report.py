"""Exportación del resultado a JSON (RF-14, versión básica).

Pensado para integrarlo en otros procesos (caso de uso CU-06). No incluye el
HTML ni las cabeceras completas del sitio: solo el resultado del análisis.
"""

from __future__ import annotations

import json
from typing import Any

from escaner import __version__
from escaner.models import ScanResult
from escaner.scoring import WEIGHTS

SCHEMA_VERSION = "1"


def to_dict(result: ScanResult) -> dict[str, Any]:
    ctx = result.context
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": f"escaner-web {__version__}",
        "rubric_version": result.rubric_version,
        "target": ctx.target_url,
        "final_url": ctx.final_url,
        "status_code": ctx.status_code,
        "mode": str(ctx.mode),
        "scanned_at": ctx.started_at.isoformat(),
        "redirects": ctx.redirect_chain,
        "grade": result.grade,
        "global_score": result.global_score,
        "categories": {
            str(cat): (
                {"score": result.category_scores[cat], "weight": WEIGHTS[cat]}
                if cat in result.category_scores
                else None
            )
            for cat in WEIGHTS
        },
        "findings": [
            {
                "category": str(f.category),
                "rule_id": f.rule_id,
                "severity": str(f.severity),
                "title": f.title,
                "evidence": f.evidence,
                "reference": f.reference,
                "bonus": f.bonus,
            }
            for f in result.findings
        ],
    }


def to_json(result: ScanResult) -> str:
    return json.dumps(to_dict(result), ensure_ascii=False, indent=2)
