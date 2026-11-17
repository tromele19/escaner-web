"""Saneado de los datos que recibe el modelo de IA (RNF-03).

Es la barrera principal frente a la inyección indirecta de instrucciones
(prompt injection): el sitio analizado lo controla un posible atacante, así que
NADA de lo que envía (HTML, cabeceras, valores de cookies, rutas encontradas,
evidencias) llega literalmente al modelo.

El modelo solo recibe un JSON cerrado con:
- el dominio (normalizado por el validador), la nota y las notas por categoría;
- cada hallazgo como identificador de una lista cerrada (``HSTS_MISSING``...),
  con su categoría, severidad y título, que salen del catálogo de reglas, no
  del sitio;
- para las tecnologías, el producto (de una lista cerrada) y una versión que
  solo puede contener dígitos y puntos.

Cualquier identificador que no esté en el catálogo se descarta.
"""

from __future__ import annotations

import re
from collections import Counter
from urllib.parse import urlsplit

from escaner.cve import PRODUCTS
from escaner.rules import RULES
from escaner.scoring import WEIGHTS

CATEGORIES = {str(c) for c in WEIGHTS}

PRODUCT_NAMES = {name: key for key, (name, _) in PRODUCTS.items()}
TECH_EVIDENCE = re.compile(
    r"^("
    + "|".join(re.escape(n) for n in sorted(PRODUCT_NAMES, key=len, reverse=True))
    + r") (\d{1,4}(?:\.\d{1,4}){0,3})\b"
)
WEB_SERVERS = {"nginx": "nginx", "apache": "apache", "iis": "iis"}
HOST = re.compile(r"^[a-z0-9.-]{1,253}$")


def sanitize(scan: dict) -> dict:
    """Convierte un escaneo guardado (``Storage.get_scan``) en la entrada del modelo."""
    host = (urlsplit(scan.get("url", "")).hostname or "").lower()
    findings, techs = [], []
    seen = set()
    times = Counter(f.get("rule_id", "") for f in scan.get("findings", []))
    for f in scan.get("findings", []):
        rule = RULES.get(f.get("rule_id", ""))
        if rule is None or rule.rule_id in seen:
            continue  # identificador desconocido o repetido: no se envía
        seen.add(rule.rule_id)
        findings.append(
            {
                "id": rule.rule_id,
                "categoria": str(rule.category),
                "severidad": str(rule.severity),
                "titulo": rule.title,
                "buena_practica": rule.bonus > 0,
                "veces": times[rule.rule_id],  # p. ej. versión anunciada por 3 tecnologías
            }
        )
    for f in scan.get("findings", []):
        if f.get("rule_id") == "TECH_VERSION_DISCLOSED":
            m = TECH_EVIDENCE.match(f.get("evidence", ""))
            if m:
                techs.append({"producto": m.group(1), "version": m.group(2)})

    servers = [
        WEB_SERVERS[PRODUCT_NAMES[t["producto"]]]
        for t in techs
        if PRODUCT_NAMES[t["producto"]] in WEB_SERVERS
    ]
    scores = scan.get("category_scores", {})
    return {
        "dominio": host if HOST.match(host) else "sitio-analizado",
        "nota_global": scan.get("global_score"),
        "letra": scan.get("grade"),
        "modo": "completo" if scan.get("mode") == "completo" else "pasivo",
        "categorias": {
            str(c): v for c, v in scores.items() if c in CATEGORIES and isinstance(v, int | float)
        },
        "hallazgos": findings,
        "tecnologias": techs,
        "servidor_web": servers[0] if servers else "desconocido",
    }


def allowed_ids(sanitized: dict) -> set[str]:
    return {f["id"] for f in sanitized["hallazgos"]}
