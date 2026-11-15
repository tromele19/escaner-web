"""Descarga acotada de CVE desde la API 2.0 de NVD (RF-08).

Solo se descargan las CVE de los productos que la herramienta sabe reconocer
(``PRODUCTS``), y de cada una solo lo necesario: identificador, puntuación
CVSS, fecha y rangos de versiones afectadas. El resultado se guarda en un
fichero JSON local, de modo que los escaneos no consultan NVD (no se filtra a
terceros qué sitios se analizan) y funcionan sin conexión.

Sin clave de API, NVD permite 5 peticiones cada 30 s: se espera 6 s entre
peticiones. Con ``NVD_API_KEY`` (gratuita) el límite es mayor.

NVD responde a menudo con 503 cuando está saturado: cada petición se
reintenta con espera creciente y, si un producto sigue fallando, se guardan
los demás y se indica cuál ha quedado incompleto.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import requests

from escaner.cve import PRODUCTS

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE = 500  # páginas pequeñas: NVD devuelve 503 con frecuencia en consultas grandes
RETRY_WAITS = (10, 20, 40, 80)  # segundos entre reintentos ante 429/5xx
RETRY_STATUS = {429, 500, 502, 503, 504}


def default_db_path() -> Path:
    base = os.environ.get("ESCANER_DATA_DIR")
    return (Path(base) if base else Path.home() / ".escaner-web") / "cve.json"


def update_database(
    path: Path | None = None,
    *,
    session: requests.Session | None = None,
    api_key: str | None = None,
    sleep: Callable[[float], None] = time.sleep,
    progress: Callable[[str], None] = lambda msg: None,
) -> dict:
    """Descarga las CVE de todos los productos conocidos y las guarda en ``path``."""
    path = path or default_db_path()
    session = session or requests.Session()
    api_key = api_key if api_key is not None else os.environ.get("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else {}
    pause = 0.7 if api_key else 6.0

    db = {
        "generated": datetime.now(UTC).isoformat(),
        "source": API,
        "products": {},
        "incomplete": [],
    }
    first = True
    for key, (name, cpes) in PRODUCTS.items():
        entries: dict[str, dict] = {}
        try:
            for vendor, product in cpes:
                start = 0
                while True:
                    if not first:
                        sleep(pause)
                    first = False
                    params = {
                        "virtualMatchString": f"cpe:2.3:a:{vendor}:{product}",
                        "resultsPerPage": PAGE,
                        "startIndex": start,
                    }
                    data = _get_with_retries(session, params, headers, sleep, progress)
                    for item in data.get("vulnerabilities", []):
                        entry = parse_cve(item.get("cve", {}), vendor, product)
                        if entry:
                            old = entries.get(entry["id"])
                            if old:
                                old["ranges"].extend(entry["ranges"])
                            else:
                                entries[entry["id"]] = entry
                    start += data.get("resultsPerPage", 0) or PAGE
                    if start >= data.get("totalResults", 0):
                        break
        except requests.exceptions.RequestException as exc:
            db["incomplete"].append(key)
            progress(f"{name}: no se ha podido descargar ({exc.__class__.__name__}), se omite")
        db["products"][key] = sorted(entries.values(), key=lambda e: e["id"])
        if key not in db["incomplete"]:
            progress(f"{name}: {len(entries)} CVE")

    if len(db["incomplete"]) == len(PRODUCTS):
        raise requests.exceptions.ConnectionError(
            "NVD no ha respondido para ningún producto; inténtalo más tarde"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(db, separators=(",", ":")), encoding="utf-8")
    tmp.replace(path)
    return db


def _get_with_retries(session, params, headers, sleep, progress) -> dict:
    """Petición a NVD con reintentos y espera creciente ante 429 y errores 5xx."""
    for attempt, wait in enumerate((*RETRY_WAITS, None)):
        try:
            resp = session.get(API, params=params, headers=headers, timeout=60)
            if resp.status_code not in RETRY_STATUS:
                resp.raise_for_status()
                return resp.json()
            error = requests.exceptions.HTTPError(f"{resp.status_code} de NVD")
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
            error = exc
        if wait is None:
            raise error
        progress(f"  NVD no responde ({error}); reintento {attempt + 1} en {wait} s")
        sleep(wait)
    raise AssertionError("inalcanzable")


def parse_cve(cve: dict, vendor: str, product: str) -> dict | None:
    """Extrae de una CVE de NVD los rangos de versiones afectadas del producto."""
    prefix = f"cpe:2.3:a:{vendor}:{product}:"
    ranges = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                if not match.get("vulnerable") or not criteria.startswith(prefix):
                    continue
                version = criteria[len(prefix) :].split(":")[0]
                r = {
                    k: match[k]
                    for k in (
                        "versionStartIncluding",
                        "versionStartExcluding",
                        "versionEndIncluding",
                        "versionEndExcluding",
                    )
                    if match.get(k)
                }
                if version not in {"*", "-", ""}:
                    r = {"exact": version}
                if r:
                    ranges.append(r)
                elif version == "*":
                    ranges.append({"all": True})
    if not ranges:
        return None
    return {
        "id": cve.get("id"),
        "cvss": cvss_score(cve.get("metrics", {})),
        "published": (cve.get("published") or "")[:10],
        "ranges": ranges,
    }


def cvss_score(metrics: dict) -> float | None:
    """Puntuación base: CVSS 4.0, 3.1, 3.0 o 2.0, la más moderna disponible."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        primary = next(
            (m for m in items if m.get("type") == "Primary"), items[0] if items else None
        )
        if primary:
            return primary.get("cvssData", {}).get("baseScore")
    return None
