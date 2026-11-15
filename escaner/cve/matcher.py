"""Cruce de tecnologías y versiones detectadas con la base local de CVE (RF-08).

Una coincidencia se presenta siempre como «posible vulnerabilidad a verificar»:
muchas distribuciones aplican parches de seguridad sin cambiar el número de
versión (backporting), así que la versión anunciada no basta para confirmarla.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class CVEMatch:
    cve_id: str
    cvss: float | None


class CVEDatabase:
    def __init__(self, data: dict) -> None:
        self.data = data
        self.generated = data.get("generated")

    @classmethod
    def load(cls, path: Path) -> CVEDatabase | None:
        try:
            return cls(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            return None

    def lookup(self, product: str, version: str) -> list[CVEMatch]:
        """CVE que afectan a ``product`` en la versión ``version``, de mayor a menor CVSS."""
        matches = [
            CVEMatch(e["id"], e.get("cvss"))
            for e in self.data.get("products", {}).get(product, [])
            if any(in_range(version, r) for r in e.get("ranges", []))
        ]
        return sorted(matches, key=lambda m: (-(m.cvss or 0), m.cve_id))


def version_key(version: str) -> tuple[int, ...]:
    """'2.4.49' -> (2, 4, 49). Ignora sufijos como '-ubuntu' o 'p1'."""
    parts = []
    for piece in version.split("."):
        m = re.match(r"\d+", piece)
        if not m:
            break
        parts.append(int(m.group()))
    return tuple(parts)


def _cmp(a: str, b: str) -> int:
    ka, kb = version_key(a), version_key(b)
    n = max(len(ka), len(kb))
    ka, kb = ka + (0,) * (n - len(ka)), kb + (0,) * (n - len(kb))
    return (ka > kb) - (ka < kb)


def in_range(version: str, r: dict) -> bool:
    if not version_key(version):
        return False
    if r.get("all"):
        return False  # «todas las versiones» sin rango: demasiado impreciso para avisar
    if "exact" in r:
        return version_key(r["exact"]) != () and _cmp(version, r["exact"]) == 0
    if "versionStartIncluding" in r and _cmp(version, r["versionStartIncluding"]) < 0:
        return False
    if "versionStartExcluding" in r and _cmp(version, r["versionStartExcluding"]) <= 0:
        return False
    if "versionEndIncluding" in r and _cmp(version, r["versionEndIncluding"]) > 0:
        return False
    if "versionEndExcluding" in r and _cmp(version, r["versionEndExcluding"]) >= 0:
        return False
    return True
