"""Motor 6 — tecnologías y vulnerabilidades conocidas (RF-08).

1. Detecta el software y la versión que el sitio anuncia (cabeceras, meta
   generator, librerías JavaScript), sin peticiones adicionales.
2. Cruza cada versión con la base local de CVE descargada de NVD.

Cada coincidencia se presenta como «posible» y «a verificar»: por el
backporting, la versión anunciada no confirma la vulnerabilidad. Por eso se
agrupa en UN hallazgo por producto (con su CVSS máximo) en lugar de penalizar
cada CVE por separado.
"""

from __future__ import annotations

from pathlib import Path

from escaner.cve import PRODUCTS
from escaner.cve.fingerprint import detect
from escaner.cve.matcher import CVEDatabase
from escaner.cve.updater import default_db_path
from escaner.engines.base import Engine
from escaner.models import Category, Finding, ScanContext
from escaner.rules import finding


class TechEngine(Engine):
    category = Category.TECH

    def __init__(self, db: CVEDatabase | None = None, db_path: Path | None = None) -> None:
        self._db = db
        self._db_path = db_path
        self._loaded = db is not None

    @property
    def db(self) -> CVEDatabase | None:
        if not self._loaded:
            self._db = CVEDatabase.load(self._db_path or default_db_path())
            self._loaded = True
        return self._db

    def is_evaluable(self, context: ScanContext) -> bool:
        return bool(context.headers)

    def analyze(self, context: ScanContext) -> list[Finding]:
        techs = detect(context.headers, context.html)
        findings: list[Finding] = []
        db = self.db
        missing_db = False

        for tech in techs:
            name = PRODUCTS[tech.product][0]
            if not tech.version:
                continue  # anuncia el producto pero no la versión: no se penaliza
            label = f"{name} {tech.version}"
            findings.append(finding("TECH_VERSION_DISCLOSED", f"{label} ({tech.source})"))
            if db is None:
                missing_db = True
                continue
            matches = db.lookup(tech.product, tech.version)
            if not matches:
                continue
            top = max((m.cvss or 0) for m in matches)
            rule = (
                "TECH_CVE_HIGH" if top >= 7 else "TECH_CVE_MEDIUM" if top >= 4 else "TECH_CVE_LOW"
            )
            ids = ", ".join(m.cve_id for m in matches[:3])
            findings.append(
                finding(rule, f"{label}: {len(matches)} CVE posibles, CVSS máx. {top:g} ({ids})")
            )

        if missing_db:
            findings.append(finding("TECH_CVE_DB_MISSING"))
        return findings
