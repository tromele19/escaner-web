"""Modelos de datos compartidos por todas las capas.

La capa de análisis produce objetos ``Finding`` normalizados; el motor de
puntuación los convierte en notas y la capa de IA solo recibe versiones
saneadas de estos objetos (nunca los datos en bruto de la adquisición).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum


class Severity(StrEnum):
    """Severidad de un hallazgo (tabla 12 de la memoria)."""

    CRITICAL = "critica"
    HIGH = "alta"
    MEDIUM = "media"
    LOW = "baja"
    INFO = "informativa"

    @property
    def penalty(self) -> int:
        """Puntos que resta el hallazgo a su categoría."""
        return _PENALTIES[self]


_PENALTIES: dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 25,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
    Severity.INFO: 0,
}


class Category(StrEnum):
    """Categorías de análisis, una por motor."""

    HEADERS = "cabeceras"
    COOKIES = "cookies"
    TLS = "tls"
    PATHS = "rutas"
    CONTENT = "contenido"
    TECH = "tecnologias"


class ScanMode(StrEnum):
    """Modo de escaneo (apartado 4.2 de la memoria)."""

    PASSIVE = "pasivo"
    FULL = "completo"


@dataclass(frozen=True, slots=True)
class Finding:
    """Hallazgo normalizado producido por un motor de análisis.

    ``rule_id`` es un identificador de una lista cerrada (p. ej.
    ``HSTS_MISSING_SUBDOMAINS``); es lo único que se envía al modelo de IA.
    ``evidence`` es un resumen corto para el informe técnico y nunca se
    envía al modelo.
    """

    category: Category
    rule_id: str
    severity: Severity
    title: str
    evidence: str = ""
    reference: str = ""
    bonus: int = 0

    def __post_init__(self) -> None:
        if not self.rule_id or not self.rule_id.replace("_", "").isalnum():
            raise ValueError(f"rule_id no válido: {self.rule_id!r}")
        if not self.rule_id.isupper():
            raise ValueError(f"rule_id debe ir en mayúsculas: {self.rule_id!r}")
        if self.bonus < 0:
            raise ValueError("bonus no puede ser negativo")


@dataclass(slots=True)
class ScanContext:
    """Datos obtenidos en la fase de adquisición y compartidos por los motores."""

    target_url: str
    mode: ScanMode = ScanMode.PASSIVE
    final_url: str | None = None
    status_code: int | None = None
    redirect_chain: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    raw_set_cookies: list[str] = field(default_factory=list)
    html: str | None = None
    tls_info: dict[str, object] | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(slots=True)
class ScanResult:
    """Resultado completo de un escaneo, listo para puntuar y persistir."""

    context: ScanContext
    findings: list[Finding] = field(default_factory=list)
    evaluated_categories: set[Category] = field(default_factory=set)
    category_scores: dict[Category, int] = field(default_factory=dict)
    global_score: float | None = None
    grade: str | None = None
    rubric_version: str = "1.0"

    def findings_for(self, category: Category) -> list[Finding]:
        return [f for f in self.findings if f.category == category]
