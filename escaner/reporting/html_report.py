"""Exportación del informe a HTML y PDF (RF-14).

El informe HTML es un único fichero autocontenido: no carga nada de fuera
(ni scripts, ni fuentes, ni imágenes), así que se puede abrir sin conexión y
adjuntar tal cual.

Seguridad: las evidencias vienen del sitio analizado, que puede ser
malicioso. Por eso:
- la plantilla usa autoescape de Jinja2: todo texto se escapa como HTML;
- el documento lleva una Content-Security-Policy que prohíbe scripts y
  cualquier recurso externo, como segunda barrera;
- solo se enlazan las referencias del catálogo de reglas (escritas por el
  autor), nunca URLs que vengan del sitio.

El PDF se genera a partir del mismo HTML con WeasyPrint si está instalado
(mejor fidelidad, pero necesita librerías del sistema) o con xhtml2pdf, que
es Python puro y funciona igual en Linux y Windows (opción por defecto).
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape

from escaner import __version__
from escaner.models import Category, Severity
from escaner.rules import RULES
from escaner.scoring import WEIGHTS

SEVERITY_ORDER = [str(s) for s in Severity]
CATEGORY_NAMES = {
    Category.TLS: "TLS y certificado",
    Category.HEADERS: "Cabeceras de seguridad",
    Category.COOKIES: "Cookies",
    Category.TECH: "Tecnologías y CVE",
    Category.PATHS: "Rutas sensibles",
    Category.CONTENT: "Contenido",
}


PDF_REPLACEMENTS = {"≥": ">=", "≤": "<=", "→": "->", "&rarr;": "->", "…": "..."}


class ExportError(Exception):
    """No se ha podido generar el fichero."""


_env = Environment(
    loader=PackageLoader("escaner", "reporting/templates"),
    autoescape=select_autoescape(["html", "j2"], default=True),
    trim_blocks=True,
    lstrip_blocks=True,
)


def safe_reference(rule_id: str) -> str | None:
    """Referencia del catálogo para una regla, solo si es un enlace https."""
    rule = RULES.get(rule_id)
    if rule and rule.reference.startswith("https://"):
        return rule.reference
    return None


def build_context(scan: dict, ai: dict | None = None) -> dict:
    findings = sorted(
        scan["findings"],
        key=lambda f: (
            SEVERITY_ORDER.index(f["severity"]) if f["severity"] in SEVERITY_ORDER else 99,
            f["category"],
        ),
    )
    problems = [f for f in findings if not f["bonus"]]
    good = [f for f in findings if f["bonus"]]
    categories = []
    for cat, weight in WEIGHTS.items():
        score = scan["category_scores"].get(str(cat))
        categories.append(
            {"id": str(cat), "name": CATEGORY_NAMES[cat], "weight": weight, "score": score}
        )
    counts = {s: sum(f["severity"] == s for f in problems) for s in SEVERITY_ORDER}
    return {
        "scan": scan,
        "domain": scan.get("domain", ""),
        "categories": categories,
        "problems": [{**f, "ref": safe_reference(f["rule_id"])} for f in problems],
        "good": good,
        "counts": counts,
        "ai": ai,
        "tool_version": __version__,
        "generated_at": datetime.now().strftime("%d/%m/%Y %H:%M"),
        "scanned_at": scan["scanned_at"][:16].replace("T", " "),
    }


def render_html(scan: dict, ai: dict | None = None) -> str:
    """HTML del informe. ``ai`` es el informe guardado (``Storage.get_report``) o None."""
    return _env.get_template("report.html.j2").render(**build_context(scan, ai))


def write_pdf(html: str, output: Path) -> str:
    """Convierte el HTML en PDF. Devuelve el motor usado."""
    try:
        from weasyprint import HTML  # type: ignore[import-not-found]
    except (ImportError, OSError):
        HTML = None  # noqa: N806
    if HTML is not None:
        HTML(string=html).write_pdf(str(output))
        return "weasyprint"
    try:
        from xhtml2pdf import pisa  # type: ignore[import-not-found]
    except ImportError as exc:
        raise ExportError(
            "Para exportar a PDF instala uno de los motores: "
            "pip install -e '.[pdf]' (xhtml2pdf) o pip install weasyprint."
        ) from exc
    # Las fuentes base de xhtml2pdf no tienen algunos símbolos: se sustituyen.
    for char, plain in PDF_REPLACEMENTS.items():
        html = html.replace(char, plain)
    with output.open("wb") as fh:
        status = pisa.CreatePDF(html, dest=fh, encoding="utf-8")
    if status.err:
        raise ExportError("xhtml2pdf no ha podido generar el PDF.")
    return "xhtml2pdf"
