"""Reglas del motor de superficie de contenido (apartado 2.3 de la memoria)."""

from escaner.models import Category, Severity
from escaner.rules import Rule, register

C = Category.CONTENT
MIXED = "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"
SRI = "https://www.w3.org/TR/SRI/"

register(
    Rule(
        "MIXED_CONTENT_ACTIVE",
        C,
        Severity.HIGH,
        "Contenido mixto activo: scripts, estilos o marcos cargados por HTTP",
        MIXED,
    ),
    Rule(
        "MIXED_CONTENT_PASSIVE",
        C,
        Severity.LOW,
        "Contenido mixto pasivo: imágenes o multimedia cargados por HTTP",
        MIXED,
    ),
    Rule(
        "FORM_PASSWORD_INSECURE",
        C,
        Severity.HIGH,
        "Formulario con contraseña que se envía sin cifrar (HTTP)",
        MIXED,
    ),
    Rule(
        "FORM_INSECURE_ACTION",
        C,
        Severity.MEDIUM,
        "Formulario que envía datos por HTTP desde una página HTTPS",
        MIXED,
    ),
    Rule(
        "THIRD_PARTY_SCRIPT_NO_SRI",
        C,
        Severity.MEDIUM,
        "Scripts de terceros sin integridad de subrecursos (SRI)",
        SRI,
    ),
    Rule(
        "THIRD_PARTY_STYLE_NO_SRI",
        C,
        Severity.LOW,
        "Hojas de estilo de terceros sin integridad de subrecursos (SRI)",
        SRI,
    ),
    Rule(
        "TARGET_BLANK_NO_NOOPENER",
        C,
        Severity.LOW,
        'Enlaces externos con target="_blank" sin rel="noopener"',
        "https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes/rel/noopener",
    ),
)
