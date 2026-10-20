"""Reglas del motor de cabeceras de seguridad HTTP (tabla 1 de la memoria)."""

from escaner.models import Category, Severity
from escaner.rules import Rule, register

H = Category.HEADERS
OWASP = "https://owasp.org/www-project-secure-headers/"
MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"

register(
    # Strict-Transport-Security (RFC 6797)
    Rule(
        "HSTS_MISSING",
        H,
        Severity.HIGH,
        "Falta la cabecera Strict-Transport-Security (HSTS)",
        "https://www.rfc-editor.org/rfc/rfc6797",
    ),
    Rule(
        "HSTS_INVALID",
        H,
        Severity.MEDIUM,
        "HSTS sin un max-age válido",
        "https://www.rfc-editor.org/rfc/rfc6797",
    ),
    Rule(
        "HSTS_SHORT_MAX_AGE",
        H,
        Severity.MEDIUM,
        "HSTS con max-age inferior a 6 meses",
        "https://www.rfc-editor.org/rfc/rfc6797",
    ),
    Rule(
        "HSTS_NO_SUBDOMAINS",
        H,
        Severity.LOW,
        "HSTS sin includeSubDomains",
        "https://www.rfc-editor.org/rfc/rfc6797",
    ),
    Rule(
        "HSTS_PRELOAD",
        H,
        Severity.INFO,
        "HSTS con preload (buena práctica)",
        "https://hstspreload.org/",
        bonus=5,
    ),
    Rule(
        "HSTS_OVER_HTTP",
        H,
        Severity.INFO,
        "HSTS enviado por HTTP: el navegador lo ignora",
        "https://www.rfc-editor.org/rfc/rfc6797#section-7.2",
    ),
    # Content-Security-Policy (W3C CSP Level 3)
    Rule(
        "CSP_MISSING",
        H,
        Severity.MEDIUM,
        "Falta la cabecera Content-Security-Policy",
        MDN + "Content-Security-Policy",
    ),
    Rule(
        "CSP_REPORT_ONLY",
        H,
        Severity.LOW,
        "CSP solo en modo report-only: no bloquea nada",
        MDN + "Content-Security-Policy-Report-Only",
    ),
    Rule(
        "CSP_NO_SCRIPT_SRC",
        H,
        Severity.MEDIUM,
        "CSP sin default-src ni script-src",
        "https://www.w3.org/TR/CSP3/",
    ),
    Rule(
        "CSP_UNSAFE_INLINE",
        H,
        Severity.MEDIUM,
        "CSP permite scripts en línea ('unsafe-inline')",
        "https://www.w3.org/TR/CSP3/",
    ),
    Rule(
        "CSP_UNSAFE_EVAL",
        H,
        Severity.MEDIUM,
        "CSP permite eval() ('unsafe-eval')",
        "https://www.w3.org/TR/CSP3/",
    ),
    Rule(
        "CSP_WILDCARD_SOURCE",
        H,
        Severity.MEDIUM,
        "CSP permite scripts de cualquier origen (*, http: o https:)",
        "https://www.w3.org/TR/CSP3/",
    ),
    Rule(
        "CSP_DATA_SCRIPTS",
        H,
        Severity.MEDIUM,
        "CSP permite scripts desde data:",
        "https://www.w3.org/TR/CSP3/",
    ),
    Rule(
        "CSP_FRAME_ANCESTORS",
        H,
        Severity.INFO,
        "CSP con frame-ancestors (protección moderna frente a clickjacking)",
        "https://www.w3.org/TR/CSP3/#directive-frame-ancestors",
        bonus=5,
    ),
    # X-Frame-Options
    Rule(
        "XFO_MISSING",
        H,
        Severity.MEDIUM,
        "Sin protección frente a clickjacking (X-Frame-Options o frame-ancestors)",
        MDN + "X-Frame-Options",
    ),
    Rule(
        "XFO_INVALID",
        H,
        Severity.LOW,
        "X-Frame-Options con un valor no válido",
        MDN + "X-Frame-Options",
    ),
    # X-Content-Type-Options
    Rule(
        "XCTO_MISSING",
        H,
        Severity.MEDIUM,
        "Falta X-Content-Type-Options: nosniff",
        MDN + "X-Content-Type-Options",
    ),
    Rule(
        "XCTO_INVALID",
        H,
        Severity.MEDIUM,
        "X-Content-Type-Options con un valor distinto de nosniff",
        MDN + "X-Content-Type-Options",
    ),
    # Referrer-Policy
    Rule(
        "REFERRER_POLICY_MISSING",
        H,
        Severity.LOW,
        "Falta la cabecera Referrer-Policy",
        MDN + "Referrer-Policy",
    ),
    Rule(
        "REFERRER_POLICY_UNSAFE",
        H,
        Severity.MEDIUM,
        "Referrer-Policy unsafe-url: envía la URL completa a terceros",
        MDN + "Referrer-Policy",
    ),
    # Permissions-Policy
    Rule(
        "PERMISSIONS_POLICY_MISSING",
        H,
        Severity.LOW,
        "Falta la cabecera Permissions-Policy",
        MDN + "Permissions-Policy",
    ),
    # Aislamiento entre orígenes: informativas, solo suman
    Rule(
        "COOP_PRESENT",
        H,
        Severity.INFO,
        "Cross-Origin-Opener-Policy configurada",
        MDN + "Cross-Origin-Opener-Policy",
        bonus=2,
    ),
    Rule(
        "CORP_PRESENT",
        H,
        Severity.INFO,
        "Cross-Origin-Resource-Policy configurada",
        MDN + "Cross-Origin-Resource-Policy",
        bonus=2,
    ),
    Rule(
        "COEP_PRESENT",
        H,
        Severity.INFO,
        "Cross-Origin-Embedder-Policy configurada",
        MDN + "Cross-Origin-Embedder-Policy",
        bonus=2,
    ),
    # Cabeceras obsoletas
    Rule(
        "XXSS_ENABLED",
        H,
        Severity.LOW,
        "X-XSS-Protection activada: obsoleta y puede introducir fallos (usar 0 o quitarla)",
        MDN + "X-XSS-Protection",
    ),
    Rule("OBSOLETE_HEADER", H, Severity.INFO, "Cabecera de seguridad obsoleta presente", OWASP),
)
