"""Reglas del motor de TLS y certificado (apartado 2.3 de la memoria)."""

from escaner.models import Category, Severity
from escaner.rules import Rule, register

T = Category.TLS
RFC8996 = "https://www.rfc-editor.org/rfc/rfc8996"
MOZ = "https://wiki.mozilla.org/Security/Server_Side_TLS"

register(
    # Disponibilidad de HTTPS
    Rule("TLS_NO_HTTPS", T, Severity.CRITICAL, "El sitio no está disponible por HTTPS", MOZ),
    Rule(
        "TLS_NO_HTTPS_REDIRECT",
        T,
        Severity.HIGH,
        "La versión HTTP no redirige a HTTPS",
        "https://www.rfc-editor.org/rfc/rfc6797",
    ),
    Rule(
        "TLS_REDIRECT_TO_HTTP",
        T,
        Severity.HIGH,
        "El sitio HTTPS redirige a una página HTTP sin cifrar",
        MOZ,
    ),
    # Certificado
    Rule("TLS_CERT_EXPIRED", T, Severity.CRITICAL, "Certificado caducado", MOZ),
    Rule(
        "TLS_CERT_NOT_YET_VALID",
        T,
        Severity.CRITICAL,
        "Certificado todavía no válido (fecha de inicio futura)",
        MOZ,
    ),
    Rule(
        "TLS_CERT_UNTRUSTED",
        T,
        Severity.CRITICAL,
        "Certificado no confiable (autofirmado o de una autoridad no reconocida)",
        MOZ,
    ),
    Rule(
        "TLS_CERT_HOSTNAME_MISMATCH",
        T,
        Severity.CRITICAL,
        "El certificado no corresponde al nombre del sitio",
        "https://www.rfc-editor.org/rfc/rfc6125",
    ),
    Rule(
        "TLS_CERT_EXPIRING_SOON", T, Severity.INFO, "El certificado caduca en menos de 30 días", MOZ
    ),
    Rule("TLS_WEAK_KEY", T, Severity.HIGH, "Clave del certificado demasiado corta", MOZ),
    Rule(
        "TLS_WEAK_SIGNATURE",
        T,
        Severity.MEDIUM,
        "Certificado firmado con un algoritmo obsoleto (SHA-1 o MD5)",
        MOZ,
    ),
    # Versiones del protocolo
    Rule("TLS_V10_ENABLED", T, Severity.HIGH, "El servidor acepta TLS 1.0 (obsoleto)", RFC8996),
    Rule("TLS_V11_ENABLED", T, Severity.HIGH, "El servidor acepta TLS 1.1 (obsoleto)", RFC8996),
    Rule(
        "TLS_NO_TLS12_OR_13",
        T,
        Severity.HIGH,
        "El servidor no acepta ni TLS 1.2 ni TLS 1.3",
        RFC8996,
    ),
    Rule(
        "TLS_V13_SUPPORTED",
        T,
        Severity.INFO,
        "El servidor acepta TLS 1.3 (buena práctica)",
        "https://www.rfc-editor.org/rfc/rfc8446",
        bonus=5,
    ),
)

# Hallazgos que impiden un HTTPS válido: la nota global queda en F (tabla 14).
FAIL_GRADE_RULES = frozenset(
    {
        "TLS_NO_HTTPS",
        "TLS_CERT_EXPIRED",
        "TLS_CERT_NOT_YET_VALID",
        "TLS_CERT_UNTRUSTED",
        "TLS_CERT_HOSTNAME_MISMATCH",
    }
)
