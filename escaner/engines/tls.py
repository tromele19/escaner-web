"""Motor 3 — TLS y certificado (RF-05).

Trabaja sobre ``context.tls_info``, que rellena el orquestador con:
- ``https_available``: si el sitio responde por HTTPS;
- ``http_redirects_to_https``: si la versión HTTP redirige a HTTPS (None si
  no se ha podido comprobar);
- ``final_url_https``: si la URL final del escaneo es HTTPS;
- ``server``: el resultado de ``inspect_tls`` (certificado y versiones).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from escaner.acquisition.tls_client import UNTRUSTED_CODES, hostname_matches
from escaner.engines.base import Engine
from escaner.models import Category, Finding, ScanContext
from escaner.rules import finding

EXPIRY_WARNING = timedelta(days=30)
MIN_KEY_BITS = {"RSA": 2048, "DSA": 2048, "EC": 256}
WEAK_HASHES = {"sha1", "md5"}


class TLSEngine(Engine):
    category = Category.TLS

    def __init__(self, now: datetime | None = None) -> None:
        self._now = now  # inyectable para las pruebas

    def is_evaluable(self, context: ScanContext) -> bool:
        return bool(context.tls_info) and "https_available" in context.tls_info

    def analyze(self, context: ScanContext) -> list[Finding]:
        info = context.tls_info or {}
        now = self._now or datetime.now(UTC)

        if not info.get("https_available"):
            return [finding("TLS_NO_HTTPS", info.get("error", ""))]

        found: list[Finding] = []
        if info.get("http_redirects_to_https") is False:
            found.append(finding("TLS_NO_HTTPS_REDIRECT"))
        if info.get("final_url_https") is False:
            found.append(finding("TLS_REDIRECT_TO_HTTP", context.final_url or ""))

        server = info.get("server") or {}
        found += check_certificate(server, now)
        found += check_versions(server.get("versions") or {})
        return found


def check_certificate(server: dict, now: datetime) -> list[Finding]:
    cert = server.get("certificate")
    if not cert:
        return []
    found = []
    not_before = datetime.fromisoformat(cert["not_before"])
    not_after = datetime.fromisoformat(cert["not_after"])
    issuer = cert.get("issuer_org") or cert.get("issuer_cn") or "desconocido"

    if now > not_after:
        found.append(finding("TLS_CERT_EXPIRED", f"caducó el {not_after:%d/%m/%Y}"))
    elif now < not_before:
        found.append(finding("TLS_CERT_NOT_YET_VALID", f"válido desde el {not_before:%d/%m/%Y}"))
    elif not_after - now < EXPIRY_WARNING:
        found.append(finding("TLS_CERT_EXPIRING_SOON", f"caduca el {not_after:%d/%m/%Y}"))

    # La caducidad la evaluamos nosotros; aquí solo interesa la confianza en la cadena.
    if not server.get("trusted") and (
        cert.get("self_signed") or server.get("verify_code") in UNTRUSTED_CODES
    ):
        detail = "autofirmado" if cert.get("self_signed") else f"emisor: {issuer}"
        found.append(finding("TLS_CERT_UNTRUSTED", detail))

    names = cert.get("san_dns") or ([cert["subject_cn"].lower()] if cert.get("subject_cn") else [])
    if not hostname_matches(server.get("host", ""), names):
        found.append(
            finding(
                "TLS_CERT_HOSTNAME_MISMATCH",
                f"certificado para: {', '.join(names[:3]) or 'sin nombres'}",
            )
        )

    minimum = MIN_KEY_BITS.get(cert.get("key_type", ""))
    if minimum and cert.get("key_bits") and cert["key_bits"] < minimum:
        found.append(finding("TLS_WEAK_KEY", f"{cert['key_type']} de {cert['key_bits']} bits"))
    if (cert.get("signature_hash") or "").lower() in WEAK_HASHES:
        found.append(finding("TLS_WEAK_SIGNATURE", f"firma {cert['signature_hash'].upper()}"))
    return found


def check_versions(versions: dict) -> list[Finding]:
    found = []
    if versions.get("TLSv1.0") is True:
        found.append(finding("TLS_V10_ENABLED"))
    if versions.get("TLSv1.1") is True:
        found.append(finding("TLS_V11_ENABLED"))
    if versions.get("TLSv1.2") is False and versions.get("TLSv1.3") is False:
        found.append(finding("TLS_NO_TLS12_OR_13"))
    if versions.get("TLSv1.3") is True:
        found.append(finding("TLS_V13_SUPPORTED"))
    return found
