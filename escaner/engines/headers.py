"""Motor 1 — cabeceras de seguridad HTTP (RF-03).

Evalúa las cabeceras de la respuesta final según la tabla 1 de la memoria.
Solo decide qué reglas se incumplen (o qué buenas prácticas se cumplen); la
severidad y los textos salen del catálogo ``escaner.rules``.
"""

from __future__ import annotations

import re

from escaner.engines.base import Engine
from escaner.models import Category, Finding, ScanContext
from escaner.rules import finding

SIX_MONTHS = 15_552_000  # segundos (180 días)
SAFE_XFO = {"deny", "sameorigin"}
OBSOLETE = ("expect-ct", "public-key-pins", "public-key-pins-report-only")


class HeadersEngine(Engine):
    category = Category.HEADERS

    def analyze(self, context: ScanContext) -> list[Finding]:
        headers = {k.lower().strip(): v.strip() for k, v in context.headers.items()}
        is_https = (context.final_url or context.target_url).lower().startswith("https://")

        findings: list[Finding] = []
        findings += check_hsts(headers.get("strict-transport-security"), is_https)
        csp = headers.get("content-security-policy")
        findings += check_csp(csp, headers.get("content-security-policy-report-only"))
        findings += check_frame_options(headers.get("x-frame-options"), csp)
        findings += check_content_type_options(headers.get("x-content-type-options"))
        findings += check_referrer_policy(headers.get("referrer-policy"))
        if "permissions-policy" not in headers:
            findings.append(finding("PERMISSIONS_POLICY_MISSING"))
        for name, rule in (
            ("cross-origin-opener-policy", "COOP_PRESENT"),
            ("cross-origin-resource-policy", "CORP_PRESENT"),
            ("cross-origin-embedder-policy", "COEP_PRESENT"),
        ):
            if headers.get(name):
                findings.append(finding(rule, f"{name}: {headers[name]}"))
        findings += check_obsolete(headers)
        return findings


# --- Strict-Transport-Security --------------------------------------------


def check_hsts(value: str | None, is_https: bool) -> list[Finding]:
    if not is_https:
        # Por HTTP el navegador ignora HSTS; la falta de HTTPS la evalúa el motor de TLS.
        return [finding("HSTS_OVER_HTTP", value)] if value else []
    if not value:
        return [finding("HSTS_MISSING")]

    directives = _parse_directives(value, sep=";")
    match = re.fullmatch(r'"?(\d+)"?', directives.get("max-age", ""))
    if not match:
        return [finding("HSTS_INVALID", value)]

    found = []
    max_age = int(match.group(1))
    if max_age < SIX_MONTHS:
        found.append(finding("HSTS_SHORT_MAX_AGE", f"max-age={max_age}"))
    if "includesubdomains" not in directives:
        found.append(finding("HSTS_NO_SUBDOMAINS", value))
    if "preload" in directives and max_age >= SIX_MONTHS:
        found.append(finding("HSTS_PRELOAD"))
    return found


# --- Content-Security-Policy ----------------------------------------------


def check_csp(value: str | None, report_only: str | None) -> list[Finding]:
    if not value:
        if report_only:
            return [finding("CSP_REPORT_ONLY", report_only)]
        return [finding("CSP_MISSING")]

    policy = parse_csp(value)
    found = []
    scripts = policy.get("script-src", policy.get("default-src"))
    if scripts is None:
        found.append(finding("CSP_NO_SCRIPT_SRC", value))
    else:
        # Con un nonce o un hash, los navegadores modernos ignoran 'unsafe-inline'.
        has_nonce_or_hash = any(
            s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for s in scripts
        )
        if "'unsafe-inline'" in scripts and not has_nonce_or_hash:
            found.append(finding("CSP_UNSAFE_INLINE", "script-src 'unsafe-inline'"))
        if "'unsafe-eval'" in scripts:
            found.append(finding("CSP_UNSAFE_EVAL", "script-src 'unsafe-eval'"))
        wildcards = [s for s in scripts if s in {"*", "http:", "https:"}]
        if wildcards:
            found.append(finding("CSP_WILDCARD_SOURCE", "script-src " + " ".join(wildcards)))
        if "data:" in scripts:
            found.append(finding("CSP_DATA_SCRIPTS", "script-src data:"))
    if "frame-ancestors" in policy:
        found.append(finding("CSP_FRAME_ANCESTORS"))
    return found


def parse_csp(value: str) -> dict[str, list[str]]:
    """Convierte una CSP en ``{directiva: [fuentes]}`` (fuentes en minúsculas).

    Si una directiva aparece dos veces, el navegador usa la primera.
    """
    policy: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            policy.setdefault(tokens[0].lower(), [t.lower() for t in tokens[1:]])
    return policy


# --- Resto de cabeceras ---------------------------------------------------


def check_frame_options(value: str | None, csp: str | None) -> list[Finding]:
    if csp and "frame-ancestors" in parse_csp(csp):
        return []  # frame-ancestors sustituye a X-Frame-Options
    if not value:
        return [finding("XFO_MISSING")]
    if value.lower() not in SAFE_XFO:
        return [finding("XFO_INVALID", value)]
    return []


def check_content_type_options(value: str | None) -> list[Finding]:
    if not value:
        return [finding("XCTO_MISSING")]
    if value.lower() != "nosniff":
        return [finding("XCTO_INVALID", value)]
    return []


def check_referrer_policy(value: str | None) -> list[Finding]:
    if not value:
        return [finding("REFERRER_POLICY_MISSING")]
    # Puede haber varias separadas por comas; el navegador usa la última que entiende.
    last = value.split(",")[-1].strip().lower()
    if last == "unsafe-url":
        return [finding("REFERRER_POLICY_UNSAFE", value)]
    return []


def check_obsolete(headers: dict[str, str]) -> list[Finding]:
    found = []
    xxss = headers.get("x-xss-protection")
    # OWASP recomienda "0" (desactivar el filtro antiguo): solo se avisa si está activado.
    if xxss is not None and xxss.startswith("1"):
        found.append(finding("XXSS_ENABLED", f"x-xss-protection: {xxss}"))
    for name in OBSOLETE:
        if name in headers:
            found.append(finding("OBSOLETE_HEADER", name))
    return found


def _parse_directives(value: str, sep: str) -> dict[str, str]:
    result = {}
    for part in value.split(sep):
        name, _, val = part.strip().partition("=")
        if name:
            result[name.strip().lower()] = val.strip()
    return result
