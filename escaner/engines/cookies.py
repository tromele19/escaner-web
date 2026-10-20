"""Motor 2 — atributos de seguridad de las cookies (RF-04).

Analiza cada cabecera ``Set-Cookie`` recibida (también las de las
redirecciones). El **valor** de la cookie nunca se guarda ni se muestra: en
la evidencia solo aparecen el nombre y los atributos.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from escaner.engines.base import Engine
from escaner.models import Category, Finding, ScanContext
from escaner.rules import finding

# "sid" solo como palabra completa (sid, connect.sid, _sid_x), no dentro de "inside".
SESSION_NAME = re.compile(r"sess|(?:^|[._-])sid(?:$|[._-])|token|auth|jwt|^remember", re.IGNORECASE)
VALID_SAMESITE = {"strict", "lax", "none"}


@dataclass(slots=True)
class Cookie:
    """Cookie analizada (sin su valor)."""

    name: str
    attributes: dict[str, str] = field(default_factory=dict)

    @property
    def secure(self) -> bool:
        return "secure" in self.attributes

    @property
    def httponly(self) -> bool:
        return "httponly" in self.attributes

    @property
    def samesite(self) -> str | None:
        return self.attributes.get("samesite")

    @property
    def is_session(self) -> bool:
        return bool(SESSION_NAME.search(self.name))

    @property
    def is_deletion(self) -> bool:
        """Cookie que el servidor está borrando (Max-Age=0): no se evalúa."""
        return self.attributes.get("max-age", "").strip() in {"0", "-1"}

    def describe(self) -> str:
        """Nombre y atributos, nunca el valor."""
        attrs = ", ".join(
            f"{k}={v}" if v else k for k, v in self.attributes.items() if k != "expires"
        )
        return f"{self.name} ({attrs or 'sin atributos'})"


def parse_set_cookie(header: str) -> Cookie | None:
    """Convierte una cabecera ``Set-Cookie`` en un ``Cookie`` (sin el valor)."""
    parts = header.split(";")
    name, sep, _value = parts[0].partition("=")
    name = name.strip()
    if not sep or not name:
        return None
    attributes: dict[str, str] = {}
    for part in parts[1:]:
        key, _, val = part.strip().partition("=")
        if key:
            attributes[key.strip().lower()] = val.strip().lower() if key.lower() != "path" else val
    return Cookie(name=name, attributes=attributes)


class CookiesEngine(Engine):
    category = Category.COOKIES

    def is_evaluable(self, context: ScanContext) -> bool:
        return any(
            (c := parse_set_cookie(h)) and not c.is_deletion for h in context.raw_set_cookies
        )

    def analyze(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for header in context.raw_set_cookies:
            cookie = parse_set_cookie(header)
            if cookie is None or cookie.is_deletion:
                continue
            for rule_id in check_cookie(cookie):
                if (rule_id, cookie.name) not in seen:
                    seen.add((rule_id, cookie.name))
                    findings.append(finding(rule_id, cookie.describe()))
        return findings


def check_cookie(cookie: Cookie) -> list[str]:
    """Devuelve los identificadores de regla que aplica a una cookie."""
    rules: list[str] = []
    samesite = cookie.samesite

    if cookie.is_session:
        if not cookie.secure:
            rules.append("SESSION_COOKIE_NO_SECURE")
        if not cookie.httponly:
            rules.append("SESSION_COOKIE_NO_HTTPONLY")
        if samesite is None:
            rules.append("SESSION_COOKIE_NO_SAMESITE")
    elif not cookie.secure:
        rules.append("COOKIE_NO_SECURE")

    if samesite is not None:
        if samesite not in VALID_SAMESITE:
            rules.append("COOKIE_SAMESITE_INVALID")
        elif samesite == "none" and not cookie.secure:
            rules.append("COOKIE_SAMESITE_NONE_INSECURE")

    name = cookie.name.lower()
    if name.startswith("__host-"):
        valid = cookie.secure and cookie.attributes.get("path") == "/"
        valid = valid and "domain" not in cookie.attributes
        if not valid:
            rules.append("COOKIE_PREFIX_INVALID")
        elif cookie.is_session:
            rules.append("SESSION_COOKIE_HOST_PREFIX")
    elif name.startswith("__secure-") and not cookie.secure:
        rules.append("COOKIE_PREFIX_INVALID")
    return rules
