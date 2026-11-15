"""Detección de tecnologías y versiones anunciadas (RF-08).

Solo usa lo que el servidor ya envía en una visita normal: cabeceras
(``Server``, ``X-Powered-By``…), la etiqueta ``<meta name="generator">`` y las
URL de librerías JavaScript conocidas. No hace peticiones adicionales.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from bs4 import BeautifulSoup

VERSION = r"(\d+(?:\.\d+){1,3})"

HEADER_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("server", "nginx", re.compile(r"nginx/" + VERSION, re.I)),
    ("server", "apache", re.compile(r"apache/" + VERSION, re.I)),
    ("server", "iis", re.compile(r"microsoft-iis/" + VERSION, re.I)),
    ("server", "openssl", re.compile(r"openssl/" + VERSION, re.I)),
    ("server", "php", re.compile(r"php/" + VERSION, re.I)),
    ("x-powered-by", "php", re.compile(r"php/" + VERSION, re.I)),
]
NAME_ONLY = [  # anunciadas sin versión
    ("server", "nginx", re.compile(r"^nginx\b", re.I)),
    ("server", "apache", re.compile(r"^apache\b", re.I)),
    ("server", "iis", re.compile(r"microsoft-iis", re.I)),
    ("x-powered-by", "php", re.compile(r"^php\b", re.I)),
]
GENERATOR_PATTERNS = [
    ("wordpress", re.compile(r"wordpress\s+" + VERSION, re.I)),
    ("drupal", re.compile(r"drupal\s+" + VERSION, re.I)),
    ("joomla", re.compile(r"joomla!?\D{0,40}?" + VERSION, re.I)),
]
SCRIPT_PATTERNS = [
    ("jquery", re.compile(r"jquery[-.@/]?(?:v)?" + VERSION + r"(?:\.min|\.slim)?\.js", re.I)),
    ("jquery", re.compile(r"/jquery/" + VERSION + r"/", re.I)),
    ("jquery", re.compile(r"jquery@" + VERSION, re.I)),
]


@dataclass(frozen=True, slots=True)
class Technology:
    product: str  # clave de PRODUCTS
    version: str | None
    source: str  # de dónde se ha obtenido (p. ej. "cabecera Server")


def detect(headers: dict[str, str], html: str | None) -> list[Technology]:
    """Devuelve las tecnologías detectadas, sin duplicados."""
    h = {k.lower(): v for k, v in headers.items()}
    found: dict[str, Technology] = {}

    def add(product, version, source):
        current = found.get(product)
        if current is None or (current.version is None and version):
            found[product] = Technology(product, version, source)

    for header, product, pattern in HEADER_PATTERNS:
        for m in pattern.finditer(h.get(header, "")):
            add(product, m.group(1), f"cabecera {header.title()}")
    for header, product, pattern in NAME_ONLY:
        if pattern.search(h.get(header, "")):
            add(product, None, f"cabecera {header.title()}")

    if html:
        soup = BeautifulSoup(html, "html.parser")
        for meta in soup.find_all("meta", attrs={"name": re.compile("^generator$", re.I)}):
            content = meta.get("content") or ""
            for product, pattern in GENERATOR_PATTERNS:
                m = pattern.search(content)
                if m:
                    add(product, m.group(1), "meta generator")
        for script in soup.find_all("script", src=True):
            for product, pattern in SCRIPT_PATTERNS:
                m = pattern.search(script["src"])
                if m:
                    add(product, m.group(1), "librería JavaScript")
                    break
    return list(found.values())
