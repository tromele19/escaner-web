"""Motor 5 — superficie de contenido (RF-07).

Analiza el HTML de la página indicada (no se rastrea el resto del sitio):
contenido mixto, recursos de terceros sin SRI, formularios que envían datos
sin cifrar y enlaces ``target="_blank"`` sin ``noopener``.

El HTML es un dato no confiable: se analiza con BeautifulSoup sin ejecutar
nada y en la evidencia solo aparecen nombres de host, no fragmentos del HTML.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from escaner.engines.base import Engine
from escaner.models import Category, Finding, ScanContext
from escaner.rules import finding

ACTIVE = {"script": "src", "iframe": "src", "object": "data", "embed": "src"}
PASSIVE = {"img": "src", "audio": "src", "video": "src", "source": "src"}


class ContentEngine(Engine):
    category = Category.CONTENT

    def is_evaluable(self, context: ScanContext) -> bool:
        return bool(context.html and context.html.strip())

    def analyze(self, context: ScanContext) -> list[Finding]:
        page_url = context.final_url or context.target_url
        page = urlsplit(page_url)
        is_https = page.scheme == "https"
        soup = BeautifulSoup(context.html or "", "html.parser")

        def resolve(value: str | None) -> str | None:
            return urljoin(page_url, value.strip()) if value and value.strip() else None

        findings: list[Finding] = []

        # --- Contenido mixto (solo tiene sentido en páginas HTTPS) ----------
        if is_https:
            active, passive = set(), set()
            for tag, attr in ACTIVE.items():
                for el in soup.find_all(tag):
                    url = resolve(el.get(attr))
                    if url and url.startswith("http://"):
                        active.add(_host(url))
            for link in soup.find_all("link"):
                url = resolve(link.get("href"))
                if url and url.startswith("http://") and _is_stylesheet(link):
                    active.add(_host(url))
            for tag, attr in PASSIVE.items():
                for el in soup.find_all(tag):
                    url = resolve(el.get(attr))
                    if url and url.startswith("http://"):
                        passive.add(_host(url))
            if active:
                findings.append(finding("MIXED_CONTENT_ACTIVE", _hosts(active)))
            if passive:
                findings.append(finding("MIXED_CONTENT_PASSIVE", _hosts(passive)))

        # --- Formularios ----------------------------------------------------
        password_insecure, insecure_action = False, False
        for form in soup.find_all("form"):
            action = resolve(form.get("action")) or page_url
            sends_http = action.startswith("http://")
            has_password = form.find(
                "input", attrs={"type": lambda t: t and t.lower() == "password"}
            )
            if has_password and sends_http:
                password_insecure = True
            elif sends_http and is_https:
                insecure_action = True
        if password_insecure:
            findings.append(finding("FORM_PASSWORD_INSECURE"))
        if insecure_action:
            findings.append(finding("FORM_INSECURE_ACTION"))

        # --- Recursos de terceros sin SRI (solo los cargados por HTTPS; los
        #     de HTTP ya son contenido mixto) -------------------------------
        scripts, styles = set(), set()
        for el in soup.find_all("script", src=True):
            url = resolve(el.get("src"))
            if url and url.startswith("https://") and _third_party(url, page.hostname):
                if not el.get("integrity"):
                    scripts.add(_host(url))
        for el in soup.find_all("link", href=True):
            url = resolve(el.get("href"))
            if (
                url
                and url.startswith("https://")
                and _is_stylesheet(el)
                and _third_party(url, page.hostname)
                and not el.get("integrity")
            ):
                styles.add(_host(url))
        if scripts:
            findings.append(finding("THIRD_PARTY_SCRIPT_NO_SRI", _hosts(scripts)))
        if styles:
            findings.append(finding("THIRD_PARTY_STYLE_NO_SRI", _hosts(styles)))

        # --- Enlaces target=_blank sin noopener ---------------------------
        unsafe = 0
        for a in soup.find_all("a", href=True):
            if (a.get("target") or "").lower() != "_blank":
                continue
            url = resolve(a.get("href"))
            rel = {r.lower() for r in (a.get("rel") or [])}
            if url and _third_party(url, page.hostname) and not rel & {"noopener", "noreferrer"}:
                unsafe += 1
        if unsafe:
            findings.append(finding("TARGET_BLANK_NO_NOOPENER", f"{unsafe} enlace(s)"))

        return findings


def _host(url: str) -> str:
    return urlsplit(url).hostname or "?"


def _hosts(hosts: set[str]) -> str:
    ordered = sorted(hosts)
    return ", ".join(ordered[:4]) + ("…" if len(ordered) > 4 else "")


def _is_stylesheet(link) -> bool:
    return "stylesheet" in {r.lower() for r in (link.get("rel") or [])}


def _third_party(url: str, page_host: str | None) -> bool:
    """Un recurso es de terceros si no está en el mismo host ni en un subdominio suyo."""
    host = (urlsplit(url).hostname or "").lower()
    page_host = (page_host or "").lower()
    if not host or not page_host:
        return False
    return not (
        host == page_host or host.endswith("." + page_host) or page_host.endswith("." + host)
    )
