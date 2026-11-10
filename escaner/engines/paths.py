"""Motor 4 — rutas y ficheros sensibles, solo en modo completo (RF-06).

Trabaja sobre ``context.path_probes`` (lo rellena el orquestador con
``probe_paths``). Un 200 no basta para dar un fichero por expuesto: cada tipo
se reconoce por su **contenido** y se descartan las respuestas iguales a la de
una ruta inventada (servidores que responden 200 a todo).

Las evidencias nunca incluyen el contenido de los ficheros: del .env solo se
indica cuántas variables tiene y sus nombres, nunca sus valores.
"""

from __future__ import annotations

import re

from escaner.acquisition.prober import SOFT404_KEY
from escaner.engines.base import Engine
from escaner.models import Category, Finding, ScanContext, ScanMode
from escaner.rules import finding
from escaner.rules.paths import ADMIN_PATHS, BACKUP_PATHS, ENV_PATHS, GIT_PATHS

ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Z][A-Z0-9_]{1,63})\s*=", re.MULTILINE)
GIT_HEAD = re.compile(r"^(ref: refs/|[0-9a-f]{40}\s*$)")
SENSITIVE_IN_ROBOTS = re.compile(
    r"^\s*disallow:\s*(\S*(?:admin|backup|private|config|secret|internal|\.git|\.env)\S*)",
    re.IGNORECASE | re.MULTILINE,
)
# Nginx/Apache («Index of /») y servidores de desarrollo como el de Python
LISTING = re.compile(r"<(?:title|h1)>\s*(?:Index of|Directory listing for) /", re.IGNORECASE)
LOGIN_FORM = re.compile(r"<input[^>]+type=[\"']?password", re.IGNORECASE)


class PathsEngine(Engine):
    category = Category.PATHS
    modes = frozenset({ScanMode.FULL})

    def is_evaluable(self, context: ScanContext) -> bool:
        return bool(context.path_probes)

    def analyze(self, context: ScanContext) -> list[Finding]:
        probes = context.path_probes or {}
        soft404 = probes.get(SOFT404_KEY, {})

        def found(path: str) -> dict | None:
            """Respuesta de la ruta si es un 200 que no parece la página de «no existe»."""
            r = probes.get(path) or {}
            if r.get("status") != 200 or r.get("length", 0) == 0:
                return None
            if soft404.get("status") == 200 and _similar(r, soft404):
                return None
            return r

        findings: list[Finding] = []

        for path in ENV_PATHS:
            r = found(path)
            if r and "<html" not in r["body"][:500].lower():
                names = ENV_LINE.findall(r["body"])
                if names:
                    shown = ", ".join(names[:5]) + ("…" if len(names) > 5 else "")
                    findings.append(
                        finding("ENV_FILE_EXPOSED", f"{path}: {len(names)} variables ({shown})")
                    )
                    break

        for path in GIT_PATHS:
            r = found(path)
            if r and (GIT_HEAD.match(r["body"]) or "[core]" in r["body"]):
                findings.append(finding("GIT_REPO_EXPOSED", path))
                break

        backups = []
        for path in BACKUP_PATHS:
            r = found(path)
            if r is None:
                continue
            if LISTING.search(r["body"]):
                findings.append(finding("DIRECTORY_LISTING", path))
            elif not path.endswith("/"):
                backups.append(path)
        if backups:
            findings.append(finding("BACKUP_FILE_EXPOSED", ", ".join(backups[:4])))

        for path in ADMIN_PATHS:
            r = found(path)
            if r and LOGIN_FORM.search(r["body"]):
                findings.append(finding("ADMIN_PANEL_EXPOSED", path))
                break

        robots = found("/robots.txt")
        if robots and "html" not in robots["content_type"]:
            revealed = SENSITIVE_IN_ROBOTS.findall(robots["body"])
            if revealed:
                findings.append(finding("ROBOTS_REVEALS_PATHS", ", ".join(revealed[:4])))

        sec = found("/.well-known/security.txt") or found("/security.txt")
        if sec and "contact:" in sec["body"].lower():
            findings.append(finding("SECURITY_TXT_PRESENT"))
        else:
            findings.append(finding("SECURITY_TXT_MISSING"))

        return _dedupe(findings)


def _similar(a: dict, b: dict) -> bool:
    """Dos respuestas son «la misma página» si coinciden tipo y tamaño (±10 %)."""
    if a.get("content_type") != b.get("content_type"):
        return False
    la, lb = a.get("length", 0), b.get("length", 0)
    return abs(la - lb) <= max(50, 0.1 * max(la, lb))


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        if (f.rule_id, f.evidence) not in seen:
            seen.add((f.rule_id, f.evidence))
            out.append(f)
    return out
