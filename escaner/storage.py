"""Persistencia en SQLite: histórico de escaneos y comparación (RF-10, RF-11).

Todas las consultas son parametrizadas (``?``): ningún dato del sitio
analizado se concatena nunca en una sentencia SQL.

Se guarda solo el resultado del análisis (notas y hallazgos con su evidencia
ya saneada), nunca el HTML ni las cabeceras completas del sitio.
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from escaner import __version__
from escaner.models import ScanResult

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id          INTEGER PRIMARY KEY,
    domain      TEXT NOT NULL UNIQUE,
    first_seen  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY,
    target_id       INTEGER NOT NULL REFERENCES targets(id),
    url             TEXT NOT NULL,
    final_url       TEXT,
    scanned_at      TEXT NOT NULL,
    mode            TEXT NOT NULL,
    global_score    REAL,
    grade           TEXT,
    category_scores TEXT NOT NULL,
    rubric_version  TEXT NOT NULL,
    tool_version    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id        INTEGER PRIMARY KEY,
    scan_id   INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    category  TEXT NOT NULL,
    rule_id   TEXT NOT NULL,
    severity  TEXT NOT NULL,
    title     TEXT NOT NULL,
    evidence  TEXT NOT NULL,
    reference TEXT NOT NULL,
    bonus     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS reports (
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    profile     TEXT NOT NULL,
    model       TEXT NOT NULL,
    content     TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (scan_id, profile)
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_id, scanned_at);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"""


def default_db_path() -> Path:
    base = os.environ.get("ESCANER_DATA_DIR")
    return (Path(base) if base else Path.home() / ".escaner-web") / "escaner.db"


def domain_of(url: str) -> str:
    return (urlsplit(url).hostname or url).lower()


@dataclass(frozen=True, slots=True)
class Comparison:
    domain: str
    old: dict
    new: dict
    new_findings: list[dict]
    resolved: list[dict]
    unchanged: list[dict]

    @property
    def score_delta(self) -> float | None:
        if self.old["global_score"] is None or self.new["global_score"] is None:
            return None
        return round(self.new["global_score"] - self.old["global_score"], 1)


class Storage:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as conn:
            conn.executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    # --- Escritura -------------------------------------------------------

    def save(self, result: ScanResult) -> int:
        """Guarda un escaneo con sus hallazgos y devuelve su identificador."""
        ctx = result.context
        domain = domain_of(ctx.target_url)
        now = datetime.now(UTC).isoformat(timespec="seconds")
        with closing(self._connect()) as conn, conn:
            conn.execute(
                "INSERT OR IGNORE INTO targets (domain, first_seen) VALUES (?, ?)", (domain, now)
            )
            (target_id,) = conn.execute(
                "SELECT id FROM targets WHERE domain = ?", (domain,)
            ).fetchone()
            cur = conn.execute(
                "INSERT INTO scans (target_id, url, final_url, scanned_at, mode, global_score,"
                " grade, category_scores, rubric_version, tool_version)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    target_id,
                    ctx.target_url,
                    ctx.final_url,
                    ctx.started_at.isoformat(timespec="seconds"),
                    str(ctx.mode),
                    result.global_score,
                    result.grade,
                    json.dumps({str(k): v for k, v in result.category_scores.items()}),
                    result.rubric_version,
                    __version__,
                ),
            )
            scan_id = cur.lastrowid
            conn.executemany(
                "INSERT INTO findings (scan_id, category, rule_id, severity, title, evidence,"
                " reference, bonus) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        scan_id,
                        str(f.category),
                        f.rule_id,
                        str(f.severity),
                        f.title,
                        f.evidence,
                        f.reference,
                        f.bonus,
                    )
                    for f in result.findings
                ],
            )
        return scan_id

    def save_report(self, scan_id: int, profile: str, model: str, content: dict) -> None:
        now = datetime.now(UTC).isoformat(timespec="seconds")
        with closing(self._connect()) as conn, conn:
            conn.execute(
                "INSERT OR REPLACE INTO reports (scan_id, profile, model, content, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (scan_id, profile, model, json.dumps(content, ensure_ascii=False), now),
            )

    # --- Lectura -------------------------------------------------------

    def history(self, domain: str, limit: int = 20) -> list[dict]:
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT s.id, s.scanned_at, s.mode, s.global_score, s.grade, s.url,"
                " (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id AND f.severity"
                "  IN ('critica', 'alta')) AS serious"
                " FROM scans s JOIN targets t ON t.id = s.target_id"
                " WHERE t.domain = ? ORDER BY s.scanned_at DESC, s.id DESC LIMIT ?",
                (domain_of(domain) if "://" in domain else domain.lower(), limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_scan(self, scan_id: int) -> dict | None:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT s.*, t.domain FROM scans s JOIN targets t ON t.id = s.target_id"
                " WHERE s.id = ?",
                (scan_id,),
            ).fetchone()
            if row is None:
                return None
            scan = dict(row)
            scan["category_scores"] = json.loads(scan["category_scores"])
            scan["findings"] = [
                dict(r)
                for r in conn.execute(
                    "SELECT category, rule_id, severity, title, evidence, reference, bonus"
                    " FROM findings WHERE scan_id = ? ORDER BY id",
                    (scan_id,),
                )
            ]
        return scan

    def get_report(self, scan_id: int, profile: str) -> dict | None:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT content, model, created_at FROM reports WHERE scan_id = ? AND profile = ?",
                (scan_id, profile),
            ).fetchone()
        if row is None:
            return None
        return {
            "content": json.loads(row["content"]),
            "model": row["model"],
            "created_at": row["created_at"],
        }

    # --- Comparación ---------------------------------------------------

    def compare(self, old_id: int, new_id: int) -> Comparison:
        """Compara dos escaneos por el par (categoría, regla) de cada hallazgo."""
        old, new = self.get_scan(old_id), self.get_scan(new_id)
        if old is None or new is None:
            raise KeyError(f"No existe el escaneo {old_id if old is None else new_id}")

        def keyed(scan):
            # Las buenas prácticas (bonificaciones) no son problemas: no se comparan.
            return {(f["category"], f["rule_id"]): f for f in scan["findings"] if not f["bonus"]}

        a, b = keyed(old), keyed(new)
        return Comparison(
            domain=new["domain"],
            old=old,
            new=new,
            new_findings=[b[k] for k in b.keys() - a.keys()],
            resolved=[a[k] for k in a.keys() - b.keys()],
            unchanged=[b[k] for k in a.keys() & b.keys()],
        )

    def compare_last(self, domain: str, n: int = 2) -> Comparison:
        rows = self.history(domain, limit=n)
        if len(rows) < 2:
            raise KeyError(f"Hacen falta al menos 2 escaneos de {domain} para comparar")
        return self.compare(rows[-1]["id"], rows[0]["id"])
