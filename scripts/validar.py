"""Validación final de la herramienta contra sitios reales (#17).

Escanea en modo PASIVO la lista de ``validacion/sitios.txt``, mide el tiempo
de cada escaneo y, si se pide con ``--observatory``, consulta también la nota
de Mozilla HTTP Observatory para comparar. Escribe:

- ``validacion/resultados.csv``: una fila por sitio;
- ``validacion/resultados.md``: la tabla y el resumen, listos para la memoria.

Uso (desde la raíz del repositorio, con el entorno virtual activo):

    python scripts/validar.py                 # solo el escáner
    python scripts/validar.py --observatory   # + nota de Mozilla Observatory

Mozilla Observatory solo evalúa cabeceras, cookies y redirecciones (no el
certificado, las versiones de TLS ni las CVE), así que no se espera la misma
nota: se mide si los dos coinciden en la letra o difieren en una.
"""

from __future__ import annotations

import argparse
import csv
import statistics
import sys
import time
from pathlib import Path

import requests

from escaner.acquisition.fetcher import FetchError
from escaner.models import ScanMode
from escaner.scanner import run_scan
from escaner.storage import Storage
from escaner.validator import TargetError

ROOT = Path(__file__).resolve().parent.parent
OBSERVATORY = "https://observatory-api.mdn.mozilla.net/api/v2/scan"
LETTERS = "ABCDEF"


def read_sites(path: Path) -> list[tuple[str, str]]:
    sites = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            parts = line.split()
            sites.append((parts[0], parts[1] if len(parts) > 1 else "-"))
    return sites


def observatory_grade(host: str) -> str:
    try:
        resp = requests.post(OBSERVATORY, params={"host": host}, timeout=60)
        data = resp.json()
    except (requests.exceptions.RequestException, ValueError):
        return "error"
    if data.get("error") or not data.get("grade"):
        return "error"
    return str(data["grade"])


def distance(ours: str, theirs: str) -> int | None:
    """Diferencia en letras (A+ y A- cuentan como A). None si no se puede comparar."""
    a, b = ours[:1], theirs[:1]
    if a not in LETTERS or b not in LETTERS:
        return None
    return abs(LETTERS.index(a) - LETTERS.index(b))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sitios", type=Path, default=ROOT / "validacion" / "sitios.txt")
    parser.add_argument(
        "--observatory",
        action="store_true",
        help="Consultar también Mozilla HTTP Observatory (envía el dominio a Mozilla).",
    )
    parser.add_argument("--no-save", action="store_true", help="No guardar en el histórico.")
    args = parser.parse_args()

    store = None if args.no_save else Storage()
    rows = []
    sites = read_sites(args.sitios)
    for n, (host, group) in enumerate(sites, 1):
        print(f"[{n}/{len(sites)}] {host} ...", end=" ", flush=True)
        start = time.perf_counter()
        row = {"sitio": host, "grupo": group}
        try:
            result = run_scan(f"https://{host}", mode=ScanMode.PASSIVE)
            row.update(
                nota=result.global_score,
                letra=result.grade,
                graves=sum(str(f.severity) in {"critica", "alta"} for f in result.findings),
                hallazgos=sum(1 for f in result.findings if not f.bonus),
                **{f"cat_{c}": s for c, s in result.category_scores.items()},
            )
            if store is not None:
                row["id"] = store.save(result)
        except (TargetError, FetchError) as exc:
            row.update(letra="error", error=str(exc)[:120])
        except Exception as exc:  # noqa: BLE001 - un fallo no debe parar la validación
            row.update(letra="fallo", error=f"{type(exc).__name__}: {exc}"[:120])
        row["segundos"] = round(time.perf_counter() - start, 1)
        if args.observatory:
            row["observatory"] = observatory_grade(host)
        print(
            row["letra"],
            row.get("nota", ""),
            f"({row['segundos']} s)",
            f"| Observatory {row['observatory']}" if args.observatory else "",
        )
        rows.append(row)

    out = ROOT / "validacion"
    fields = [
        "sitio",
        "grupo",
        "id",
        "letra",
        "nota",
        "graves",
        "hallazgos",
        "segundos",
        "observatory",
        "cat_tls",
        "cat_cabeceras",
        "cat_cookies",
        "cat_tecnologias",
        "cat_rutas",
        "cat_contenido",
        "error",
    ]
    with (out / "resultados.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    (out / "resultados.md").write_text(summary(rows, args.observatory), encoding="utf-8")
    print(f"\nResultados en {out / 'resultados.csv'} y {out / 'resultados.md'}")
    return 0


def summary(rows: list[dict], with_obs: bool) -> str:
    ok = [r for r in rows if r.get("nota") is not None]
    times = [r["segundos"] for r in ok]
    lines = [
        "# Resultados de la validación",
        "",
        f"Sitios: {len(rows)} · escaneados: {len(ok)} · con error: {len(rows) - len(ok)}",
    ]
    if times:
        lines.append(
            f"Tiempo por escaneo: mediana {statistics.median(times)} s, máximo {max(times)} s"
        )
    controls = [r for r in rows if r["grupo"] == "control"]
    if controls:
        hits = sum(r.get("letra") == "F" for r in controls)
        lines.append(f"Controles negativos (badssl.com) con F: {hits}/{len(controls)}")
    if with_obs:
        pairs = [d for r in ok if (d := distance(r["letra"], r.get("observatory", ""))) is not None]
        if pairs:
            lines.append(
                f"Comparación con Observatory ({len(pairs)} sitios): misma letra "
                f"{sum(d == 0 for d in pairs)}, a una letra {sum(d == 1 for d in pairs)}, "
                f"a dos o más {sum(d >= 2 for d in pairs)}"
            )
    lines += [
        "",
        "| Sitio | Grupo | Letra | Nota | Graves | Tiempo (s)"
        + (" | Observatory |" if with_obs else " |"),
        "|---|---|---|---|---|---" + ("|---|" if with_obs else "|"),
    ]
    for r in rows:
        cells = [
            r["sitio"],
            r["grupo"],
            r.get("letra", ""),
            r.get("nota", ""),
            r.get("graves", ""),
            r["segundos"],
        ]
        if with_obs:
            cells.append(r.get("observatory", ""))
        lines.append("| " + " | ".join(str(c) for c in cells) + " |")
    errors = [r for r in rows if r.get("error")]
    if errors:
        lines += ["", "Errores:", *[f"- {r['sitio']}: {r['error']}" for r in errors]]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
