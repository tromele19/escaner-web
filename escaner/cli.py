"""Interfaz de línea de comandos (capa de presentación)."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from escaner import __version__
from escaner.acquisition.fetcher import FetchError
from escaner.models import ScanMode, ScanResult, Severity
from escaner.reporting.json_report import stored_to_json, to_json
from escaner.scanner import run_scan
from escaner.scoring import WEIGHTS
from escaner.validator import TargetError

app = typer.Typer(
    name="escaner",
    help="Escáner de seguridad web con IA. Úsalo solo contra sitios propios o autorizados.",
    no_args_is_help=True,
)
console = Console()

AUTH_WARNING = (
    "El modo completo envía peticiones adicionales a rutas concretas del sitio.\n"
    "Solo debe usarse contra sitios propios o con autorización expresa "
    "(art. 197 bis del Código Penal)."
)


def _not_implemented(feature: str) -> None:
    console.print(f"[yellow]{feature}: todavía no implementado.[/yellow]")
    raise typer.Exit(code=2)


@app.command()
def version() -> None:
    """Muestra la versión de la herramienta."""
    console.print(f"escaner-web {__version__}")


@app.command()
def scan(
    url: str = typer.Argument(..., help="URL o dominio a analizar."),
    authorized: bool = typer.Option(
        False, "--authorized", help="Modo completo (incluye rutas sensibles). Exige autorización."
    ),
    lab: bool = typer.Option(
        False, "--lab", help="Permite direcciones privadas (solo para el laboratorio propio)."
    ),
    json_out: Path | None = typer.Option(
        None, "--json", help="Guarda el resultado en un fichero JSON.", dir_okay=False
    ),
    save: bool = typer.Option(True, "--save/--no-save", help="Guardar en el histórico."),
    profile: str = typer.Option("divulgativo", help="Perfil del informe: tecnico o divulgativo."),
) -> None:
    """Analiza una URL y muestra la nota y los hallazgos."""
    mode = ScanMode.PASSIVE
    if authorized:
        console.print(f"[bold red]Aviso:[/bold red] {AUTH_WARNING}")
        if not typer.confirm("¿Confirmas que eres propietario del sitio o tienes autorización?"):
            console.print("Escaneo cancelado.")
            raise typer.Exit(code=1)
        mode = ScanMode.FULL

    try:
        with console.status(f"Analizando {url}..."):
            result = run_scan(url, mode=mode, allow_private=lab)
    except (TargetError, FetchError) as exc:
        console.print(Text(f"Error: {exc}", style="bold red"))
        raise typer.Exit(code=1) from exc

    print_result(result)
    if save:
        from escaner.storage import Storage

        scan_id = Storage().save(result)
        console.print(
            f"Escaneo guardado en el histórico con id [bold]{scan_id}[/bold] "
            f"(escaner history {Text(result.context.target_url).plain})"
        )
    if json_out is not None:
        json_out.write_text(to_json(result), encoding="utf-8")
        console.print(f"Resultado guardado en {json_out}")


SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "green",
}
SEVERITY_ORDER = list(Severity)
GRADE_STYLE = {"A": "bold green", "B": "green", "C": "yellow", "D": "dark_orange", "E": "red"}


def print_result(result: ScanResult) -> None:
    """Muestra el resultado en la terminal.

    Todo el texto procedente del sitio se pasa como ``Text`` (no como marcado
    de Rich) para que no pueda inyectar estilos ni secuencias de escape.
    """
    ctx = result.context
    grade = result.grade or "-"
    header = Text.assemble(
        ("Nota global: ", "bold"),
        (f" {grade} ", GRADE_STYLE.get(grade, "bold white on red")),
        f"  {result.global_score if result.global_score is not None else '-'} / 100",
    )
    console.print()
    console.print(Text(f"Objetivo: {ctx.target_url}", style="bold"))
    if ctx.final_url and ctx.final_url != ctx.target_url:
        console.print(Text(f"URL final: {ctx.final_url} ({len(ctx.redirect_chain)} redirecciones)"))
    if ctx.tls_info and not ctx.tls_info.get("verified", True):
        console.print(Text("Aviso: el certificado TLS no es válido.", style="bold red"))
    console.print(header)

    categories = Table(title="Categorías", show_lines=False)
    categories.add_column("Categoría")
    categories.add_column("Peso", justify="right")
    categories.add_column("Nota", justify="right")
    for cat, weight in WEIGHTS.items():
        score = result.category_scores.get(cat)
        categories.add_row(
            str(cat), f"{weight} %", str(score) if score is not None else Text("No aplica", "dim")
        )
    console.print(categories)

    findings = sorted(
        result.findings, key=lambda f: (SEVERITY_ORDER.index(f.severity), str(f.category))
    )
    table = Table(title=f"Hallazgos ({len(findings)})", show_lines=False)
    table.add_column("Severidad")
    table.add_column("Categoría")
    table.add_column("Hallazgo")
    table.add_column("Evidencia", overflow="fold")
    for f in findings:
        table.add_row(
            Text(str(f.severity), SEVERITY_STYLE[f.severity]),
            Text(str(f.category)),
            Text(f.title),
            Text(f.evidence, style="dim"),
        )
    console.print(table)


@app.command(name="update-cve")
def update_cve() -> None:
    """Descarga de NVD la base local de CVE (tarda unos minutos sin clave de API)."""
    import requests

    from escaner.cve.updater import default_db_path, update_database

    path = default_db_path()
    console.print(f"Descargando CVE de NVD en {path} (5 peticiones cada 30 s sin NVD_API_KEY)...")
    try:
        db = update_database(path, progress=lambda msg: console.print(f"  {msg}"))
    except requests.exceptions.RequestException as exc:
        console.print(Text(f"Error descargando de NVD: {exc}", style="bold red"))
        raise typer.Exit(code=1) from exc
    console.print(f"[green]Base de CVE actualizada:[/green] {path}")
    if db.get("incomplete"):
        console.print(
            f"[yellow]Sin descargar (NVD no respondió):[/yellow] {', '.join(db['incomplete'])}. "
            "Vuelve a ejecutar «escaner update-cve» más tarde."
        )


@app.command()
def history(
    domain: str = typer.Argument(..., help="Dominio, p. ej. ejemplo.es."),
    limit: int = typer.Option(20, help="Número máximo de escaneos."),
) -> None:
    """Lista los escaneos guardados de un dominio."""
    from escaner.storage import Storage

    rows = Storage().history(domain, limit)
    if not rows:
        console.print(f"No hay escaneos guardados de {domain}.")
        raise typer.Exit(code=1)
    table = Table(title=f"Histórico de {domain}")
    for col in ("Id", "Fecha (UTC)", "Modo", "Nota", "Graves"):
        table.add_column(col, justify="right" if col in {"Id", "Nota", "Graves"} else "left")
    for r in rows:
        grade = r["grade"] or "-"
        table.add_row(
            str(r["id"]),
            r["scanned_at"][:16].replace("T", " "),
            r["mode"],
            Text(
                f"{grade} {r['global_score'] if r['global_score'] is not None else '-'}",
                GRADE_STYLE.get(grade, "bold red"),
            ),
            str(r["serious"]),
        )
    console.print(table)


@app.command()
def compare(
    domain: str = typer.Argument(..., help="Dominio."),
    old: int | None = typer.Option(None, "--old", help="Id del escaneo antiguo."),
    new: int | None = typer.Option(None, "--new", help="Id del escaneo nuevo."),
) -> None:
    """Compara escaneos de un dominio: hallazgos nuevos, resueltos y variación de nota.

    Sin --old/--new compara los dos últimos escaneos del dominio.
    """
    from escaner.storage import Storage

    store = Storage()
    try:
        cmp = store.compare(old, new) if old and new else store.compare_last(domain)
    except KeyError as exc:
        console.print(Text(str(exc.args[0]), style="bold red"))
        raise typer.Exit(code=1) from exc

    delta = cmp.score_delta
    arrow = "=" if not delta else ("▲" if delta > 0 else "▼")
    style = "green" if delta and delta > 0 else "red" if delta and delta < 0 else "white"
    console.print(
        Text(
            f"{cmp.domain}: escaneo {cmp.old['id']} ({cmp.old['grade']} {cmp.old['global_score']})"
            f" → escaneo {cmp.new['id']} ({cmp.new['grade']} {cmp.new['global_score']})  "
            f"{arrow} {delta if delta is not None else ''}",
            style=f"bold {style}",
        )
    )
    for title, items, colour in (
        ("Resueltos", cmp.resolved, "green"),
        ("Nuevos", cmp.new_findings, "red"),
    ):
        table = Table(title=f"{title} ({len(items)})", title_style=colour)
        table.add_column("Severidad")
        table.add_column("Categoría")
        table.add_column("Hallazgo")
        for f in sorted(items, key=lambda f: SEVERITY_ORDER.index(Severity(f["severity"]))):
            table.add_row(
                Text(f["severity"], SEVERITY_STYLE[Severity(f["severity"])]),
                Text(f["category"]),
                Text(f["title"]),
            )
        console.print(table)
    console.print(f"Sin cambios: {len(cmp.unchanged)} hallazgos.")


@app.command()
def export(
    scan_id: int = typer.Argument(..., help="Id del escaneo (ver «escaner history»)."),
    format: str = typer.Option("json", "--format", help="json (html y pdf, próximamente)."),
    output: Path | None = typer.Option(None, "--output", "-o", help="Fichero de salida."),
) -> None:
    """Exporta el resultado de un escaneo guardado."""
    from escaner.storage import Storage

    scan = Storage().get_scan(scan_id)
    if scan is None:
        console.print(Text(f"No existe el escaneo {scan_id}.", style="bold red"))
        raise typer.Exit(code=1)
    if format != "json":
        _not_implemented(f"export --format {format}")
    content = stored_to_json(scan)
    if output is None:
        print(content)
    else:
        output.write_text(content, encoding="utf-8")
        console.print(f"Exportado a {output}")


@app.command()
def ask(
    scan_id: int = typer.Argument(..., help="Id del escaneo."),
    question: str = typer.Argument(..., help="Pregunta sobre el informe."),
) -> None:
    """Pregunta sobre un informe ya generado."""
    _not_implemented("ask")


if __name__ == "__main__":
    app()
