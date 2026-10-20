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
from escaner.reporting.json_report import to_json
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


@app.command()
def history(domain: str = typer.Argument(..., help="Dominio.")) -> None:
    """Lista los escaneos guardados de un dominio."""
    _not_implemented("history")


@app.command()
def compare(
    domain: str = typer.Argument(..., help="Dominio."),
    last: int = typer.Option(2, help="Número de escaneos a comparar."),
) -> None:
    """Compara escaneos de un dominio (hallazgos nuevos, resueltos y variación de nota)."""
    _not_implemented("compare")


@app.command()
def export(
    scan_id: int = typer.Argument(..., help="Id del escaneo."),
    format: str = typer.Option("json", "--format", help="pdf, html o json."),
) -> None:
    """Exporta el informe de un escaneo."""
    _not_implemented("export")


@app.command()
def ask(
    scan_id: int = typer.Argument(..., help="Id del escaneo."),
    question: str = typer.Argument(..., help="Pregunta sobre el informe."),
) -> None:
    """Pregunta sobre un informe ya generado."""
    _not_implemented("ask")


if __name__ == "__main__":
    app()
