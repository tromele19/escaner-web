"""Interfaz de línea de comandos (capa de presentación)."""

from __future__ import annotations

import typer
from rich.console import Console

from escaner import __version__
from escaner.models import ScanMode

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
    console.print(f"Objetivo: {url} · modo {mode} · perfil {profile}")
    _not_implemented("scan")


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
