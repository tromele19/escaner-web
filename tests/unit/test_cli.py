from typer.testing import CliRunner

from escaner.cli import app

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "escaner-web" in result.stdout


def test_modo_completo_se_cancela_sin_confirmacion():
    result = runner.invoke(app, ["scan", "https://ejemplo.es", "--authorized"], input="n\n")
    assert result.exit_code == 1
    assert "cancelado" in result.stdout


def _fake_result():
    from escaner.acquisition.fetcher import FetchResult
    from escaner.scanner import run_scan

    def fetcher(target, **kwargs):
        return FetchResult(
            target.url, target.url, 200, {"X-Frame-Options": "[bold red]inyeccion[/]"}, ["sid=x"]
        )

    return run_scan("https://ejemplo.es", fetcher=fetcher, resolver=lambda h, p: ["93.184.216.34"])


def test_scan_muestra_nota_y_hallazgos(monkeypatch, tmp_path):
    import json

    import escaner.cli as cli

    monkeypatch.setattr(cli, "run_scan", lambda url, **kw: _fake_result())
    out = tmp_path / "r.json"
    result = runner.invoke(app, ["scan", "https://ejemplo.es", "--json", str(out)])
    assert result.exit_code == 0, result.stdout
    assert "Nota global" in result.stdout
    assert "No aplica" in result.stdout  # TLS, rutas... aún no evaluadas
    assert "[bold red]inyeccion[/]" in result.stdout  # se muestra literal, sin interpretar
    assert json.loads(out.read_text())["grade"] in list("ABCDEF")


def test_scan_objetivo_no_valido_sale_con_error():
    result = runner.invoke(app, ["scan", "http://127.0.0.1"])
    assert result.exit_code == 1
    assert "no pública" in result.stdout
