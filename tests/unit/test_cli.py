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
