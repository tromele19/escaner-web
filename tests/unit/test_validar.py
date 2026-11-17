"""Pruebas del script de validación (sin red)."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("validar", ROOT / "scripts" / "validar.py")
validar = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validar)


def test_lee_la_lista_de_sitios(tmp_path):
    f = tmp_path / "s.txt"
    f.write_text("# comentario\n\nejemplo.es  medios  # nota\nsolo.es\n", encoding="utf-8")
    assert validar.read_sites(f) == [("ejemplo.es", "medios"), ("solo.es", "-")]


def test_lista_real_tiene_controles():
    sites = validar.read_sites(ROOT / "validacion" / "sitios.txt")
    assert len(sites) >= 30 and sum(g == "control" for _, g in sites) >= 3


def test_distancia_entre_letras():
    assert validar.distance("B", "B+") == 0
    assert validar.distance("A", "C-") == 2
    assert validar.distance("D", "error") is None


def test_resumen_con_controles_y_observatory():
    rows = [
        {
            "sitio": "a.es",
            "grupo": "x",
            "letra": "B",
            "nota": 82.0,
            "graves": 1,
            "segundos": 3.0,
            "observatory": "B-",
        },
        {
            "sitio": "expired.badssl.com",
            "grupo": "control",
            "letra": "F",
            "nota": 40.0,
            "graves": 1,
            "segundos": 2.0,
            "observatory": "error",
        },
        {
            "sitio": "caido.es",
            "grupo": "x",
            "letra": "error",
            "segundos": 0.1,
            "error": "No se puede resolver",
        },
    ]
    md = validar.summary(rows, with_obs=True)
    assert "escaneados: 2" in md and "con F: 1/1" in md and "misma letra 1" in md
    assert "caido.es: No se puede resolver" in md
