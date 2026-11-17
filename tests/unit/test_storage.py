"""Pruebas del histórico en SQLite y de la comparación (RF-10, RF-11)."""

import json
from datetime import UTC, datetime, timedelta

import pytest
from typer.testing import CliRunner

from escaner.cli import app
from escaner.models import Category, ScanContext, ScanResult
from escaner.rules import finding
from escaner.scoring import score_result
from escaner.storage import Storage, default_db_path

runner = CliRunner()
T0 = datetime(2026, 11, 15, 10, 0, tzinfo=UTC)


def result(rule_ids, url="https://ejemplo.es/", minutes=0):
    ctx = ScanContext(url, final_url=url, started_at=T0 + timedelta(minutes=minutes))
    r = ScanResult(
        ctx, [finding(rid, "evidencia") for rid in rule_ids], {Category.HEADERS, Category.TLS}
    )
    return score_result(r)


@pytest.fixture
def store(tmp_path):
    return Storage(tmp_path / "escaner.db")


def test_guarda_y_recupera_un_escaneo(store):
    scan_id = store.save(result(["HSTS_MISSING", "CSP_MISSING"]))
    scan = store.get_scan(scan_id)
    assert scan["domain"] == "ejemplo.es"
    assert scan["grade"] == "B" and scan["global_score"] == 84.4  # (100·25 + 65·20) / 45
    assert scan["category_scores"] == {"tls": 100, "cabeceras": 65}
    assert [f["rule_id"] for f in scan["findings"]] == ["HSTS_MISSING", "CSP_MISSING"]


def test_historico_mas_reciente_primero_y_solo_del_dominio(store):
    store.save(result(["HSTS_MISSING"], minutes=0))
    store.save(result([], url="https://otro.es/", minutes=1))
    store.save(result([], minutes=2))
    rows = store.history("ejemplo.es")
    assert [r["serious"] for r in rows] == [0, 1]
    assert rows[0]["scanned_at"] > rows[1]["scanned_at"]
    assert store.history("https://ejemplo.es/ruta") == rows  # acepta también una URL


def test_comparacion_nuevos_resueltos_y_variacion(store):
    a = store.save(result(["HSTS_MISSING", "CSP_MISSING"], minutes=0))
    b = store.save(result(["CSP_MISSING", "XCTO_MISSING", "HSTS_PRELOAD"], minutes=5))
    cmp = store.compare(a, b)
    assert [f["rule_id"] for f in cmp.resolved] == ["HSTS_MISSING"]
    assert [f["rule_id"] for f in cmp.new_findings] == [
        "XCTO_MISSING"
    ]  # HSTS_PRELOAD suma: no cuenta
    assert [f["rule_id"] for f in cmp.unchanged] == ["CSP_MISSING"]
    assert cmp.score_delta == round(cmp.new["global_score"] - cmp.old["global_score"], 1)
    assert store.compare_last("ejemplo.es").new["id"] == b


def test_comparar_sin_dos_escaneos_da_error(store):
    store.save(result([]))
    with pytest.raises(KeyError):
        store.compare_last("ejemplo.es")


def test_consultas_parametrizadas_frente_a_inyeccion_sql(store):
    store.save(result(["HSTS_MISSING"]))
    malicioso = "ejemplo.es' OR '1'='1"
    assert store.history(malicioso) == []
    store.save(result([], url="https://x.es/'); DROP TABLE scans;--/"))
    assert len(store.history("ejemplo.es")) == 1  # la tabla sigue ahí


def test_informes_de_ia_se_guardan_por_perfil(store):
    scan_id = store.save(result([]))
    store.save_report(scan_id, "tecnico", "qwen2.5:3b", {"resumen": "ok"})
    assert store.get_report(scan_id, "tecnico")["content"] == {"resumen": "ok"}
    assert store.get_report(scan_id, "divulgativo") is None


# --- CLI -------------------------------------------------------------------


def test_cli_history_compare_y_export(tmp_path):
    store = Storage(default_db_path())  # ruta aislada por tests/conftest.py
    a = store.save(result(["HSTS_MISSING"], minutes=0))
    b = store.save(result([], minutes=5))

    r = runner.invoke(app, ["history", "ejemplo.es"])
    assert r.exit_code == 0 and str(a) in r.stdout and str(b) in r.stdout

    r = runner.invoke(app, ["compare", "ejemplo.es"])
    assert r.exit_code == 0 and "Resueltos (1)" in r.stdout and "▲" in r.stdout

    out = tmp_path / "e.json"
    r = runner.invoke(app, ["export", str(a), "-f", "json", "--output", str(out)])
    data = json.loads(out.read_text())
    assert (
        r.exit_code == 0
        and data["scan_id"] == a
        and data["findings"][0]["rule_id"] == "HSTS_MISSING"
    )


def test_cli_history_de_dominio_sin_escaneos():
    r = runner.invoke(app, ["history", "nadie.es"])
    assert r.exit_code == 1 and "No hay escaneos" in r.stdout
