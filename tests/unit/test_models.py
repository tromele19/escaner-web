import pytest

from escaner.engines.base import Engine
from escaner.models import Category, Finding, ScanContext, ScanMode, ScanResult, Severity


def test_penalizaciones_coinciden_con_la_rubrica():
    assert Severity.CRITICAL.penalty == 40
    assert Severity.HIGH.penalty == 25
    assert Severity.MEDIUM.penalty == 10
    assert Severity.LOW.penalty == 5
    assert Severity.INFO.penalty == 0


def test_finding_valido():
    f = Finding(Category.HEADERS, "HSTS_MISSING", Severity.HIGH, "Falta HSTS")
    assert f.category is Category.HEADERS


INVALIDOS = ["", "hsts_missing", "HSTS MISSING", "HSTS-MISSING", "<script>"]


@pytest.mark.parametrize("rule_id", INVALIDOS)
def test_finding_rechaza_rule_id_no_valido(rule_id):
    with pytest.raises(ValueError):
        Finding(Category.HEADERS, rule_id, Severity.LOW, "x")


def test_finding_rechaza_bonus_negativo():
    with pytest.raises(ValueError):
        Finding(Category.HEADERS, "CSP_OK", Severity.INFO, "x", bonus=-1)


def test_scan_result_filtra_por_categoria():
    ctx = ScanContext(target_url="https://ejemplo.es")
    r = ScanResult(
        context=ctx,
        findings=[
            Finding(Category.HEADERS, "HSTS_MISSING", Severity.HIGH, "a"),
            Finding(Category.COOKIES, "COOKIE_NO_SECURE", Severity.HIGH, "b"),
        ],
    )
    assert [f.rule_id for f in r.findings_for(Category.COOKIES)] == ["COOKIE_NO_SECURE"]


def test_motor_de_rutas_solo_en_modo_completo():
    class RutasFalso(Engine):
        category = Category.PATHS
        modes = frozenset({ScanMode.FULL})

        def analyze(self, context):
            return []

    motor = RutasFalso()
    assert not motor.applies_to(ScanContext("https://ejemplo.es", mode=ScanMode.PASSIVE))
    assert motor.applies_to(ScanContext("https://ejemplo.es", mode=ScanMode.FULL))
