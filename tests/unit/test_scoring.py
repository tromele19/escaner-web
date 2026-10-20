"""Pruebas del motor de puntuación (RF-09)."""

import pytest

from escaner.models import Category, Finding, ScanContext, ScanResult, Severity
from escaner.scoring import WEIGHTS, category_score, grade_for, score_result


def f(sev, cat=Category.HEADERS, bonus=0, rule="REGLA_PRUEBA"):
    return Finding(cat, rule, sev, "prueba", bonus=bonus)


def result(findings, evaluated):
    return ScanResult(ScanContext("https://ejemplo.es/"), findings, set(evaluated))


# --- Nota por categoría --------------------------------------------------


def test_sin_hallazgos_100():
    assert category_score([]) == 100


@pytest.mark.parametrize(
    ("sev", "expected"),
    [
        (Severity.CRITICAL, 60),
        (Severity.HIGH, 75),
        (Severity.MEDIUM, 90),
        (Severity.LOW, 95),
        (Severity.INFO, 100),
    ],
)
def test_penalizacion_por_severidad(sev, expected):
    assert category_score([f(sev)]) == expected


def test_nunca_baja_de_cero():
    assert category_score([f(Severity.CRITICAL)] * 5) == 0


def test_bonificacion_no_supera_100():
    assert category_score([f(Severity.INFO, bonus=5)] * 3) == 100


def test_bonificacion_compensa_parcialmente():
    assert category_score([f(Severity.MEDIUM), f(Severity.INFO, bonus=5)]) == 95


# --- Escala --------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "letter"),
    [
        (100, "A"),
        (90, "A"),
        (89.9, "B"),
        (80, "B"),
        (70, "C"),
        (60, "D"),
        (50, "E"),
        (49.9, "F"),
        (0, "F"),
    ],
)
def test_escala_de_notas(score, letter):
    assert grade_for(score) == letter


# --- Nota global ---------------------------------------------------------


def test_pesos_suman_100():
    assert sum(WEIGHTS.values()) == 100


def test_media_ponderada_solo_de_categorias_evaluables():
    # Cabeceras 20 % con 75 y cookies 15 % con 100 -> (75*20 + 100*15) / 35 = 85.7
    r = score_result(result([f(Severity.HIGH)], {Category.HEADERS, Category.COOKIES}))
    assert r.category_scores == {Category.HEADERS: 75, Category.COOKIES: 100}
    assert r.global_score == 85.7
    assert r.grade == "B"


def test_categoria_no_evaluable_no_cuenta():
    # Hallazgos de cookies con la categoría no evaluada: se ignoran
    r = score_result(result([f(Severity.HIGH, Category.COOKIES)], {Category.HEADERS}))
    assert Category.COOKIES not in r.category_scores
    assert r.global_score == 100.0


def test_un_hallazgo_critico_limita_la_nota_a_d():
    findings = [f(Severity.CRITICAL, Category.HEADERS)]
    evaluated = set(WEIGHTS)  # todas evaluadas -> 60*20/100 + 80 = 92 sin el límite
    r = score_result(result(findings, evaluated))
    assert r.global_score == 69
    assert r.grade == "D"


def test_sin_categorias_evaluadas_no_hay_nota():
    r = score_result(result([], set()))
    assert r.global_score is None and r.grade is None


def test_es_determinista():
    findings = [f(Severity.MEDIUM), f(Severity.LOW, Category.COOKIES)]
    a = score_result(result(findings, {Category.HEADERS, Category.COOKIES}))
    b = score_result(result(list(reversed(findings)), {Category.COOKIES, Category.HEADERS}))
    assert (a.global_score, a.grade, a.category_scores) == (
        b.global_score,
        b.grade,
        b.category_scores,
    )
