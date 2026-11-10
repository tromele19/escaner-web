"""Pruebas del motor de superficie de contenido (RF-07)."""

from pathlib import Path

import pytest

from escaner.engines.content import ContentEngine
from escaner.models import Category, ScanContext, Severity

# La misma página que sirve contenido.lab en el laboratorio
LAB_HTML = (Path(__file__).parents[2] / "lab/sites/contenido/index.html").read_text(
    encoding="utf-8"
)


def analyze(html, url="https://ejemplo.es/"):
    return ContentEngine().analyze(ScanContext(url, final_url=url, html=html))


def ids(html, url="https://ejemplo.es/"):
    return {f.rule_id for f in analyze(html, url)}


def test_pagina_limpia_sin_hallazgos():
    html = """<html><head><script src="/app.js"></script>
    <link rel="stylesheet" href="/estilo.css"></head>
    <body><img src="/logo.png"><form action="/login"><input type="password"></form>
    <a href="/otra" target="_blank">interna</a></body></html>"""
    assert analyze(html) == []


def test_pagina_del_laboratorio_contenido_lab():
    found = {f.rule_id: f for f in analyze(LAB_HTML, "https://contenido.lab/")}
    assert set(found) == {
        "MIXED_CONTENT_ACTIVE",
        "MIXED_CONTENT_PASSIVE",
        "FORM_PASSWORD_INSECURE",
        "THIRD_PARTY_SCRIPT_NO_SRI",
        "THIRD_PARTY_STYLE_NO_SRI",
        "TARGET_BLANK_NO_NOOPENER",
    }
    assert found["MIXED_CONTENT_ACTIVE"].severity is Severity.HIGH
    assert found["MIXED_CONTENT_ACTIVE"].category is Category.CONTENT
    assert "cdn.ejemplo-lab.test" in found["MIXED_CONTENT_ACTIVE"].evidence
    # dayjs lleva integrity: no debe aparecer como script sin SRI
    assert found["THIRD_PARTY_SCRIPT_NO_SRI"].evidence == "cdn.jsdelivr.net"


# --- Contenido mixto ------------------------------------------------------


@pytest.mark.parametrize(
    "tag",
    [
        '<script src="http://cdn.x.com/a.js"></script>',
        '<iframe src="http://x.com/"></iframe>',
        '<link rel="stylesheet" href="http://x.com/a.css">',
    ],
)
def test_contenido_mixto_activo(tag):
    assert "MIXED_CONTENT_ACTIVE" in ids(f"<html>{tag}</html>")


def test_contenido_mixto_pasivo_es_bajo():
    (f,) = analyze('<img src="http://x.com/a.png">')
    assert (f.rule_id, f.severity) == ("MIXED_CONTENT_PASSIVE", Severity.LOW)


def test_en_pagina_http_no_hay_contenido_mixto():
    assert ids('<script src="http://x.com/a.js"></script>', url="http://ejemplo.es/") == set()


# --- Formularios ----------------------------------------------------------


def test_formulario_con_contrasena_a_http():
    html = '<form action="http://ejemplo.es/login"><input type="password"></form>'
    assert "FORM_PASSWORD_INSECURE" in ids(html)


def test_login_en_pagina_http_con_action_relativa():
    html = '<form action="/login"><input type="PASSWORD"></form>'
    assert "FORM_PASSWORD_INSECURE" in ids(html, url="http://ejemplo.es/")


def test_formulario_sin_contrasena_a_http_desde_https():
    html = '<form action="http://ejemplo.es/buscar"><input name="q"></form>'
    assert ids(html) == {"FORM_INSECURE_ACTION"}


# --- SRI ------------------------------------------------------------------


def test_script_de_terceros_con_integrity_no_penaliza():
    html = '<script src="https://cdn.x.com/a.js" integrity="sha384-abc"></script>'
    assert ids(html) == set()


def test_subdominio_propio_no_es_tercero():
    html = '<script src="https://static.ejemplo.es/a.js"></script>'
    assert ids(html) == set()


def test_estilo_de_terceros_sin_sri():
    html = '<link rel="stylesheet" href="https://fonts.x.com/a.css">'
    assert ids(html) == {"THIRD_PARTY_STYLE_NO_SRI"}


# --- Enlaces --------------------------------------------------------------


def test_target_blank_con_noopener_no_penaliza():
    html = '<a href="https://otra.org" target="_blank" rel="noopener">x</a>'
    assert ids(html) == set()


def test_target_blank_sin_noopener_cuenta_enlaces():
    html = (
        '<a href="https://a.org" target="_blank">1</a><a href="https://b.org" target="_blank">2</a>'
    )
    (f,) = analyze(html)
    assert f.rule_id == "TARGET_BLANK_NO_NOOPENER" and f.evidence == "2 enlace(s)"


# --- Robustez -------------------------------------------------------------


def test_html_vacio_no_es_evaluable():
    assert ContentEngine().is_evaluable(ScanContext("https://ejemplo.es/", html="  ")) is False


def test_html_mal_formado_no_rompe_el_motor():
    assert isinstance(analyze("<html><script src=http://x.com/a.js<<form action=>"), list)


def test_evidencia_sin_fragmentos_de_html():
    html = '<script src="http://evil.com/a.js?<script>alert(1)</script>"></script>'
    (f,) = analyze(html)
    assert "<" not in f.evidence and f.evidence == "evil.com"
