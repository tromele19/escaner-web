"""Pruebas del motor de cookies (RF-04)."""

import pytest

from escaner.engines.cookies import CookiesEngine, parse_set_cookie
from escaner.models import Category, ScanContext, Severity

GOOD_SESSION = "__Host-session=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"


def analyze(*cookies, url="https://ejemplo.es/"):
    ctx = ScanContext(target_url=url, final_url=url, raw_set_cookies=list(cookies))
    return CookiesEngine().analyze(ctx)


def ids(*cookies):
    return {f.rule_id for f in analyze(*cookies)}


# --- Parser --------------------------------------------------------------


def test_parser_separa_nombre_y_atributos_sin_guardar_el_valor():
    c = parse_set_cookie("SID=secreto; Path=/app; Secure; HttpOnly; SameSite=Strict")
    assert c.name == "SID"
    assert c.secure and c.httponly and c.samesite == "strict"
    assert c.attributes["path"] == "/app"
    assert "secreto" not in c.describe()


def test_parser_cookie_con_fecha_y_comas():
    c = parse_set_cookie("id=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure")
    assert c.secure
    assert "expires" not in c.describe()


@pytest.mark.parametrize("header", ["", "sinigual", "=valor; Secure"])
def test_parser_rechaza_cabeceras_mal_formadas(header):
    assert parse_set_cookie(header) is None


# --- Cookies de sesión ---------------------------------------------------


def test_cookie_de_sesion_correcta_solo_suma():
    findings = analyze(GOOD_SESSION)
    assert [f.rule_id for f in findings] == ["SESSION_COOKIE_HOST_PREFIX"]
    assert findings[0].bonus > 0
    assert findings[0].category is Category.COOKIES


@pytest.mark.parametrize("name", ["PHPSESSID", "JSESSIONID", "sid", "connect.sid", "auth_token"])
def test_reconoce_nombres_de_sesion(name):
    assert "SESSION_COOKIE_NO_SECURE" in ids(f"{name}=x; HttpOnly; SameSite=Lax")


def test_cookie_de_sesion_sin_ningun_atributo():
    findings = analyze("PHPSESSID=abc")
    assert {f.rule_id for f in findings} == {
        "SESSION_COOKIE_NO_SECURE",
        "SESSION_COOKIE_NO_HTTPONLY",
        "SESSION_COOKIE_NO_SAMESITE",
    }
    assert {f.severity for f in findings} == {Severity.HIGH, Severity.LOW}


def test_la_evidencia_no_contiene_el_valor_de_la_cookie():
    for f in analyze("PHPSESSID=VALOR_SECRETO_123"):
        assert "VALOR_SECRETO_123" not in f.evidence
        assert "PHPSESSID" in f.evidence


# --- Otras cookies -------------------------------------------------------


@pytest.mark.parametrize("name", ["inside", "consider", "tema"])
def test_no_confunde_palabras_que_contienen_sid(name):
    assert "SESSION_COOKIE_NO_SECURE" not in ids(f"{name}=x")


def test_cookie_normal_sin_secure_es_baja():
    findings = analyze("tema=oscuro; Path=/")
    assert [(f.rule_id, f.severity) for f in findings] == [("COOKIE_NO_SECURE", Severity.LOW)]


def test_cookie_normal_sin_httponly_no_penaliza():
    assert ids("tema=oscuro; Secure; SameSite=Lax") == set()


def test_samesite_none_sin_secure():
    assert "COOKIE_SAMESITE_NONE_INSECURE" in ids("pref=1; SameSite=None")


def test_samesite_valor_invalido():
    assert "COOKIE_SAMESITE_INVALID" in ids("pref=1; Secure; SameSite=Siempre")


# --- Prefijos ------------------------------------------------------------


@pytest.mark.parametrize(
    "header",
    [
        "__Host-id=1; Secure; Path=/; Domain=ejemplo.es",  # no puede llevar Domain
        "__Host-id=1; Secure; Path=/app",  # Path debe ser /
        "__Host-id=1; Path=/",  # falta Secure
        "__Secure-id=1; Path=/",  # falta Secure
    ],
)
def test_prefijo_que_no_cumple_requisitos(header):
    assert "COOKIE_PREFIX_INVALID" in ids(header)


def test_prefijo_secure_correcto():
    assert ids("__Secure-pref=1; Secure; SameSite=Lax") == set()


# --- Varias cookies y casos límite ---------------------------------------


def test_no_duplica_hallazgos_de_la_misma_cookie():
    findings = analyze("tema=a", "tema=b")
    assert len(findings) == 1


def test_cookie_que_se_borra_no_se_evalua():
    ctx = ScanContext("https://ejemplo.es/", raw_set_cookies=["PHPSESSID=; Max-Age=0"])
    assert CookiesEngine().analyze(ctx) == []
    assert CookiesEngine().is_evaluable(ctx) is False


def test_sitio_sin_cookies_no_es_evaluable():
    assert CookiesEngine().is_evaluable(ScanContext("https://ejemplo.es/")) is False


def test_sitio_con_cookies_es_evaluable():
    ctx = ScanContext("https://ejemplo.es/", raw_set_cookies=["a=1"])
    assert CookiesEngine().is_evaluable(ctx) is True
