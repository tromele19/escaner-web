"""Pruebas del orquestador y de la exportación JSON."""

import json

import pytest

from escaner.acquisition.fetcher import FetchError, FetchResult, Hop
from escaner.models import Category, ScanMode
from escaner.reporting.json_report import to_dict, to_json
from escaner.rules import finding
from escaner.scanner import run_scan
from escaner.validator import TargetError
from tests.unit.tls_fakes import fake_inspector

DNS = {"ejemplo.es": ["93.184.216.34"], "interno.es": ["10.0.0.1"]}


def resolver(host, port):
    if host not in DNS:
        raise TargetError("No se puede resolver")
    return DNS[host]


def make_fetcher(headers=None, cookies=(), tls_verified=True, error=None):
    calls = []

    def fetcher(target, **kwargs):
        calls.append((target, kwargs))
        if error:
            raise error
        return FetchResult(
            requested_url="http://ejemplo.es/",
            final_url="https://ejemplo.es/",
            status_code=200,
            headers=headers or {},
            set_cookies=list(cookies),
            redirect_chain=[Hop("http://ejemplo.es/", 301, "https://ejemplo.es/")],
            html="<html></html>",
            tls_verified=tls_verified,
        )

    fetcher.calls = calls
    return fetcher


def fake_prober():
    calls = []

    def prober(base_url, paths, **kw):
        calls.append((base_url, list(paths), kw))
        return {
            "__soft404__": {"status": 404, "content_type": "text/html", "length": 10, "body": "no"}
        }

    prober.calls = calls
    return prober


def scan(url="http://ejemplo.es", **kwargs):
    kwargs.setdefault("fetcher", make_fetcher())
    kwargs.setdefault("tls_inspector", fake_inspector())
    kwargs.setdefault("prober", fake_prober())
    return run_scan(url, resolver=resolver, **kwargs)


def test_flujo_completo_rellena_contexto_hallazgos_y_nota():
    r = scan(fetcher=make_fetcher(cookies=["PHPSESSID=x"]))
    assert r.context.final_url == "https://ejemplo.es/"
    assert r.context.redirect_chain == ["http://ejemplo.es/"]
    assert r.evaluated_categories == {
        Category.TLS,
        Category.HEADERS,
        Category.COOKIES,
        Category.CONTENT,
    }
    assert "HSTS_MISSING" in {f.rule_id for f in r.findings}
    assert "SESSION_COOKIE_NO_SECURE" in {f.rule_id for f in r.findings}
    assert r.grade is not None and 0 <= r.global_score <= 100


def test_sin_cookies_la_categoria_no_aplica():
    r = scan()
    assert Category.COOKIES not in r.evaluated_categories
    assert Category.COOKIES not in r.category_scores


def test_objetivo_privado_se_rechaza_antes_de_descargar():
    fetcher = make_fetcher()
    with pytest.raises(TargetError):
        scan("http://interno.es", fetcher=fetcher)
    assert fetcher.calls == []


def test_modo_laboratorio_se_propaga_al_cliente_http():
    fetcher = make_fetcher()
    scan("http://interno.es", allow_private=True, fetcher=fetcher)
    assert fetcher.calls[0][1]["allow_private"] is True


def test_error_de_descarga_se_propaga():
    with pytest.raises(FetchError):
        scan(fetcher=make_fetcher(error=FetchError("sin conexión")))


def test_certificado_no_valido_queda_en_el_contexto():
    r = scan(fetcher=make_fetcher(tls_verified=False))
    assert r.context.tls_info["verified"] is False


def test_modo_se_guarda_en_el_contexto():
    assert scan(mode=ScanMode.FULL).context.mode is ScanMode.FULL


# --- JSON ----------------------------------------------------------------


def test_json_valido_y_sin_datos_en_bruto():
    r = scan(fetcher=make_fetcher(cookies=["PHPSESSID=VALOR_SECRETO"]))
    data = json.loads(to_json(r))
    assert data["grade"] == r.grade
    assert data["categories"]["cookies"]["weight"] == 15
    assert data["categories"]["tls"]["weight"] == 25
    assert data["categories"]["rutas"] is None  # no evaluada en modo pasivo
    assert "VALOR_SECRETO" not in to_json(r)
    assert "<html>" not in to_json(r)


def test_json_tiene_todos_los_campos_de_hallazgo():
    d = to_dict(scan())
    assert set(d["findings"][0]) == {
        "category",
        "rule_id",
        "severity",
        "title",
        "evidence",
        "reference",
        "bonus",
    }


# --- Saneado de la evidencia ---------------------------------------------


def test_evidencia_sin_caracteres_de_control():
    f = finding("XFO_INVALID", "ALLOW\x1b[31m-FROM\x00\r\nX")
    assert "\x1b" not in f.evidence and "\x00" not in f.evidence and "\n" not in f.evidence


# --- Integración del TLS ------------------------------------------------


def test_sitio_sin_https_da_f():
    r = scan(tls_inspector=fake_inspector(error="Connection refused"))
    assert "TLS_NO_HTTPS" in {f.rule_id for f in r.findings}
    assert r.grade == "F"


def test_se_inspecciona_el_host_final_si_es_https():
    inspector = fake_inspector()
    scan(tls_inspector=inspector)
    assert inspector.calls == [("ejemplo.es", 443)]


def test_url_http_que_redirige_a_https_no_penaliza():
    r = scan("http://ejemplo.es")
    assert r.context.tls_info["http_redirects_to_https"] is True
    assert "TLS_NO_HTTPS_REDIRECT" not in {f.rule_id for f in r.findings}


def test_url_https_comprueba_tambien_la_version_http():
    fetcher = make_fetcher()
    r = scan("https://ejemplo.es", fetcher=fetcher)
    assert [c[0].url for c in fetcher.calls] == ["https://ejemplo.es/", "http://ejemplo.es/"]
    assert r.context.tls_info["http_redirects_to_https"] is True


# --- Modo completo --------------------------------------------------------


def test_modo_pasivo_no_pide_ninguna_ruta():
    prober = fake_prober()
    r = scan(prober=prober)
    assert prober.calls == []
    assert Category.PATHS not in r.evaluated_categories


def test_modo_completo_sondea_el_origen_final():
    prober = fake_prober()
    r = scan(mode=ScanMode.FULL, prober=prober)
    assert prober.calls[0][0] == "https://ejemplo.es/"
    assert Category.PATHS in r.evaluated_categories
