"""Pruebas de la detección de tecnologías, la base de CVE y el motor 6 (RF-08)."""

import json

import pytest

from escaner.cve.fingerprint import detect
from escaner.cve.matcher import CVEDatabase, in_range, version_key
from escaner.cve.updater import cvss_score, default_db_path, parse_cve, update_database
from escaner.engines.tech import TechEngine
from escaner.models import Category, ScanContext, Severity

# --- Detección -------------------------------------------------------------


def techs(headers=None, html=None):
    return {(t.product, t.version) for t in detect(headers or {}, html)}


def test_cabeceras_server_y_x_powered_by():
    found = techs({"Server": "Apache/2.4.49 (Unix) OpenSSL/1.1.1k", "X-Powered-By": "PHP/7.4.3"})
    assert found == {("apache", "2.4.49"), ("openssl", "1.1.1"), ("php", "7.4.3")}


def test_server_sin_version():
    assert techs({"Server": "nginx"}) == {("nginx", None)}


def test_meta_generator_y_jquery():
    html = """<meta name="generator" content="WordPress 6.4.2">
    <script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>"""
    assert techs(html=html) == {("wordpress", "6.4.2"), ("jquery", "3.5.1")}


def test_html_del_laboratorio_inseguro():
    html = '<meta name="generator" content="WordPress 5.8">'
    assert techs({"Server": "nginx/1.26.3", "X-Powered-By": "PHP/7.4.3"}, html) == {
        ("nginx", "1.26.3"),
        ("php", "7.4.3"),
        ("wordpress", "5.8"),
    }


# --- Versiones y rangos --------------------------------------------------


def test_version_key():
    assert version_key("2.4.49") == (2, 4, 49)
    assert version_key("1.1.1k") == (1, 1, 1)
    assert version_key("abc") == ()


@pytest.mark.parametrize(
    ("version", "rng", "expected"),
    [
        ("7.4.3", {"exact": "7.4.3"}, True),
        ("7.4.3", {"exact": "7.4.4"}, False),
        ("7.4.3", {"versionStartIncluding": "7.4.0", "versionEndExcluding": "7.4.21"}, True),
        ("7.4.21", {"versionStartIncluding": "7.4.0", "versionEndExcluding": "7.4.21"}, False),
        ("7.4.21", {"versionEndIncluding": "7.4.21"}, True),
        ("7.4", {"versionStartExcluding": "7.4.0"}, False),  # 7.4 == 7.4.0
        ("8.1.0", {"versionStartIncluding": "7.4.0", "versionEndExcluding": "7.4.21"}, False),
        ("5.8", {"all": True}, False),
        ("raro", {"exact": "raro"}, False),
    ],
)
def test_in_range(version, rng, expected):
    assert in_range(version, rng) is expected


# --- Formato de NVD --------------------------------------------------------


def nvd_cve(cve_id, criteria, score, **ranges):
    return {
        "cve": {
            "id": cve_id,
            "published": "2021-09-16T15:15:07.000",
            "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": score}}]},
            "configurations": [
                {"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": criteria, **ranges}]}]}
            ],
        }
    }


PHP_ANY = "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"


def test_parse_cve_con_rango_y_version_exacta():
    item = nvd_cve(
        "CVE-2024-4577", PHP_ANY, 9.8, versionStartIncluding="7.0", versionEndExcluding="8.1.29"
    )["cve"]
    entry = parse_cve(item, "php", "php")
    assert entry["id"] == "CVE-2024-4577" and entry["cvss"] == 9.8
    assert entry["ranges"] == [{"versionStartIncluding": "7.0", "versionEndExcluding": "8.1.29"}]
    exact = parse_cve(
        nvd_cve("CVE-X", "cpe:2.3:a:php:php:7.4.3:*:*:*:*:*:*:*", 5)["cve"], "php", "php"
    )
    assert exact["ranges"] == [{"exact": "7.4.3"}]


def test_parse_cve_de_otro_producto_se_ignora():
    item = nvd_cve("CVE-Y", "cpe:2.3:a:otro:producto:*:*:*:*:*:*:*:*", 7)["cve"]
    assert parse_cve(item, "php", "php") is None


def test_cvss_prefiere_la_version_mas_moderna():
    metrics = {
        "cvssMetricV2": [{"type": "Primary", "cvssData": {"baseScore": 5.0}}],
        "cvssMetricV31": [{"type": "Secondary", "cvssData": {"baseScore": 7.5}}],
    }
    assert cvss_score(metrics) == 7.5
    assert cvss_score({}) is None


class FakeNVD:
    """Simula la API 2.0 de NVD con paginación."""

    def __init__(self, per_product):
        self.per_product = per_product
        self.calls = []

    def get(self, url, params, headers, timeout):
        self.calls.append(params)
        items = self.per_product.get(params["virtualMatchString"], [])
        start = params["startIndex"]
        page = items[start : start + 1]  # 1 por página para probar la paginación
        return FakeResp({"resultsPerPage": 1, "totalResults": len(items), "vulnerabilities": page})


class FakeResp:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self):
        pass

    def json(self):
        return self._data


def test_update_database_pagina_respeta_el_limite_y_guarda(tmp_path):
    nvd = FakeNVD(
        {
            "cpe:2.3:a:php:php": [
                nvd_cve("CVE-2024-4577", PHP_ANY, 9.8, versionEndExcluding="8.1.29"),
                nvd_cve("CVE-2021-21703", PHP_ANY, 7.0, versionEndExcluding="7.4.25"),
            ],
        }
    )
    pauses = []
    path = tmp_path / "cve.json"
    db = update_database(path, session=nvd, api_key="", sleep=pauses.append)
    assert [e["id"] for e in db["products"]["php"]] == ["CVE-2021-21703", "CVE-2024-4577"]
    assert all(p == 6.0 for p in pauses)  # sin clave: 6 s entre peticiones
    assert json.loads(path.read_text())["products"]["php"][0]["cvss"] == 7.0


def test_ruta_por_defecto_aislada_en_las_pruebas(tmp_path):
    assert "datos" in str(default_db_path())


# --- Motor -------------------------------------------------------------


DB = CVEDatabase(
    {
        "generated": "2026-11-15",
        "products": {
            "php": [
                {"id": "CVE-2024-4577", "cvss": 9.8, "ranges": [{"versionEndExcluding": "8.1.29"}]},
                {
                    "id": "CVE-2021-21703",
                    "cvss": 7.0,
                    "ranges": [{"versionEndExcluding": "7.4.25"}],
                },
                {"id": "CVE-2099-0001", "cvss": 5.0, "ranges": [{"exact": "8.3.0"}]},
            ],
            "jquery": [
                {
                    "id": "CVE-2020-11022",
                    "cvss": 6.1,
                    "ranges": [{"versionStartIncluding": "1.2", "versionEndExcluding": "3.5.0"}],
                },
            ],
        },
    }
)


def analyze(headers, html=None, db=DB):
    return TechEngine(db=db).analyze(ScanContext("https://e.es/", headers=headers, html=html))


def test_php_antiguo_con_cve_graves():
    found = {f.rule_id: f for f in analyze({"X-Powered-By": "PHP/7.4.3"})}
    assert set(found) == {"TECH_VERSION_DISCLOSED", "TECH_CVE_HIGH"}
    f = found["TECH_CVE_HIGH"]
    assert f.severity is Severity.HIGH and f.category is Category.TECH
    assert "2 CVE posibles" in f.evidence and "9.8" in f.evidence and "CVE-2024-4577" in f.evidence


def test_cve_medio_y_version_sin_cve():
    assert {f.rule_id for f in analyze({}, '<script src="/js/jquery-3.4.1.min.js"></script>')} == {
        "TECH_VERSION_DISCLOSED",
        "TECH_CVE_MEDIUM",
    }
    assert {f.rule_id for f in analyze({"X-Powered-By": "PHP/8.2.0"})} == {"TECH_VERSION_DISCLOSED"}


def test_sin_version_anunciada_no_penaliza():
    assert analyze({"Server": "nginx"}) == []


def test_sin_base_de_cve_avisa(tmp_path):
    engine = TechEngine(db_path=tmp_path / "no-existe.json")
    ctx = ScanContext("https://e.es/", headers={"X-Powered-By": "PHP/7.4.3"})
    assert {f.rule_id for f in engine.analyze(ctx)} == {
        "TECH_VERSION_DISCLOSED",
        "TECH_CVE_DB_MISSING",
    }
