"""Pruebas del motor de cabeceras (RF-03).

Para cada regla: caso correcto, cabecera ausente y cabecera mal configurada.
"""

import pytest

from escaner.engines.headers import HeadersEngine, parse_csp
from escaner.models import Category, ScanContext, Severity
from escaner.rules import RULES

GOOD = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def analyze(headers, url="https://ejemplo.es/"):
    ctx = ScanContext(target_url=url, final_url=url, headers=headers)
    return HeadersEngine().analyze(ctx)


def ids(headers, url="https://ejemplo.es/"):
    return {f.rule_id for f in analyze(headers, url)}


def with_(**changes):
    """Copia de GOOD cambiando cabeceras (None = quitarla)."""
    h = dict(GOOD)
    for name, value in changes.items():
        name = name.replace("_", "-")
        if value is None:
            h.pop(name, None)
        else:
            h[name] = value
    return h


# --- Configuración correcta ----------------------------------------------


def test_configuracion_correcta_solo_da_buenas_practicas():
    findings = analyze(GOOD)
    assert {f.rule_id for f in findings} == {"HSTS_PRELOAD", "CSP_FRAME_ANCESTORS", "COOP_PRESENT"}
    assert all(f.severity is Severity.INFO and f.bonus > 0 for f in findings)
    assert all(f.category is Category.HEADERS for f in findings)


def test_nombres_de_cabecera_sin_distinguir_mayusculas():
    assert ids({k.lower(): v for k, v in GOOD.items()}) == ids(GOOD)


def test_sitio_sin_ninguna_cabecera():
    assert ids({}) == {
        "HSTS_MISSING",
        "CSP_MISSING",
        "XFO_MISSING",
        "XCTO_MISSING",
        "REFERRER_POLICY_MISSING",
        "PERMISSIONS_POLICY_MISSING",
    }


# --- HSTS ----------------------------------------------------------------


def test_hsts_ausente_es_alta():
    (f,) = [
        f for f in analyze(with_(Strict_Transport_Security=None)) if f.rule_id.startswith("HSTS")
    ]
    assert f.rule_id == "HSTS_MISSING"
    assert f.severity is Severity.HIGH


def test_hsts_max_age_corto():
    assert "HSTS_SHORT_MAX_AGE" in ids(with_(Strict_Transport_Security="max-age=300"))


def test_hsts_max_age_no_numerico():
    assert "HSTS_INVALID" in ids(with_(Strict_Transport_Security="max-age=mucho"))


def test_hsts_max_age_entre_comillas_es_valido():
    found = ids(with_(Strict_Transport_Security='max-age="31536000"; includeSubDomains'))
    assert not found & {"HSTS_INVALID", "HSTS_SHORT_MAX_AGE", "HSTS_NO_SUBDOMAINS"}


def test_hsts_sin_subdominios():
    assert "HSTS_NO_SUBDOMAINS" in ids(with_(Strict_Transport_Security="max-age=31536000"))


def test_hsts_por_http_no_cuenta_y_no_se_pide():
    found = ids(GOOD, url="http://ejemplo.es/")
    assert "HSTS_OVER_HTTP" in found
    assert "HSTS_MISSING" not in found and "HSTS_PRELOAD" not in found


def test_sitio_http_sin_hsts_no_penaliza_hsts():
    assert not {i for i in ids({}, url="http://ejemplo.es/") if i.startswith("HSTS")}


# --- CSP -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("csp", "expected"),
    [
        ("default-src 'self' 'unsafe-inline'", "CSP_UNSAFE_INLINE"),
        ("script-src 'self' 'unsafe-eval'", "CSP_UNSAFE_EVAL"),
        ("script-src *", "CSP_WILDCARD_SOURCE"),
        ("script-src https:", "CSP_WILDCARD_SOURCE"),
        ("script-src 'self' data:", "CSP_DATA_SCRIPTS"),
        ("img-src 'self'", "CSP_NO_SCRIPT_SRC"),
    ],
)
def test_csp_insegura(csp, expected):
    assert expected in ids(with_(Content_Security_Policy=csp))


def test_csp_script_src_tiene_prioridad_sobre_default_src():
    found = ids(with_(Content_Security_Policy="default-src * 'unsafe-inline'; script-src 'self'"))
    assert not found & {"CSP_UNSAFE_INLINE", "CSP_WILDCARD_SOURCE"}


def test_csp_unsafe_inline_con_nonce_no_penaliza():
    csp = "script-src 'self' 'nonce-abc123' 'unsafe-inline'"
    assert "CSP_UNSAFE_INLINE" not in ids(with_(Content_Security_Policy=csp))


def test_csp_solo_report_only():
    h = with_(
        Content_Security_Policy=None, Content_Security_Policy_Report_Only="default-src 'self'"
    )
    found = ids(h)
    assert "CSP_REPORT_ONLY" in found and "CSP_MISSING" not in found


def test_parse_csp_primera_directiva_gana():
    assert parse_csp("script-src 'self'; script-src *")["script-src"] == ["'self'"]


# --- X-Frame-Options -----------------------------------------------------


def test_frame_ancestors_sustituye_a_x_frame_options():
    assert "XFO_MISSING" not in ids(GOOD)


def test_sin_frame_ancestors_ni_xfo():
    h = with_(Content_Security_Policy="default-src 'self'")
    assert "XFO_MISSING" in ids(h)


@pytest.mark.parametrize("value", ["DENY", "sameorigin"])
def test_xfo_valido(value):
    h = with_(Content_Security_Policy="default-src 'self'", X_Frame_Options=value)
    assert not ids(h) & {"XFO_MISSING", "XFO_INVALID"}


def test_xfo_allow_from_obsoleto_es_invalido():
    h = with_(
        Content_Security_Policy="default-src 'self'", X_Frame_Options="ALLOW-FROM https://a.es"
    )
    assert "XFO_INVALID" in ids(h)


# --- Otras ---------------------------------------------------------------


def test_xcto_ausente_e_invalido():
    assert "XCTO_MISSING" in ids(with_(X_Content_Type_Options=None))
    assert "XCTO_INVALID" in ids(with_(X_Content_Type_Options="sniff"))


def test_referrer_policy_unsafe_url():
    assert "REFERRER_POLICY_UNSAFE" in ids(with_(Referrer_Policy="unsafe-url"))


def test_referrer_policy_varias_valores_usa_el_ultimo():
    assert "REFERRER_POLICY_UNSAFE" not in ids(with_(Referrer_Policy="unsafe-url, no-referrer"))


def test_x_xss_protection_activada_y_desactivada():
    assert "XXSS_ENABLED" in ids(with_(X_XSS_Protection="1; mode=block"))
    found = ids(with_(X_XSS_Protection="0"))
    assert "XXSS_ENABLED" not in found and "OBSOLETE_HEADER" in found


def test_cabeceras_de_aislamiento_suman():
    h = with_(Cross_Origin_Resource_Policy="same-site", Cross_Origin_Embedder_Policy="require-corp")
    assert {"COOP_PRESENT", "CORP_PRESENT", "COEP_PRESENT"} <= ids(h)


# --- Catálogo ------------------------------------------------------------


def test_evidencia_se_recorta():
    long_csp = "script-src " + " ".join(f"https://cdn{i}.ejemplo.es" for i in range(50)) + " *"
    f = next(f for f in analyze(with_(Content_Security_Policy=long_csp)))
    assert len(f.evidence) <= 120


def test_todas_las_reglas_de_cabeceras_estan_en_el_catalogo():
    header_rules = {r for r, rule in RULES.items() if rule.category is Category.HEADERS}
    assert len(header_rules) == 26
