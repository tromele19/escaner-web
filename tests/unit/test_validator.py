"""Pruebas del validador de objetivo (RF-01).

Se usa un resolvedor DNS falso para que las pruebas no dependan de la red.
"""

import pytest

from escaner.validator import TargetError, validate_target

FAKE_DNS = {
    "ejemplo.es": ["93.184.216.34"],
    "interno.ejemplo.es": ["10.0.0.5"],
    "mixto.ejemplo.es": ["93.184.216.34", "192.168.1.10"],
    "localhost": ["127.0.0.1", "::1"],
    "xn--espaa-rta.es": ["93.184.216.35"],
}


def fake_resolver(host, port):
    if host not in FAKE_DNS:
        raise TargetError(f"No se puede resolver el host '{host}'.")
    return FAKE_DNS[host]


def check(raw, **kwargs):
    return validate_target(raw, resolver=fake_resolver, **kwargs)


# --- Casos válidos --------------------------------------------------------


def test_url_completa_valida():
    t = check("https://ejemplo.es/ruta?x=1")
    assert t.url == "https://ejemplo.es/ruta?x=1"
    assert t.host == "ejemplo.es"
    assert t.port == 443
    assert t.addresses == ("93.184.216.34",)


def test_sin_esquema_se_asume_https():
    assert check("ejemplo.es").url == "https://ejemplo.es/"


def test_normaliza_mayusculas_y_quita_fragmento():
    assert check("HTTPS://EJEMPLO.ES/#seccion").url == "https://ejemplo.es/"


def test_http_con_puerto_no_estandar():
    t = check("http://ejemplo.es:8080/")
    assert t.port == 8080
    assert t.url == "http://ejemplo.es:8080/"


def test_puerto_por_defecto_no_se_repite():
    assert check("https://ejemplo.es:443/").url == "https://ejemplo.es/"


def test_dominio_internacional_se_convierte_a_idna():
    assert check("https://españa.es").host == "xn--espaa-rta.es"


def test_ip_publica_literal():
    assert check("http://93.184.216.34/").addresses == ("93.184.216.34",)


# --- Entradas mal formadas -----------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "ftp://ejemplo.es",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "https://",
        "https://ejemplo .es",
        "https://ejemplo.es:99999/",
    ],
)
def test_rechaza_entradas_no_validas(raw):
    with pytest.raises(TargetError):
        check(raw)


def test_rechaza_credenciales_en_la_url():
    with pytest.raises(TargetError, match="usuario"):
        check("https://admin:clave@ejemplo.es/")


def test_rechaza_host_que_no_resuelve():
    with pytest.raises(TargetError, match="resolver"):
        check("https://no-existe.invalid/")


# --- Protección anti-SSRF ------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://10.1.2.3/",
        "http://172.16.0.1/",
        "http://192.168.1.1/",
        "http://169.254.169.254/latest/meta-data/",  # metadatos de la nube
        "http://100.64.0.1/",  # CGNAT
        "http://0.0.0.0/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",  # IPv4 camuflada en IPv6
        "http://[fe80::1]/",
        "http://[fc00::1]/",
        "http://224.0.0.1/",  # multicast
        "https://interno.ejemplo.es/",  # dominio público que apunta a IP privada
    ],
)
def test_bloquea_direcciones_no_publicas(raw):
    with pytest.raises(TargetError, match="no pública"):
        check(raw)


def test_bloquea_si_alguna_ip_es_privada():
    with pytest.raises(TargetError, match="192.168.1.10"):
        check("https://mixto.ejemplo.es/")


def test_modo_laboratorio_permite_direcciones_privadas():
    t = check("http://localhost/", allow_private=True)
    assert t.addresses == ("127.0.0.1", "::1")
