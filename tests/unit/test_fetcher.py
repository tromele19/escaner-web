"""Pruebas del cliente HTTP (RF-02, RNF-02).

No se hace ninguna petición real: ``FakeSession`` simula un servidor web con
respuestas programadas por URL, y el DNS también es falso.
"""

import pytest
import requests
from requests.structures import CaseInsensitiveDict
from urllib3._collections import HTTPHeaderDict

from escaner.acquisition.fetcher import USER_AGENT, FetchError, fetch
from escaner.validator import TargetError, validate_target

FAKE_DNS = {
    "ejemplo.es": ["93.184.216.34"],
    "otro.es": ["93.184.216.35"],
    "interno.es": ["10.0.0.5"],
}


def fake_resolver(host, port):
    if host not in FAKE_DNS:
        raise TargetError(f"No se puede resolver el host '{host}'.")
    return FAKE_DNS[host]


class FakeRaw:
    def __init__(self, headers):
        self.headers = headers


class FakeResponse:
    def __init__(self, status=200, headers=None, body=b"", set_cookies=()):
        raw = HTTPHeaderDict()
        for k, v in (headers or {}).items():
            raw.add(k, v)
        for c in set_cookies:
            raw.add("Set-Cookie", c)
        self.status_code = status
        self.headers = CaseInsensitiveDict(
            {k: ", ".join(raw.getlist(k)) for k in raw.keys()}  # como hace requests
        )
        self.raw = FakeRaw(raw)
        self._body = body
        self.closed = False

    @property
    def is_redirect(self):
        return "location" in self.headers and self.status_code in (301, 302, 303, 307, 308)

    def iter_content(self, chunk_size=1):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i : i + chunk_size]

    def close(self):
        self.closed = True


class FakeSession:
    """Sesión que responde según un diccionario ``url -> FakeResponse``."""

    def __init__(self, routes, ssl_error_urls=()):
        self.routes = routes
        self.ssl_error_urls = set(ssl_error_urls)
        self.headers = {}
        self.calls = []

    def get(self, url, verify=True, **kwargs):
        self.calls.append((url, verify, kwargs))
        assert kwargs["allow_redirects"] is False  # las redirecciones las sigue el escáner
        assert kwargs["timeout"] > 0
        if url in self.ssl_error_urls and verify:
            raise requests.exceptions.SSLError("certificado caducado")
        if url not in self.routes:
            raise requests.exceptions.ConnectionError("no hay ruta")
        result = self.routes[url]
        if isinstance(result, Exception):
            raise result
        return result

    def close(self):
        pass


def run(url, routes, **kwargs):
    session = kwargs.pop("session", None) or FakeSession(routes)
    target = validate_target(url, resolver=fake_resolver)
    return fetch(target, session=session, resolver=fake_resolver, **kwargs), session


HTML = {"Content-Type": "text/html; charset=utf-8"}


# --- Respuesta simple ----------------------------------------------------


def test_respuesta_directa_con_html_y_cabeceras():
    routes = {
        "https://ejemplo.es/": FakeResponse(
            200, {**HTML, "Strict-Transport-Security": "max-age=31536000"}, b"<h1>Hola</h1>"
        )
    }
    r, session = run("https://ejemplo.es", routes)
    assert r.status_code == 200
    assert r.final_url == "https://ejemplo.es/"
    assert r.headers["Strict-Transport-Security"] == "max-age=31536000"
    assert r.html == "<h1>Hola</h1>"
    assert r.redirect_chain == []
    assert r.tls_verified is True
    assert session.headers["User-Agent"] == USER_AGENT


def test_html_sin_charset_se_decodifica_como_utf8():
    routes = {
        "https://ejemplo.es/": FakeResponse(200, {"Content-Type": "text/html"}, "año".encode())
    }
    r, _ = run("https://ejemplo.es", routes)
    assert r.html == "año"


def test_contenido_no_html_no_se_guarda():
    routes = {"https://ejemplo.es/": FakeResponse(200, {"Content-Type": "application/json"}, b"{}")}
    r, _ = run("https://ejemplo.es", routes)
    assert r.html is None


# --- Cookies -------------------------------------------------------------


def test_set_cookie_se_conservan_por_separado():
    cookies = [
        "sid=abc; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure; HttpOnly",
        "tema=oscuro; Path=/",
    ]
    routes = {"https://ejemplo.es/": FakeResponse(200, HTML, b"", set_cookies=cookies)}
    r, _ = run("https://ejemplo.es", routes)
    assert r.set_cookies == cookies


def test_cookies_de_las_redirecciones_tambien_se_recogen():
    routes = {
        "http://ejemplo.es/": FakeResponse(
            301, {"Location": "https://ejemplo.es/"}, set_cookies=["a=1"]
        ),
        "https://ejemplo.es/": FakeResponse(200, HTML, b"", set_cookies=["b=2"]),
    }
    r, _ = run("http://ejemplo.es", routes)
    assert r.set_cookies == ["a=1", "b=2"]


# --- Redirecciones -------------------------------------------------------


def test_sigue_redireccion_http_a_https():
    routes = {
        "http://ejemplo.es/": FakeResponse(301, {"Location": "https://ejemplo.es/"}),
        "https://ejemplo.es/": FakeResponse(200, HTML, b"ok"),
    }
    r, _ = run("http://ejemplo.es", routes)
    assert r.final_url == "https://ejemplo.es/"
    assert [(h.url, h.status_code) for h in r.redirect_chain] == [("http://ejemplo.es/", 301)]


def test_redireccion_relativa():
    routes = {
        "https://ejemplo.es/": FakeResponse(302, {"Location": "/inicio"}),
        "https://ejemplo.es/inicio": FakeResponse(200, HTML, b"ok"),
    }
    r, _ = run("https://ejemplo.es", routes)
    assert r.final_url == "https://ejemplo.es/inicio"


def test_redireccion_a_otro_dominio_publico():
    routes = {
        "https://ejemplo.es/": FakeResponse(302, {"Location": "https://otro.es/"}),
        "https://otro.es/": FakeResponse(200, HTML, b"ok"),
    }
    r, _ = run("https://ejemplo.es", routes)
    assert r.final_url == "https://otro.es/"


@pytest.mark.parametrize(
    "location",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1/admin",
        "https://interno.es/",
        "file:///etc/passwd",
    ],
)
def test_redireccion_hacia_red_interna_se_bloquea(location):
    routes = {"https://ejemplo.es/": FakeResponse(302, {"Location": location})}
    with pytest.raises(FetchError, match="Redirección bloqueada"):
        run("https://ejemplo.es", routes)


def test_detecta_bucle_de_redirecciones():
    routes = {
        "https://ejemplo.es/a": FakeResponse(302, {"Location": "/b"}),
        "https://ejemplo.es/b": FakeResponse(302, {"Location": "/a"}),
    }
    with pytest.raises(FetchError, match="Bucle"):
        run("https://ejemplo.es/a", routes)


def test_limite_de_redirecciones():
    routes = {
        f"https://ejemplo.es/{i}": FakeResponse(302, {"Location": f"/{i + 1}"}) for i in range(20)
    }
    with pytest.raises(FetchError, match="Demasiadas"):
        run("https://ejemplo.es/0", routes, max_redirects=3)


# --- Límites y errores ---------------------------------------------------


def test_respuesta_demasiado_grande_se_corta():
    routes = {"https://ejemplo.es/": FakeResponse(200, HTML, b"x" * 1000)}
    r, _ = run("https://ejemplo.es", routes, max_bytes=100)
    assert r.truncated is True
    assert len(r.html) == 100


def test_timeout_da_error_claro():
    routes = {"https://ejemplo.es/": requests.exceptions.ReadTimeout()}
    with pytest.raises(FetchError, match="Tiempo de espera"):
        run("https://ejemplo.es", routes, timeout=2)


def test_error_de_conexion():
    with pytest.raises(FetchError, match="No se ha podido conectar"):
        run("https://ejemplo.es", {})


def test_certificado_no_valido_se_reintenta_y_se_marca():
    routes = {"https://ejemplo.es/": FakeResponse(200, HTML, b"ok")}
    session = FakeSession(routes, ssl_error_urls={"https://ejemplo.es/"})
    r, _ = run("https://ejemplo.es", routes, session=session)
    assert r.tls_verified is False
    assert [verify for _, verify, _ in session.calls] == [True, False]
