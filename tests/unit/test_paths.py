"""Pruebas del sondeo y del motor de rutas sensibles (RF-06)."""

import pytest

from escaner.acquisition.prober import SOFT404_KEY, probe_paths
from escaner.engines.paths import PathsEngine
from escaner.models import Category, ScanContext, ScanMode, Severity
from escaner.rules.paths import ALL_PATHS

ENV_BODY = "APP_ENV=production\nDB_HOST=127.0.0.1\nDB_USER=admin\nDB_PASSWORD=supersecreta\n"
NOT_FOUND = {"status": 404, "content_type": "text/html", "length": 150, "body": "<h1>404</h1>"}


def resp(body, status=200, ctype="text/plain"):
    return {"status": status, "content_type": ctype, "length": len(body), "body": body}


def analyze(probes, mode=ScanMode.FULL):
    all_probes = {SOFT404_KEY: NOT_FOUND, **{p: NOT_FOUND for p in ALL_PATHS}}
    all_probes.update(probes)
    ctx = ScanContext("https://ejemplo.es/", mode=mode, path_probes=all_probes)
    return PathsEngine().analyze(ctx)


def ids(probes):
    return {f.rule_id for f in analyze(probes)}


# --- Motor ---------------------------------------------------------------


def test_sitio_limpio_solo_avisa_de_security_txt():
    findings = analyze({})
    assert [f.rule_id for f in findings] == ["SECURITY_TXT_MISSING"]
    assert findings[0].category is Category.PATHS


def test_env_expuesto_es_critico_y_no_muestra_valores():
    (f,) = [f for f in analyze({"/.env": resp(ENV_BODY)}) if f.rule_id == "ENV_FILE_EXPOSED"]
    assert f.severity is Severity.CRITICAL
    assert "4 variables" in f.evidence and "DB_PASSWORD" in f.evidence
    assert "supersecreta" not in f.evidence and "127.0.0.1" not in f.evidence


def test_env_que_es_una_pagina_html_no_cuenta():
    html = "<html><body>APP=1</body></html>"
    assert "ENV_FILE_EXPOSED" not in ids({"/.env": resp(html, ctype="text/html")})


def test_git_expuesto():
    assert "GIT_REPO_EXPOSED" in ids({"/.git/HEAD": resp("ref: refs/heads/main\n")})
    assert "GIT_REPO_EXPOSED" in ids({"/.git/config": resp("[core]\n\tbare = false\n")})


def test_git_head_con_otro_contenido_no_cuenta():
    assert "GIT_REPO_EXPOSED" not in ids({"/.git/HEAD": resp("hola")})


def test_copias_de_seguridad_y_listado_de_directorios():
    found = ids(
        {
            "/backup/": resp("<html><title>Index of /backup/</title></html>", ctype="text/html"),
            "/index.html.bak": resp("<html>copia</html>", ctype="application/octet-stream"),
            "/db_backup.sql": resp("-- dump\nCREATE TABLE users;"),
        }
    )
    assert {"DIRECTORY_LISTING", "BACKUP_FILE_EXPOSED"} <= found


@pytest.mark.parametrize(
    "page",
    ["<title>Index of /backup/</title>", "<h1>Directory listing for /backup/</h1>"],
)
def test_listado_de_directorios_nginx_apache_y_python(page):
    assert "DIRECTORY_LISTING" in ids({"/backup/": resp(page, ctype="text/html")})


def test_panel_admin_con_formulario_de_login():
    page = '<form><input name="u"><input type="password" name="p"></form>'
    assert "ADMIN_PANEL_EXPOSED" in ids({"/admin/": resp(page, ctype="text/html")})


def test_panel_admin_sin_login_no_cuenta():
    assert "ADMIN_PANEL_EXPOSED" not in ids({"/admin/": resp("<h1>Hola</h1>", ctype="text/html")})


def test_robots_que_revela_rutas():
    robots = "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /fotos/\n"
    (f,) = [
        f for f in analyze({"/robots.txt": resp(robots)}) if f.rule_id == "ROBOTS_REVEALS_PATHS"
    ]
    assert "/admin/" in f.evidence and "/fotos/" not in f.evidence


def test_security_txt_presente_suma():
    found = ids({"/.well-known/security.txt": resp("Contact: mailto:seguridad@ejemplo.es\n")})
    assert "SECURITY_TXT_PRESENT" in found and "SECURITY_TXT_MISSING" not in found


# --- Servidores que responden 200 a todo (soft 404) ----------------------


def test_soft404_no_genera_falsos_positivos():
    spa = resp("<html>" + "x" * 2000 + "</html>", ctype="text/html")
    probes = {SOFT404_KEY: spa, **{p: spa for p in ALL_PATHS}}
    assert ids(probes) == {"SECURITY_TXT_MISSING"}


def test_soft404_no_oculta_un_env_real():
    spa = resp("<html>" + "x" * 2000 + "</html>", ctype="text/html")
    probes = {SOFT404_KEY: spa, **{p: spa for p in ALL_PATHS}, "/.env": resp(ENV_BODY)}
    assert "ENV_FILE_EXPOSED" in ids(probes)


# --- Modo ----------------------------------------------------------------


def test_solo_en_modo_completo():
    engine = PathsEngine()
    assert not engine.applies_to(ScanContext("https://ejemplo.es/", mode=ScanMode.PASSIVE))
    assert engine.applies_to(ScanContext("https://ejemplo.es/", mode=ScanMode.FULL))


# --- Sondeo --------------------------------------------------------------


class FakeResp:
    def __init__(self, status, body=b"", ctype="text/plain"):
        self.status_code = status
        self.headers = {"Content-Type": ctype}
        self._body = body

    def iter_content(self, chunk_size=1):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i : i + chunk_size]

    def close(self):
        pass


class FakeSession:
    def __init__(self, routes):
        self.routes = routes
        self.headers = {}
        self.calls = []

    def get(self, url, **kw):
        self.calls.append((url, kw))
        return self.routes.get(url, FakeResp(404, b"no"))

    def close(self):
        pass


def test_sondeo_mismo_origen_sin_redirecciones_y_con_canario():
    session = FakeSession({"https://ejemplo.es/.env": FakeResp(200, ENV_BODY.encode())})
    r = probe_paths("https://ejemplo.es/inicio?x=1", ["/.env", "/admin/"], session=session, delay=0)
    urls = [u for u, _ in session.calls]
    assert urls[0].startswith("https://ejemplo.es/escaner-") and urls[0].endswith("-no-existe")
    assert urls[1:] == ["https://ejemplo.es/.env", "https://ejemplo.es/admin/"]
    assert all(kw["allow_redirects"] is False for _, kw in session.calls)
    assert r["/.env"]["status"] == 200 and r[SOFT404_KEY]["status"] == 404


def test_sondeo_limita_el_tamano_leido():
    big = FakeResp(200, b"A" * 200_000)
    session = FakeSession({"https://ejemplo.es/backup.sql": big})
    r = probe_paths("https://ejemplo.es/", ["/backup.sql"], session=session, delay=0)
    assert r["/backup.sql"]["length"] == 64 * 1024


def test_sondeo_respeta_la_pausa(monkeypatch):
    sleeps = []
    monkeypatch.setattr("escaner.acquisition.prober.time.sleep", sleeps.append)
    probe_paths("https://ejemplo.es/", ["/a", "/b"], session=FakeSession({}), delay=0.3)
    assert sleeps == [0.3, 0.3]


@pytest.mark.parametrize("path", ALL_PATHS)
def test_lista_cerrada_de_rutas_relativas_al_origen(path):
    assert path.startswith("/") and "://" not in path and ".." not in path
