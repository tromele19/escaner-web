"""Sondeo de rutas sensibles — solo en modo completo (RF-06, RNF-08).

Pide al servidor una lista cerrada de rutas (``/.env``, ``/.git/HEAD``...)
para comprobar si están expuestas. Es la única parte de la herramienta que
hace peticiones que un navegador no haría, por eso:

- solo se ejecuta con ``--authorized`` y confirmación expresa (art. 197 bis CP);
- las rutas son una lista fija y pequeña, sin fuerza bruta;
- se deja una pausa entre peticiones para no sobrecargar el servidor;
- nunca se siguen redirecciones ni se sale del origen analizado;
- solo se leen los primeros KB de cada respuesta;
- antes se pide una ruta inventada para detectar servidores que responden 200
  a todo («soft 404») y no confundirlos con ficheros expuestos.
"""

from __future__ import annotations

import secrets
import time
import warnings
from collections.abc import Iterable
from urllib.parse import urlsplit, urlunsplit

import requests
from urllib3.exceptions import InsecureRequestWarning

from escaner.acquisition.fetcher import USER_AGENT, system_ca_bundle

MAX_BYTES = 64 * 1024
DEFAULT_DELAY = 0.3
DEFAULT_TIMEOUT = 8.0
SOFT404_KEY = "__soft404__"


def probe_paths(
    base_url: str,
    paths: Iterable[str],
    *,
    session: requests.Session | None = None,
    delay: float = DEFAULT_DELAY,
    timeout: float = DEFAULT_TIMEOUT,
    verify_tls: bool = True,
) -> dict[str, dict]:
    """Pide cada ruta en el origen de ``base_url`` y devuelve ``{ruta: datos}``.

    ``datos`` = ``{status, content_type, length, body}`` o ``{error}``. El cuerpo
    se trunca a 64 KB y solo se usa para reconocer firmas; nunca se guarda en
    el resultado del escaneo.
    """
    parts = urlsplit(base_url)
    origin = (parts.scheme, parts.netloc)
    own_session = session is None
    session = session or requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    verify = system_ca_bundle() if verify_tls else False

    results: dict[str, dict] = {}
    canary = f"/escaner-{secrets.token_hex(6)}-no-existe"
    try:
        for i, path in enumerate([canary, *paths]):
            if i:
                time.sleep(delay)
            url = urlunsplit((*origin, path, "", ""))
            key = SOFT404_KEY if path == canary else path
            results[key] = _get(session, url, timeout, verify)
    finally:
        if own_session:
            session.close()
    return results


def _get(session, url, timeout, verify) -> dict:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", InsecureRequestWarning)
            resp = session.get(
                url, allow_redirects=False, stream=True, timeout=timeout, verify=verify
            )
    except requests.exceptions.RequestException as exc:
        return {"error": type(exc).__name__}
    try:
        body = b""
        for chunk in resp.iter_content(chunk_size=16 * 1024):
            body += chunk
            if len(body) >= MAX_BYTES:
                body = body[:MAX_BYTES]
                break
    except requests.exceptions.RequestException:
        body = b""
    finally:
        resp.close()
    return {
        "status": resp.status_code,
        "content_type": resp.headers.get("Content-Type", "").split(";")[0].strip().lower(),
        "length": len(body),
        "body": body.decode("utf-8", errors="replace"),
    }
