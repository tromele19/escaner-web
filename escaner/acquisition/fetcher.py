"""Cliente HTTP de la capa de adquisición (RF-02, RNF-02, RNF-08).

Descarga la URL objetivo con las mismas peticiones que haría un navegador y
devuelve lo que necesitan los motores: cadena de redirecciones, cabeceras,
cookies y HTML.

Decisiones de seguridad:
- Las redirecciones se siguen **a mano**: cada salto se vuelve a pasar por el
  validador anti-SSRF, para que un sitio no pueda redirigir al escáner hacia
  la red interna (p. ej. ``Location: http://169.254.169.254/``).
- Límite de saltos (10 por defecto) y detección de bucles.
- Tiempo máximo por petición y tamaño máximo de respuesta (5 MB): un servidor
  lento o malicioso no puede bloquear ni llenar la memoria de la herramienta.
- User-Agent propio que identifica la herramienta (uso responsable).
- Si el certificado no es válido se repite la petición sin verificarlo para
  poder analizar igualmente cabeceras y cookies; el fallo queda marcado en
  ``tls_verified`` y lo evalúa el motor de TLS.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field
from urllib.parse import urljoin

import requests
from urllib3.exceptions import InsecureRequestWarning

from escaner import __version__
from escaner.validator import Resolver, Target, TargetError, system_resolver, validate_target

USER_AGENT = f"escaner-web/{__version__} (escaner de configuracion; uso autorizado)"
DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_REDIRECTS = 10
DEFAULT_MAX_BYTES = 5 * 1024 * 1024
HTML_TYPES = ("text/html", "application/xhtml+xml")


class FetchError(Exception):
    """No se ha podido obtener la respuesta del objetivo."""


@dataclass(frozen=True, slots=True)
class Hop:
    """Un salto de la cadena de redirecciones."""

    url: str
    status_code: int
    location: str | None = None


@dataclass(slots=True)
class FetchResult:
    """Datos obtenidos de la URL objetivo."""

    requested_url: str
    final_url: str
    status_code: int
    headers: dict[str, str]
    set_cookies: list[str] = field(default_factory=list)
    redirect_chain: list[Hop] = field(default_factory=list)
    html: str | None = None
    truncated: bool = False
    tls_verified: bool = True


def fetch(
    target: Target,
    *,
    allow_private: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    max_bytes: int = DEFAULT_MAX_BYTES,
    session: requests.Session | None = None,
    resolver: Resolver = system_resolver,
) -> FetchResult:
    """Descarga ``target`` siguiendo redirecciones de forma segura."""
    own_session = session is None
    session = session or requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.8"})

    chain: list[Hop] = []
    set_cookies: list[str] = []
    seen: set[str] = set()
    url = target.url
    tls_verified = True

    try:
        while True:
            if url in seen:
                raise FetchError(f"Bucle de redirecciones detectado en {url}.")
            seen.add(url)

            response, verified = _get(session, url, timeout)
            tls_verified = tls_verified and verified
            set_cookies.extend(_raw_set_cookies(response))
            location = response.headers.get("Location")

            if response.is_redirect and location:
                response.close()
                chain.append(Hop(url, response.status_code, location))
                if len(chain) > max_redirects:
                    raise FetchError(f"Demasiadas redirecciones (máximo {max_redirects}).")
                next_url = urljoin(url, location)
                try:
                    url = validate_target(
                        next_url, allow_private=allow_private, resolver=resolver
                    ).url
                except TargetError as exc:
                    raise FetchError(f"Redirección bloqueada hacia {next_url}: {exc}") from exc
                continue

            body, truncated = _read_limited(response, max_bytes)
            content_type = response.headers.get("Content-Type", "").lower()
            html = _decode(body, response) if content_type.startswith(HTML_TYPES) else None
            return FetchResult(
                requested_url=target.url,
                final_url=url,
                status_code=response.status_code,
                headers=dict(response.headers),
                set_cookies=set_cookies,
                redirect_chain=chain,
                html=html,
                truncated=truncated,
                tls_verified=tls_verified,
            )
    finally:
        if own_session:
            session.close()


def _get(session: requests.Session, url: str, timeout: float) -> tuple[requests.Response, bool]:
    """Hace la petición; si falla el certificado, la repite sin verificarlo."""
    kwargs = {"allow_redirects": False, "stream": True, "timeout": timeout}
    try:
        return session.get(url, verify=True, **kwargs), True
    except requests.exceptions.SSLError:
        pass
    except requests.exceptions.Timeout as exc:
        raise FetchError(f"Tiempo de espera agotado ({timeout:g} s) en {url}.") from exc
    except requests.exceptions.RequestException as exc:
        raise FetchError(f"No se ha podido conectar con {url}: {exc}") from exc

    # Certificado no válido: se repite sin verificar SOLO para poder leer las
    # cabeceras. No se envían datos del usuario y el fallo queda registrado.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", InsecureRequestWarning)
        try:
            return session.get(url, verify=False, **kwargs), False
        except requests.exceptions.RequestException as exc:
            raise FetchError(f"No se ha podido conectar con {url}: {exc}") from exc


def _raw_set_cookies(response: requests.Response) -> list[str]:
    """Devuelve cada cabecera ``Set-Cookie`` por separado.

    ``response.headers`` junta todas en una sola cadena separada por comas, lo
    que rompe las cookies con fecha (``Expires=Wed, 21 Oct ...``).
    """
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        return list(raw_headers.getlist("Set-Cookie"))
    value = response.headers.get("Set-Cookie")
    return [value] if value else []


def _read_limited(response: requests.Response, max_bytes: int) -> tuple[bytes, bool]:
    """Lee el cuerpo hasta ``max_bytes``; indica si se ha cortado."""
    chunks: list[bytes] = []
    total = 0
    try:
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            remaining = max_bytes - total
            if len(chunk) > remaining:
                chunks.append(chunk[:remaining])
                return b"".join(chunks), True
            chunks.append(chunk)
            total += len(chunk)
    except requests.exceptions.RequestException as exc:
        raise FetchError(f"Error leyendo la respuesta: {exc}") from exc
    finally:
        response.close()
    return b"".join(chunks), False


def _decode(body: bytes, response: requests.Response) -> str:
    """Decodifica el HTML con el charset de la cabecera o, si no lo hay, UTF-8.

    No se usa ``response.encoding`` porque ``requests`` asume ISO-8859-1 cuando
    ``text/html`` no indica charset, y casi todas las webs actuales son UTF-8.
    """
    encoding = "utf-8"
    for param in response.headers.get("Content-Type", "").split(";")[1:]:
        name, _, value = param.strip().partition("=")
        if name.lower() == "charset" and value:
            encoding = value.strip("\"' ")
    try:
        return body.decode(encoding, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")
