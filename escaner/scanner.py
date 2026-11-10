"""Orquestador del escaneo (capa de orquestación).

Une las fases del diagrama de flujo de la memoria (figura 1):
validación del objetivo → adquisición → motores de análisis → puntuación.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from urllib.parse import urlsplit

from escaner.acquisition.fetcher import FetchError, FetchResult, fetch
from escaner.acquisition.prober import probe_paths
from escaner.acquisition.tls_client import TLSError, TLSInfo, inspect_tls
from escaner.engines.base import Engine
from escaner.engines.content import ContentEngine
from escaner.engines.cookies import CookiesEngine
from escaner.engines.headers import HeadersEngine
from escaner.engines.paths import PathsEngine
from escaner.engines.tls import TLSEngine
from escaner.models import ScanContext, ScanMode, ScanResult
from escaner.rules.paths import ALL_PATHS
from escaner.scoring import score_result
from escaner.validator import Resolver, Target, system_resolver, validate_target

Fetcher = Callable[..., FetchResult]
TLSInspector = Callable[[str, int], TLSInfo]
Prober = Callable[..., dict]


def default_engines() -> list[Engine]:
    """Motores disponibles. Falta el de tecnologías y CVE."""
    return [TLSEngine(), HeadersEngine(), CookiesEngine(), PathsEngine(), ContentEngine()]


def run_scan(
    url: str,
    *,
    mode: ScanMode = ScanMode.PASSIVE,
    allow_private: bool = False,
    engines: Sequence[Engine] | None = None,
    fetcher: Fetcher = fetch,
    resolver: Resolver = system_resolver,
    tls_inspector: TLSInspector = inspect_tls,
    prober: Prober = probe_paths,
) -> ScanResult:
    """Ejecuta un escaneo completo y devuelve el resultado ya puntuado.

    Lanza ``TargetError`` si el objetivo no es válido y ``FetchError`` si no
    se ha podido obtener la respuesta.
    """
    target: Target = validate_target(url, allow_private=allow_private, resolver=resolver)
    response = fetcher(target, allow_private=allow_private, resolver=resolver)

    context = ScanContext(
        target_url=target.url,
        mode=mode,
        final_url=response.final_url,
        status_code=response.status_code,
        redirect_chain=[hop.url for hop in response.redirect_chain],
        headers=response.headers,
        raw_set_cookies=response.set_cookies,
        html=response.html,
        tls_info=collect_tls_info(
            target, response, allow_private, fetcher, resolver, tls_inspector
        ),
    )

    if mode is ScanMode.FULL:
        # Solo en modo completo (con autorización confirmada): rutas sensibles
        # en el mismo origen que la URL final, que ya ha pasado el validador.
        context.path_probes = prober(
            response.final_url, ALL_PATHS, verify_tls=response.tls_verified
        )

    result = ScanResult(context=context)
    for engine in engines if engines is not None else default_engines():
        if not engine.applies_to(context) or not engine.is_evaluable(context):
            continue
        result.evaluated_categories.add(engine.category)
        result.findings.extend(engine.analyze(context))
    return score_result(result)


def collect_tls_info(
    target: Target,
    response: FetchResult,
    allow_private: bool,
    fetcher: Fetcher,
    resolver: Resolver,
    tls_inspector: TLSInspector,
) -> dict:
    """Reúne lo que necesita el motor de TLS (solo peticiones normales, modo pasivo)."""
    final = urlsplit(response.final_url)
    info: dict = {"verified": response.tls_verified}

    # Se inspecciona el host final si es HTTPS (p. ej. tras redirigir a www.);
    # si no, el host original en el puerto 443.
    if final.scheme == "https":
        host, port = final.hostname or target.host, final.port or 443
    else:
        host, port = target.host, 443
    try:
        info["server"] = tls_inspector(host, port).to_dict()
        info["https_available"] = True
    except TLSError as exc:
        info["https_available"] = False
        info["error"] = str(exc)[:200]
        return info

    if target.scheme == "http":
        # El usuario pidió la versión HTTP: basta con ver adónde acabó.
        info["http_redirects_to_https"] = final.scheme == "https"
    else:
        info["final_url_https"] = final.scheme == "https"
        # Se comprueba si la versión HTTP redirige a HTTPS (una petición más).
        try:
            http_target = validate_target(
                f"http://{target.host}/", allow_private=allow_private, resolver=resolver
            )
            http_resp = fetcher(http_target, allow_private=allow_private, resolver=resolver)
            info["http_redirects_to_https"] = http_resp.final_url.startswith("https://")
        except (FetchError, ValueError):
            info["http_redirects_to_https"] = None  # sin puerto 80 o no comprobable
    return info
