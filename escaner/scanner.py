"""Orquestador del escaneo (capa de orquestación).

Une las fases del diagrama de flujo de la memoria (figura 1):
validación del objetivo → adquisición → motores de análisis → puntuación.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from escaner.acquisition.fetcher import FetchResult, fetch
from escaner.engines.base import Engine
from escaner.engines.cookies import CookiesEngine
from escaner.engines.headers import HeadersEngine
from escaner.models import ScanContext, ScanMode, ScanResult
from escaner.scoring import score_result
from escaner.validator import Resolver, Target, system_resolver, validate_target

Fetcher = Callable[..., FetchResult]


def default_engines() -> list[Engine]:
    """Motores disponibles. Se irán añadiendo TLS, rutas, contenido y tecnologías."""
    return [HeadersEngine(), CookiesEngine()]


def run_scan(
    url: str,
    *,
    mode: ScanMode = ScanMode.PASSIVE,
    allow_private: bool = False,
    engines: Sequence[Engine] | None = None,
    fetcher: Fetcher = fetch,
    resolver: Resolver = system_resolver,
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
        tls_info={"verified": response.tls_verified},
    )

    result = ScanResult(context=context)
    for engine in engines if engines is not None else default_engines():
        if not engine.applies_to(context) or not engine.is_evaluable(context):
            continue
        result.evaluated_categories.add(engine.category)
        result.findings.extend(engine.analyze(context))
    return score_result(result)
