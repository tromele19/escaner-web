"""Validador de objetivo: normalización de URL y protección anti-SSRF (RF-01).

Toda URL que entra en la herramienta pasa por aquí antes de hacer ninguna
petición. El objetivo es que el escáner no pueda usarse para atacar la red
interna de quien lo ejecuta (SSRF): direcciones locales, privadas, de
metadatos de la nube, etc.

Reglas:
1. Solo se aceptan los esquemas ``http`` y ``https`` (si no se indica, ``https``).
2. No se aceptan credenciales en la URL (``usuario:clave@host``).
3. El host se resuelve por DNS y se comprueban **todas** las direcciones que
   devuelve: si alguna no es pública, se rechaza el objetivo.
4. Las direcciones no públicas solo se permiten con ``allow_private=True``
   (pensado para el laboratorio propio).

Límite conocido: entre esta comprobación y la conexión real el DNS podría
cambiar (DNS rebinding). Por eso el cliente HTTP vuelve a validar el destino
en cada redirección.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

ALLOWED_SCHEMES = frozenset({"http", "https"})
DEFAULT_PORTS = {"http": 80, "https": 443}

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int], list[str]]


class TargetError(ValueError):
    """El objetivo no es válido o no está permitido."""


@dataclass(frozen=True, slots=True)
class Target:
    """Objetivo ya validado y normalizado."""

    url: str
    scheme: str
    host: str
    port: int
    addresses: tuple[str, ...]


def system_resolver(host: str, port: int) -> list[str]:
    """Resuelve un host con el DNS del sistema y devuelve sus direcciones IP."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise TargetError(f"No se puede resolver el host '{host}'.") from exc
    return sorted({info[4][0] for info in infos})


def is_public_address(ip: IPAddress) -> bool:
    """Indica si una dirección IP es pública (enrutable en Internet)."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        # ::ffff:127.0.0.1 es en realidad 127.0.0.1
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def validate_target(
    raw: str,
    *,
    allow_private: bool = False,
    resolver: Resolver = system_resolver,
) -> Target:
    """Valida y normaliza el objetivo introducido por el usuario.

    Lanza ``TargetError`` con un mensaje explicativo si no es válido.
    """
    text = (raw or "").strip()
    if not text:
        raise TargetError("No se ha indicado ninguna URL.")
    if any(ch.isspace() for ch in text):
        raise TargetError("La URL no puede contener espacios.")
    if "://" not in text:
        text = "https://" + text

    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise TargetError(f"Esquema no permitido: '{parts.scheme}'. Solo http o https.")
    if parts.username is not None or parts.password is not None:
        raise TargetError("La URL no puede incluir usuario ni contraseña.")

    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise TargetError("La URL no tiene un host válido.")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetError(f"Nombre de host no válido: '{host}'.") from exc

    try:
        port = parts.port or DEFAULT_PORTS[scheme]
    except ValueError as exc:
        raise TargetError("El puerto indicado no es válido.") from exc

    addresses = _resolve(host, port, resolver)
    if not allow_private:
        blocked = [a for a in addresses if not is_public_address(ipaddress.ip_address(a))]
        if blocked:
            raise TargetError(
                f"El host '{host}' apunta a una dirección no pública ({', '.join(blocked)}). "
                "Solo se permite con la opción de laboratorio."
            )

    netloc = f"[{host}]" if ":" in host else host
    if parts.port is not None and parts.port != DEFAULT_PORTS[scheme]:
        netloc = f"{netloc}:{port}"
    url = urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
    return Target(url=url, scheme=scheme, host=host, port=port, addresses=tuple(addresses))


def _resolve(host: str, port: int, resolver: Resolver) -> list[str]:
    """Devuelve las IP del host (la propia IP si ya es una dirección literal)."""
    try:
        return [str(ipaddress.ip_address(host))]
    except ValueError:
        pass
    addresses = resolver(host, port)
    if not addresses:
        raise TargetError(f"El host '{host}' no tiene direcciones IP.")
    return list(addresses)
