"""Cliente TLS de la capa de adquisición (RF-05).

Obtiene del servidor la información que necesita el motor de TLS:
- el certificado (aunque no sea válido), con sus fechas, nombres, emisor,
  tamaño de clave y algoritmo de firma;
- si el certificado es de confianza para el sistema;
- qué versiones de TLS acepta el servidor (1.0, 1.1, 1.2 y 1.3).

Solo hace conexiones TLS normales, como un navegador (modo pasivo). El host
ya ha pasado por el validador anti-SSRF antes de llegar aquí.

Limitación conocida: las pruebas de TLS 1.0/1.1 dependen de que el OpenSSL
local permita negociarlas; si no lo permite, el resultado es «no comprobado»
y no se penaliza.
"""

from __future__ import annotations

import socket
import ssl
import warnings
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import NameOID

DEFAULT_TIMEOUT = 8.0

VERSIONS = {
    "TLSv1.0": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}

# Códigos de OpenSSL que indican que la cadena no es de confianza.
UNTRUSTED_CODES = {18, 19, 20, 21, 24, 27, 28}


class TLSError(Exception):
    """No se ha podido establecer ninguna conexión TLS con el servidor."""


@dataclass(slots=True)
class CertInfo:
    subject_cn: str | None
    issuer_cn: str | None
    issuer_org: str | None
    san_dns: list[str]
    not_before: str  # ISO 8601 UTC
    not_after: str
    self_signed: bool
    key_type: str
    key_bits: int | None
    signature_hash: str | None


@dataclass(slots=True)
class TLSInfo:
    host: str
    port: int
    trusted: bool
    verify_error: str | None = None
    verify_code: int | None = None
    negotiated_version: str | None = None
    cipher: str | None = None
    certificate: CertInfo | None = None
    # True = aceptada, False = rechazada, None = no se ha podido comprobar
    versions: dict[str, bool | None] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def inspect_tls(host: str, port: int = 443, timeout: float = DEFAULT_TIMEOUT) -> TLSInfo:
    """Conecta por TLS a ``host:port`` y devuelve la información del servidor."""
    info = TLSInfo(host=host, port=port, trusted=False)

    # 1) Conexión verificada, como la haría un navegador.
    der = None
    try:
        der, version, cipher = _handshake(host, port, timeout, verify=True)
        info.trusted = True
    except ssl.SSLCertVerificationError as exc:
        info.verify_code = exc.verify_code
        info.verify_error = exc.verify_message
    except (ssl.SSLError, OSError) as exc:
        raise TLSError(
            f"No se ha podido establecer una conexión TLS con {host}:{port}: {exc}"
        ) from exc

    # 2) Si el certificado no es válido, se obtiene igualmente para analizarlo.
    if der is None:
        try:
            der, version, cipher = _handshake(host, port, timeout, verify=False)
        except (ssl.SSLError, OSError) as exc:
            raise TLSError(f"No se ha podido leer el certificado de {host}:{port}: {exc}") from exc

    info.negotiated_version = version
    info.cipher = cipher
    info.certificate = parse_certificate(der) if der else None
    info.versions = {name: _accepts(host, port, v, timeout) for name, v in VERSIONS.items()}
    return info


def _handshake(host, port, timeout, verify: bool):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(binary_form=True), tls.version(), tls.cipher()[0]


def _accepts(host: str, port: int, version: ssl.TLSVersion, timeout: float) -> bool | None:
    """Indica si el servidor acepta una versión concreta de TLS."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():
            # Python avisa de que TLS 1.0/1.1 están obsoletos: es justo lo que se comprueba.
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = version
            ctx.maximum_version = version
        if version < ssl.TLSVersion.TLSv1_2:
            # Las versiones antiguas están desactivadas por defecto en OpenSSL 3:
            # se baja el nivel de seguridad SOLO para preguntar al servidor.
            ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None  # el OpenSSL local no permite probar esta versión
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except ssl.SSLError as exc:
        reason = (exc.reason or "").upper()
        if "NO_PROTOCOLS_AVAILABLE" in reason or "NO_CIPHERS_AVAILABLE" in reason:
            return None  # limitación local, no del servidor
        return False
    except OSError:
        return False


def parse_certificate(der: bytes) -> CertInfo:
    """Extrae del certificado los datos que evalúa el motor de TLS."""
    cert = x509.load_der_x509_certificate(der)

    def attr(name, oid):
        values = name.get_attributes_for_oid(oid)
        return str(values[0].value) if values else None

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_dns = [n.lower() for n in san.value.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        san_dns = []

    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_type, bits = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_type, bits = "EC", key.key_size
    elif isinstance(key, dsa.DSAPublicKey):
        key_type, bits = "DSA", key.key_size
    else:
        key_type, bits = type(key).__name__.replace("PublicKey", ""), None

    hash_alg = cert.signature_hash_algorithm
    return CertInfo(
        subject_cn=attr(cert.subject, NameOID.COMMON_NAME),
        issuer_cn=attr(cert.issuer, NameOID.COMMON_NAME),
        issuer_org=attr(cert.issuer, NameOID.ORGANIZATION_NAME),
        san_dns=san_dns,
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=cert.not_valid_after_utc.isoformat(),
        self_signed=cert.issuer == cert.subject,
        key_type=key_type,
        key_bits=bits,
        signature_hash=hash_alg.name if hash_alg else None,
    )


def hostname_matches(host: str, names: list[str]) -> bool:
    """Comprueba si ``host`` coincide con algún nombre del certificado (RFC 6125).

    El comodín solo cubre una etiqueta y solo en la primera posición:
    ``*.ejemplo.es`` vale para ``www.ejemplo.es`` pero no para ``ejemplo.es``
    ni para ``a.b.ejemplo.es``.
    """
    host = host.lower().rstrip(".")
    for name in names:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and "." in host:
            label, _, rest = host.partition(".")
            if label and rest == name[2:]:
                return True
    return False


def now_utc() -> datetime:
    return datetime.now(UTC)
