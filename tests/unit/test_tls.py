"""Pruebas del cliente y del motor de TLS (RF-05)."""

import datetime as dt
import ssl
import threading
from dataclasses import asdict

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from escaner.acquisition.tls_client import (
    TLSError,
    hostname_matches,
    inspect_tls,
    parse_certificate,
)
from escaner.engines.tls import TLSEngine
from escaner.models import Category, ScanContext, Severity
from tests.unit.tls_fakes import good_tls

NOW = dt.datetime.now(dt.UTC)


def analyze(server=None, **info):
    tls_info = {"https_available": True, "http_redirects_to_https": True, "final_url_https": True}
    tls_info.update(info)
    if server is not None:
        tls_info["server"] = server
    ctx = ScanContext("https://ejemplo.es/", final_url="https://ejemplo.es/", tls_info=tls_info)
    return TLSEngine().analyze(ctx)


def ids(server=None, **info):
    return {f.rule_id for f in analyze(server, **info)}


def server_dict(**cert_changes):
    return good_tls(**cert_changes).to_dict()


# --- Motor: configuración correcta ---------------------------------------


def test_configuracion_correcta_solo_suma_tls13():
    findings = analyze(server_dict())
    assert [f.rule_id for f in findings] == ["TLS_V13_SUPPORTED"]
    assert findings[0].category is Category.TLS and findings[0].bonus > 0


def test_sin_https_es_critico():
    findings = analyze(https_available=False, error="Connection refused")
    assert [(f.rule_id, f.severity) for f in findings] == [("TLS_NO_HTTPS", Severity.CRITICAL)]


def test_categoria_no_evaluable_sin_datos_tls():
    assert TLSEngine().is_evaluable(ScanContext("https://ejemplo.es/")) is False


# --- Redirecciones -------------------------------------------------------


def test_http_que_no_redirige_a_https():
    assert "TLS_NO_HTTPS_REDIRECT" in ids(server_dict(), http_redirects_to_https=False)


def test_redireccion_http_no_comprobable_no_penaliza():
    assert "TLS_NO_HTTPS_REDIRECT" not in ids(server_dict(), http_redirects_to_https=None)


def test_https_que_redirige_a_http():
    assert "TLS_REDIRECT_TO_HTTP" in ids(server_dict(), final_url_https=False)


# --- Certificado ---------------------------------------------------------


def test_certificado_caducado():
    s = server_dict(not_after=(NOW - dt.timedelta(days=3)).isoformat())
    assert "TLS_CERT_EXPIRED" in ids(s)


def test_certificado_todavia_no_valido():
    s = server_dict(not_before=(NOW + dt.timedelta(days=3)).isoformat())
    assert "TLS_CERT_NOT_YET_VALID" in ids(s)


def test_certificado_caduca_pronto_es_informativo():
    s = server_dict(not_after=(NOW + dt.timedelta(days=10)).isoformat())
    (f,) = [f for f in analyze(s) if f.rule_id == "TLS_CERT_EXPIRING_SOON"]
    assert f.severity is Severity.INFO


def test_certificado_autofirmado():
    s = server_dict(self_signed=True)
    s["trusted"] = False
    s["verify_code"] = 18
    assert "TLS_CERT_UNTRUSTED" in ids(s)


def test_cadena_no_confiable():
    s = server_dict()
    s["trusted"] = False
    s["verify_code"] = 20
    assert "TLS_CERT_UNTRUSTED" in ids(s)


def test_caducado_no_se_cuenta_ademas_como_no_confiable():
    s = server_dict(not_after=(NOW - dt.timedelta(days=3)).isoformat())
    s["trusted"] = False
    s["verify_code"] = 10  # X509_V_ERR_CERT_HAS_EXPIRED
    found = ids(s)
    assert "TLS_CERT_EXPIRED" in found and "TLS_CERT_UNTRUSTED" not in found


def test_nombre_del_certificado_no_coincide():
    s = server_dict(san_dns=["otro-sitio.es"], subject_cn="otro-sitio.es")
    assert "TLS_CERT_HOSTNAME_MISMATCH" in ids(s)


def test_clave_rsa_corta():
    assert "TLS_WEAK_KEY" in ids(server_dict(key_bits=1024))


def test_firma_sha1():
    assert "TLS_WEAK_SIGNATURE" in ids(server_dict(signature_hash="sha1"))


# --- Versiones -----------------------------------------------------------


def test_tls10_y_tls11_aceptados():
    s = server_dict()
    s["versions"].update({"TLSv1.0": True, "TLSv1.1": True})
    assert {"TLS_V10_ENABLED", "TLS_V11_ENABLED"} <= ids(s)


def test_version_no_comprobable_no_penaliza():
    s = server_dict()
    s["versions"].update({"TLSv1.0": None, "TLSv1.1": None})
    assert not ids(s) & {"TLS_V10_ENABLED", "TLS_V11_ENABLED"}


def test_sin_tls12_ni_tls13():
    s = server_dict()
    s["versions"] = {"TLSv1.0": True, "TLSv1.1": False, "TLSv1.2": False, "TLSv1.3": False}
    assert "TLS_NO_TLS12_OR_13" in ids(s)


# --- Coincidencia de nombres (RFC 6125) ----------------------------------


@pytest.mark.parametrize(
    ("host", "names", "expected"),
    [
        ("ejemplo.es", ["ejemplo.es"], True),
        ("EJEMPLO.es.", ["ejemplo.es"], True),
        ("www.ejemplo.es", ["*.ejemplo.es"], True),
        ("ejemplo.es", ["*.ejemplo.es"], False),
        ("a.b.ejemplo.es", ["*.ejemplo.es"], False),
        ("ejemplo.es", ["otro.es"], False),
        ("ejemplo.es", [], False),
    ],
)
def test_hostname_matches(host, names, expected):
    assert hostname_matches(host, names) is expected


# --- Cliente TLS contra un servidor real local ---------------------------


def make_cert(tmp_path, cn="localhost", days=30, key_bits=2048):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=1))
        .not_valid_after(NOW + dt.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert, cert_file, key_file


@pytest.fixture
def tls_server(tmp_path):
    """Servidor TLS en 127.0.0.1 con certificado autofirmado que solo acepta TLS 1.2+."""
    import socket

    cert, cert_file, key_file = make_cert(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert_file, key_file)
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    stop = threading.Event()

    def serve():
        listener.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            try:
                with ctx.wrap_socket(conn, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield port
    stop.set()
    thread.join(timeout=2)
    listener.close()


def test_inspect_tls_contra_servidor_local(tls_server):
    info = inspect_tls("127.0.0.1", tls_server, timeout=3)
    assert info.trusted is False  # autofirmado
    assert info.certificate.self_signed is True
    assert info.certificate.key_bits == 2048
    assert info.versions["TLSv1.2"] is True
    assert info.versions["TLSv1.0"] in (False, None)  # rechazada o no comprobable
    # El motor lo marca como no confiable y con nombre que no coincide (127.0.0.1)
    found = {
        f.rule_id
        for f in TLSEngine().analyze(
            ScanContext(
                "https://127.0.0.1/", tls_info={"https_available": True, "server": info.to_dict()}
            )
        )
    }
    assert {"TLS_CERT_UNTRUSTED", "TLS_CERT_HOSTNAME_MISMATCH"} <= found


def test_inspect_tls_puerto_cerrado():
    import socket

    with socket.create_server(("127.0.0.1", 0)) as s:
        port = s.getsockname()[1]
    with pytest.raises(TLSError):
        inspect_tls("127.0.0.1", port, timeout=1)


def test_parse_certificate(tmp_path):
    cert, _, _ = make_cert(tmp_path, cn="ejemplo.es", key_bits=2048)
    c = parse_certificate(cert.public_bytes(serialization.Encoding.DER))
    assert c.subject_cn == "ejemplo.es" and c.san_dns == ["ejemplo.es"]
    assert c.key_type == "RSA" and c.signature_hash == "sha256"
    assert asdict(c)["self_signed"] is True
