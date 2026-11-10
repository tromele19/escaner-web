"""Datos TLS simulados para las pruebas (sin conexiones reales)."""

from datetime import UTC, datetime, timedelta

from escaner.acquisition.tls_client import CertInfo, TLSError, TLSInfo


def good_tls(host="ejemplo.es", port=443, **cert_changes) -> TLSInfo:
    now = datetime.now(UTC)
    cert = dict(
        subject_cn=host,
        issuer_cn="R11",
        issuer_org="Let's Encrypt",
        san_dns=[host, f"www.{host}"],
        not_before=(now - timedelta(days=30)).isoformat(),
        not_after=(now + timedelta(days=60)).isoformat(),
        self_signed=False,
        key_type="RSA",
        key_bits=2048,
        signature_hash="sha256",
    )
    cert.update(cert_changes)
    return TLSInfo(
        host=host,
        port=port,
        trusted=True,
        negotiated_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        certificate=CertInfo(**cert),
        versions={"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True},
    )


def fake_inspector(info=None, error=None):
    calls = []

    def inspector(host, port):
        calls.append((host, port))
        if error:
            raise TLSError(error)
        return info or good_tls(host, port)

    inspector.calls = calls
    return inspector
