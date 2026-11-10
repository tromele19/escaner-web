"""Genera los certificados del laboratorio (se ejecuta desde setup.sh).

- Una autoridad de certificación propia («Escaner Lab CA») que se instala en
  el almacén de confianza de la Kali, para que los sitios del laboratorio
  tengan un certificado válido como en Internet.
- Un certificado válido para correcto.lab, inseguro.lab, expuesto.lab y
  contenido.lab.
- Un certificado CADUCADO para caducado.lab.

Las claves privadas se quedan en la máquina (lab/certs está en .gitignore).
"""

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).parent / "certs")
VALID_SITES = ["correcto.lab", "inseguro.lab", "expuesto.lab", "contenido.lab"]
NOW = datetime.now(UTC)


def save(name, key, cert):
    (OUT / f"{name}.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (OUT / f"{name}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (OUT / f"{name}.key").chmod(0o600)


def make_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Escaner Lab CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    save("lab-ca", key, cert)
    return key, cert


def make_leaf(name, hosts, ca_key, ca_cert, not_before, not_after):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hosts[0])]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(h) for h in hosts]), False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .sign(ca_key, hashes.SHA256())
    )
    save(name, key, cert)


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    ca_key, ca_cert = make_ca()
    make_leaf(
        "sitios", VALID_SITES, ca_key, ca_cert, NOW - timedelta(days=1), NOW + timedelta(days=397)
    )
    make_leaf(
        "caducado",
        ["caducado.lab"],
        ca_key,
        ca_cert,
        NOW - timedelta(days=400),
        NOW - timedelta(days=5),
    )
    print(f"Certificados generados en {OUT}")
