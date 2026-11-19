"""Certificates for the test lab: a lab CA, and per-site certificates (valid, expired, wrong name, self-signed, expiring)."""
import datetime as dt
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

DIR = Path(__file__).parent / "_certs"


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _write(path, key, cert):
    path.with_suffix(".key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                           serialization.NoEncryption()))
    path.with_suffix(".pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def ca():
    DIR.mkdir(exist_ok=True)
    p = DIR / "ca"
    if p.with_suffix(".pem").exists():
        key = serialization.load_pem_private_key(p.with_suffix(".key").read_bytes(), None)
        return key, x509.load_pem_x509_certificate(p.with_suffix(".pem").read_bytes())
    key = _key()
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(_name("Site Check Lab CA")).issuer_name(_name("Site Check Lab CA"))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False, key_agreement=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    _write(p, key, cert)
    return key, cert


def site_cert(slug, host, kind="good"):
    """kind: good | expired | wrong | self | expiring. Returns (certfile, keyfile)."""
    p = DIR / f"{slug}-{kind}"
    if p.with_suffix(".pem").exists():
        return str(p.with_suffix(".pem")), str(p.with_suffix(".key"))
    ca_key, ca_cert = ca()
    key = _key()
    now = dt.datetime.now(dt.timezone.utc)
    start, end = now - dt.timedelta(days=30), now + dt.timedelta(days=80)
    name = host
    if kind == "expired":
        start, end = now - dt.timedelta(days=120), now - dt.timedelta(days=5)
    if kind == "expiring":
        end = now + dt.timedelta(days=9, hours=12)
    if kind == "renewsoon":
        end = now + dt.timedelta(days=25, hours=12)
    if kind == "wrong":
        name = "other-company.lab.test"
    issuer_key, issuer = (key, _name(name)) if kind == "self" else (ca_key, ca_cert.subject)
    b = (x509.CertificateBuilder().subject_name(_name(name)).issuer_name(issuer).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(end)
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
    if kind != "self":
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
    cert = b.sign(issuer_key, hashes.SHA256())
    _write(p, key, cert)
    return str(p.with_suffix(".pem")), str(p.with_suffix(".key"))


def ca_file():
    ca()
    return str(DIR / "ca.pem")
