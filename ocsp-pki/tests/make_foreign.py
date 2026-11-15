#!/usr/bin/env python3
"""边界验收：构造外部 CA 的请求（wrong issuer）。"""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

from ocspca.config import load_config

cfg = load_config()
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Foreign Rogue CA")])
foreign = (
    x509.CertificateBuilder()
    .subject_name(name).issuer_name(name)
    .public_key(key.public_key())
    .serial_number(0x123456789)
    .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=5))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(key, hashes.SHA256()))
leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
leaf = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "foreign-leaf")]))
    .issuer_name(name).public_key(leaf_key.public_key())
    .serial_number(0xabcdef)
    .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=5))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
    .sign(key, hashes.SHA256()))
req = (ocsp.OCSPRequestBuilder()
       .add_certificate(leaf, foreign, hashes.SHA1()).build())
Path("/tmp/foreign.ocsp-req").write_bytes(
    req.public_bytes(serialization.Encoding.DER))
print("foreign-CA request -> /tmp/foreign.ocsp-req")
