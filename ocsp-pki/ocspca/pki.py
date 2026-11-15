"""PKI 素材：CA、委托 OCSP 响应者证书、叶子证书的生成与加载。

签名委托模型（RFC 6960 §2.6 / §4.2.2.2.1）：
响应者持独立的 id-kp-OCSPSigning 证书（由本 CA 签发，带 id-pkix-ocsp-nocheck），
OCSP 响应中直接携带该证书，客户端用 CA 证书即可验证响应签名与 EKU 链。
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .config import Config

OCSP_NOCHECK_OID = x509.ObjectIdentifier("1.3.6.1.5.5.7.48.1.5")


def _save_key(key, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    os.chmod(path, 0o600)


def load_private_key(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def _random_serial() -> int:
    # 128 位正整数，最高位清零避免符号问题
    return int.from_bytes(os.urandom(16), "big") & ((1 << 159) - 1) | 1


def _not_before(minus_seconds: int = 120) -> datetime:
    return datetime.now(timezone.utc) - timedelta(seconds=minus_seconds)


def _aia(cfg: Config) -> x509.AuthorityInformationAccess:
    return x509.AuthorityInformationAccess([
        x509.AccessDescription(
            x509.oid.AuthorityInformationAccessOID.OCSP,
            x509.UniformResourceIdentifier(cfg.ocsp_url)),
        x509.AccessDescription(
            x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
            x509.UniformResourceIdentifier(cfg.ca_cert_url)),
    ])


def _full_crl_dp(cfg: Config) -> x509.DistributionPoint:
    return x509.DistributionPoint(
        full_name=[x509.UniformResourceIdentifier(cfg.full_crl_url)],
        relative_name=None, reasons=None, crl_issuer=None)


def _delta_crl_dp(cfg: Config) -> x509.DistributionPoint:
    return x509.DistributionPoint(
        full_name=[x509.UniformResourceIdentifier(cfg.delta_crl_url)],
        relative_name=None, reasons=None, crl_issuer=None)


def _sign_cert(builder: x509.CertificateBuilder, ca_key) -> x509.Certificate:
    return builder.sign(private_key=ca_key, algorithm=hashes.SHA256())


# ---------------- CA ----------------
def build_ca(cfg: Config) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    _save_key(key, cfg.ca_key_path)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Internal"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Example Internal Root CA"),
    ])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(_random_serial())
        .not_valid_before(_not_before())
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, data_encipherment=False,
            key_agreement=False, key_encipherment=False,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                       critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
            key.public_key()), critical=False)
        .add_extension(x509.CRLDistributionPoints([_full_crl_dp(cfg)]),
                       critical=False)
    )
    cert = _sign_cert(builder, key)
    cfg.ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


# ---------------- 委托 OCSP 响应者证书 ----------------
def build_responder(cfg: Config) -> None:
    ca_cert = load_cert(cfg.ca_cert_path)
    ca_key = load_private_key(cfg.ca_key_path)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _save_key(key, cfg.responder_key_path)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Internal"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Example OCSP Responder"),
    ])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(_random_serial())
        .not_valid_before(_not_before())
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False), critical=True)
        # RFC 6960 §4.2.2.2.1：EKU 必须含 id-kp-OCSPSigning
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
                       critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                       critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
            ca_cert.public_key()), critical=False)
        .add_extension(_aia(cfg), critical=False)
        # id-pkix-ocsp-nocheck：告诉客户端不必对响应者证书本身再发 OCSP 查询
        .add_extension(x509.OCSPNoCheck(), critical=False)
    )
    cert = _sign_cert(builder, ca_key)
    cfg.responder_cert_path.write_bytes(
        cert.public_bytes(serialization.Encoding.PEM))


# ---------------- 叶子证书 ----------------
def issue_leaf(cfg: Config, common_name: str) -> tuple[Path, Path]:
    ca_cert = load_cert(cfg.ca_cert_path)
    ca_key = load_private_key(cfg.ca_key_path)
    safe = common_name.replace(" ", "_").replace("*", "wildcard")
    key_path = cfg.certs_dir / f"{safe}.key.pem"
    cert_path = cfg.certs_dir / f"{safe}.cert.pem"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _save_key(key, key_path)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Internal"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(_random_serial())
        .not_valid_before(_not_before())
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=True,
            content_commitment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH,
            ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                       critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
            ca_cert.public_key()), critical=False)
        .add_extension(_aia(cfg), critical=False)
        # RFC 5280 §4.2.1.13：CDP 指向全量 CRL
        .add_extension(x509.CRLDistributionPoints([_full_crl_dp(cfg)]),
                       critical=False)
        # FreshestCRL 指向增量 CRL（非关键）
        .add_extension(x509.FreshestCRL([_delta_crl_dp(cfg)]), critical=False)
    )
    cert = _sign_cert(builder, ca_key)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def build_dummy_cert(serial: int, issuer: x509.Certificate) -> x509.Certificate:
    """构造仅用于填充 OCSP CertID 的占位证书。

    OCSPResponseBuilder.add_response 只取证书的 serial_number 以及
    name/key 哈希所需的 issuer 关系，占位证书不需要真实存在、不会发给客户端。
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = (
        x509.CertificateBuilder()
        .subject_name(issuer.subject)
        .issuer_name(issuer.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(_not_before())
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
    )
    return builder.sign(private_key=key, algorithm=hashes.SHA256())
