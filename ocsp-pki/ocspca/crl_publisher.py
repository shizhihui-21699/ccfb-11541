"""全量 / 增量 CRL 发布（RFC 5280 §5.2）。

序号模型（crl_state.json）：
- full_seq：最近一次全量 CRL 的 CRLNumber，每次发布全量 +1
- delta_seq：CRL 序号空间里的独立计数器，每次发布增量 +1
- last_full_change_seq：全量 CRL 中包含的最大 change_seq（增量的基准水位）

增量 CRL 的正确性要点：
1. DeltaCRLIndicator（关键扩展）携带其基准全量 CRL 的 CRLNumber；
2. 增量必须包含基准之后所有“仍有效”的吊销（RFC 5280 允许重复包含），
   以及 remove_from_crl（certificate_hold 解冻）记录；
3. 全量 CRL 带 FreshestCRL 指向增量地址；
4. 每次重新发布全量后，脏记录 change_seq 被刷新到新水位，增量重新从空集开始。
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ReasonFlags

from .config import DELTA_CRL_TTL_SECONDS, FULL_CRL_TTL_SECONDS, Config
from .pki import load_cert, load_private_key
from .store import REASON_MAP, CertRecord, CertStore


class CRLState:
    def __init__(self, path: Path):
        self.path = path
        self.full_seq = 0
        self.delta_seq = 0
        self.last_full_change_seq = 0
        self.load()

    def load(self) -> None:
        if self.path.exists():
            data = json.loads(self.path.read_text())
            self.full_seq = data.get("full_seq", 0)
            self.delta_seq = data.get("delta_seq", 0)
            self.last_full_change_seq = data.get("last_full_change_seq", 0)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps({
            "full_seq": self.full_seq,
            "delta_seq": self.delta_seq,
            "last_full_change_seq": self.last_full_change_seq,
        }, indent=2))
        tmp.replace(self.path)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _dp(url: str) -> x509.DistributionPoint:
    return x509.DistributionPoint(
        full_name=[x509.UniformResourceIdentifier(url)],
        relative_name=None, reasons=None, crl_issuer=None)


def _reason(rec: CertRecord) -> ReasonFlags | None:
    if not rec.reason:
        return None
    return REASON_MAP[rec.reason]


def _build_crl(ca_cert, ca_key, entries: list[tuple[CertRecord, datetime]],
               number: int, this_update: datetime, next_update: datetime,
               cfg: Config, is_delta: bool, base_number: int | None) -> x509.CertificateRevocationList:
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(this_update)
    builder = builder.next_update(next_update)

    for rec, rev_time in entries:
        rb = (x509.RevokedCertificateBuilder()
              .serial_number(rec.serial_int)
              .revocation_date(rev_time))
        reason = _reason(rec)
        if reason is not None:
            rb = rb.add_extension(x509.CRLReason(reason), critical=False)
        builder = builder.add_revoked_certificate(rb.build())

    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
        critical=False)
    builder = builder.add_extension(x509.CRLNumber(number), critical=False)

    if is_delta:
        # 关键扩展：引用基准全量 CRL 的 CRLNumber（RFC 5280 §5.2.4）
        assert base_number is not None
        builder = builder.add_extension(
            x509.DeltaCRLIndicator(base_number), critical=True)
        # 增量自身的分发点
        builder = builder.add_extension(
            x509.CRLDistributionPoints([_dp(cfg.delta_crl_url)]),
            critical=False)
    else:
        # 全量 CRL 的分发点 + FreshestCRL 指引客户端取增量
        builder = builder.add_extension(
            x509.CRLDistributionPoints([_dp(cfg.full_crl_url)]),
            critical=False)
        builder = builder.add_extension(
            x509.FreshestCRL([_dp(cfg.delta_crl_url)]), critical=False)

    return builder.sign(private_key=ca_key, algorithm=hashes.SHA256())


def _write_crl(crl: x509.CertificateRevocationList, der_path: Path,
               pem_path: Path) -> None:
    der_path.parent.mkdir(parents=True, exist_ok=True)
    der_path.write_bytes(crl.public_bytes(serialization.Encoding.DER))
    pem_path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))


def _parse_time(value: str | None) -> datetime:
    return datetime.fromisoformat(value) if value else _now()


def publish_full(cfg: Config, store: CertStore,
                 state: CRLState) -> x509.CertificateRevocationList:
    """发布全量 CRL：包含所有当前仍生效的吊销（含 certificate_hold）。"""
    ca_cert = load_cert(cfg.ca_cert_path)
    ca_key = load_private_key(cfg.ca_key_path)

    max_change = state.last_full_change_seq
    entries: list[tuple[CertRecord, datetime]] = []
    for rec in store.list():
        if rec.status == "revoked" and rec.reason != "remove_from_crl":
            entries.append((rec, _parse_time(rec.revoked_at)))
            if (rec.change_seq or 0) > max_change:
                max_change = rec.change_seq or 0

    state.full_seq += 1
    number = state.full_seq
    now = _now()
    crl = _build_crl(
        ca_cert, ca_key, entries, number, now,
        now + timedelta(seconds=FULL_CRL_TTL_SECONDS),
        cfg, is_delta=False, base_number=None)
    _write_crl(crl, cfg.full_crl_der, cfg.full_crl_pem)

    # 全量 CRL 是权威基线：所有记录的水位都推进到当前序号，
    # 待处理的解冻(remove_from_crl)已被全量“隐式确认”为 good，清除其标记，
    # 使后续增量从空集重新累积。
    for rec in store.list():
        rec.change_seq = number
        if rec.unhold_seq:
            rec.unhold_seq = None
            rec.unhold_at = None
    store.save()
    state.last_full_change_seq = max_change if max_change > number else number
    state.save()
    return crl


def publish_delta(cfg: Config, store: CertStore,
                  state: CRLState) -> x509.CertificateRevocationList:
    """发布增量 CRL：基准是 full_seq 对应的最近一次全量。

    入选规则（满足任一）：
    - 记录 change_seq > last_full_change_seq 且当前仍处于吊销状态；
    - 记录带 unhold_seq（解冻/remove_from_crl 尚未并入全量）。
    每次都重复带上基准之后所有有效变更，保证增量可独立校验（RFC 5280 §5.2.4）。
    """
    if state.full_seq == 0:
        raise RuntimeError("必须先发布全量 CRL")

    ca_cert = load_cert(cfg.ca_cert_path)
    ca_key = load_private_key(cfg.ca_key_path)

    base_number = state.full_seq
    watermark = state.last_full_change_seq
    entries: list[tuple[CertRecord, datetime]] = []
    for rec in store.list():
        active_new_revoke = (
            rec.status == "revoked"
            and rec.reason != "remove_from_crl"
            and (rec.change_seq or 0) > watermark
        )
        unhold_pending = bool(rec.unhold_seq and rec.unhold_seq > watermark)
        if active_new_revoke:
            entries.append((rec, _parse_time(rec.revoked_at)))
        elif unhold_pending:
            # 解冻条目以 remove_from_crl 原因进入增量
            shadow = CertRecord(
                serial_hex=rec.serial_hex, subject=rec.subject,
                pem_path=rec.pem_path, status="revoked",
                revoked_at=rec.unhold_at, reason="remove_from_crl")
            entries.append((shadow, _parse_time(rec.unhold_at)))

    state.delta_seq += 1
    number = state.delta_seq
    now = _now()
    crl = _build_crl(
        ca_cert, ca_key, entries, number, now,
        now + timedelta(seconds=DELTA_CRL_TTL_SECONDS),
        cfg, is_delta=True, base_number=base_number)
    _write_crl(crl, cfg.delta_crl_der, cfg.delta_crl_pem)
    state.save()
    return crl
