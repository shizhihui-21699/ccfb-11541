"""RFC 6960 OCSP 响应器（HTTP 绑定见 §附录 A.1）。

职责：
- 解析 DER 编码 OCSPRequest（GET base64 / POST raw DER 两种绑定）
- 校验 CertID 的 issuerNameHash / issuerKeyHash 是否指向本 CA
- nonce 扩展（RFC 8954 沿用 RFC 6960 §4.4.1）：请求带 nonce 则原样回显，
  带 nonce 的响应不可缓存，每次实时签名
- 无 nonce 响应走预签名缓存：启动全量预热，后台周期刷新，store 变更后整体重建
- 未知 serial 按 unknown 状态实时应答，不进缓存
- 签名使用委托的 id-kp-OCSPSigning 响应者证书，响应内嵌该证书
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http import HTTPStatus

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from cryptography.x509.ocsp import OCSPCertStatus

from .config import (OCSP_REFRESH_INTERVAL, OCSP_SKEW_GUARD, OCSP_TTL_SECONDS,
                     STORE_POLL_INTERVAL, Config)
from .pki import build_dummy_cert, load_cert, load_private_key
from .store import REASON_MAP, CertRecord, CertStore

OCSP_CONTENT_TYPE = "application/ocsp-response"
OCSP_REQUEST_CONTENT_TYPE = "application/ocsp-request"


@dataclass
class CacheEntry:
    der: bytes
    this_update: datetime
    next_update: datetime
    status: str
    reason: str | None


class OCSPResponder:
    def __init__(self, cfg: Config, store: CertStore):
        self.cfg = cfg
        self.store = store
        self.ca_cert = load_cert(cfg.ca_cert_path)
        self.responder_cert = load_cert(cfg.responder_cert_path)
        self.responder_key = load_private_key(cfg.responder_key_path)

        self._cache: dict[tuple[str, str], CacheEntry] = {}
        self._dummy_cache: dict[int, x509.Certificate] = {}
        self._dummy_lock = threading.Lock()
        self._cache_lock = threading.RLock()

        self.stats = {
            "requests_total": 0,
            "presigned_hits": 0,
            "realtime_signed": 0,
            "nonce_requests": 0,
            "unknown_serials": 0,
            "bad_requests": 0,
            "wrong_issuer": 0,
        }
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ---------------- 签名素材 ----------------
    def _dummy(self, serial: int) -> x509.Certificate:
        with self._dummy_lock:
            cert = self._dummy_cache.get(serial)
            if cert is None:
                cert = build_dummy_cert(serial, self.ca_cert)
                self._dummy_cache[serial] = cert
            return cert

    def _issuer_matches(self, req: ocsp.OCSPRequest) -> bool:
        algo = req.hash_algorithm
        if not isinstance(algo, (hashes.SHA1, hashes.SHA256,
                                 hashes.SHA384, hashes.SHA512)):
            return False
        # 用库自身的 RequestBuilder 生成参考 CertID，保证 nameHash/keyHash
        # 的 DER 截取方式与 RFC 6960 完全一致（keyHash 是 SubjectPublicKey
        # BIT STRING 内容，而非整个 SPKI）。
        ref = (ocsp.OCSPRequestBuilder()
               .add_certificate(self._dummy(req.serial_number),
                                self.ca_cert, algo)
               .build())
        return (ref.issuer_name_hash == req.issuer_name_hash and
                ref.issuer_key_hash == req.issuer_key_hash)

    # ---------------- 响应构造 ----------------
    def _record_status(self, rec: CertRecord | None):
        if rec is None or rec.status != "revoked":
            return OCSPCertStatus.GOOD if rec is not None else OCSPCertStatus.UNKNOWN
        return OCSPCertStatus.REVOKED

    def _build_response(self, serial: int, algo: hashes.HashAlgorithm,
                        nonce: bytes | None,
                        now: datetime | None = None) -> bytes:
        now = now or datetime.now(timezone.utc)
        next_update = now + timedelta(seconds=OCSP_TTL_SECONDS)
        rec = self.store.get(format(serial, "x"))
        cert_for_id = self._dummy(serial)

        builder = ocsp.OCSPResponseBuilder()
        if rec is not None and rec.status == "revoked":
            status = OCSPCertStatus.REVOKED
            rev_time = datetime.fromisoformat(rec.revoked_at) if rec.revoked_at else now
            reason = REASON_MAP[rec.reason] if rec.reason else None
            builder = builder.add_response(
                cert=cert_for_id, issuer=self.ca_cert, algorithm=algo,
                cert_status=status, this_update=now, next_update=next_update,
                revocation_time=rev_time, revocation_reason=reason)
        else:
            status = OCSPCertStatus.GOOD if rec is not None else OCSPCertStatus.UNKNOWN
            builder = builder.add_response(
                cert=cert_for_id, issuer=self.ca_cert, algorithm=algo,
                cert_status=status, this_update=now, next_update=next_update,
                revocation_time=None, revocation_reason=None)

        builder = (builder
                   .responder_id(ocsp.OCSPResponderEncoding.NAME, self.responder_cert)
                   .certificates([self.responder_cert]))
        if nonce is not None:
            builder = builder.add_extension(
                x509.OCSPNonce(nonce), critical=False)
        resp = builder.sign(self.responder_key, hashes.SHA256())
        return resp.public_bytes(serialization.Encoding.DER)

    # ---------------- 预签名缓存 ----------------
    def _cache_key(self, serial_hex: str, algo: hashes.HashAlgorithm) -> tuple[str, str]:
        return (serial_hex.lower(), algo.name)

    def _rebuild_cache(self) -> int:
        """store 变更后整体重建（吊销是低频管理动作，简单正确优于增量修补）。"""
        now = datetime.now(timezone.utc)
        new_cache: dict[tuple[str, str], CacheEntry] = {}
        for rec in self.store.list():
            for algo in (hashes.SHA1(), hashes.SHA256()):
                der = self._build_response(rec.serial_int, algo, None, now)
                new_cache[self._cache_key(rec.serial_hex, algo)] = CacheEntry(
                    der=der, this_update=now,
                    next_update=now + timedelta(seconds=OCSP_TTL_SECONDS),
                    status=rec.status, reason=rec.reason)
        with self._cache_lock:
            self._cache = new_cache
        return len(new_cache)

    def _refresh_expired(self) -> None:
        now = datetime.now(timezone.utc)
        guard = now + timedelta(seconds=OCSP_SKEW_GUARD)
        with self._cache_lock:
            for key, entry in list(self._cache.items()):
                if entry.next_update <= guard:
                    serial_hex, algo_name = key
                    algo = hashes.SHA256() if algo_name == "sha256" else hashes.SHA1()
                    rec = self.store.get(serial_hex)
                    der = self._build_response(int(serial_hex, 16), algo, None, now)
                    self._cache[key] = CacheEntry(
                        der=der, this_update=now,
                        next_update=now + timedelta(seconds=OCSP_TTL_SECONDS),
                        status=rec.status if rec else "unknown",
                        reason=rec.reason if rec else None)

    def _background_loop(self) -> None:
        last_refresh = 0.0
        while not self._stop.is_set():
            time.sleep(STORE_POLL_INTERVAL)
            try:
                # 单一步骤：文件 mtime 变化 → 重新加载 store → 整体重建缓存。
                # reload_if_changed 内部按 path.stat() 判定，返回 True 即内存已是新数据。
                if self.store.reload_if_changed():
                    self._rebuild_cache()
                if time.time() - last_refresh >= OCSP_REFRESH_INTERVAL:
                    self._refresh_expired()
                    last_refresh = time.time()
            except Exception as exc:  # 后台线程绝不能静默死掉
                self.stats["background_errors"] = self.stats.get("background_errors", 0) + 1
                print(f"[ocsp] background loop error: {exc!r}")

    def start(self) -> None:
        self._rebuild_cache()
        self._thread = threading.Thread(
            target=self._background_loop, name="ocsp-refresh", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    # ---------------- 请求入口 ----------------
    def handle_ocsp_request(self, raw: bytes) -> tuple[int, bytes]:
        self.stats["requests_total"] += 1
        try:
            req = ocsp.load_der_ocsp_request(raw)
        except ValueError:
            self.stats["bad_requests"] += 1
            return HTTPStatus.BAD_REQUEST, b"malformed OCSP request"

        if not self._issuer_matches(req):
            # 非本 CA 管辖：RFC 6960 unauthorized 的 HTTP 等价处理
            self.stats["wrong_issuer"] += 1
            return HTTPStatus.NOT_FOUND, b"issuer not served by this responder"

        try:
            nonce_ext = req.extensions.get_extension_for_class(x509.OCSPNonce)
            nonce = nonce_ext.value.nonce
        except x509.ExtensionNotFound:
            nonce = None

        serial = req.serial_number
        algo = req.hash_algorithm

        if nonce is not None:
            # 带 nonce：强制实时签名，不读也不写预签名缓存
            self.stats["nonce_requests"] += 1
            der = self._build_response(serial, algo, nonce)
            self.stats["realtime_signed"] += 1
            return HTTPStatus.OK, der

        key = self._cache_key(format(serial, "x"), algo)
        with self._cache_lock:
            entry = self._cache.get(key)
        if entry is not None and entry.next_update > (
                datetime.now(timezone.utc) + timedelta(seconds=OCSP_SKEW_GUARD)):
            self.stats["presigned_hits"] += 1
            return HTTPStatus.OK, entry.der

        # 缓存未命中：未知 serial（不缓存），或极端情况下的兜底实时签名
        rec = self.store.get(format(serial, "x"))
        if rec is None:
            self.stats["unknown_serials"] += 1
        der = self._build_response(serial, algo, None)
        self.stats["realtime_signed"] += 1
        return HTTPStatus.OK, der

    def cache_snapshot(self) -> list[dict]:
        with self._cache_lock:
            return [
                {
                    "serial_hex": k[0], "hash": k[1],
                    "this_update": e.this_update.isoformat(),
                    "next_update": e.next_update.isoformat(),
                    "status": e.status, "reason": e.reason,
                }
                for k, e in sorted(self._cache.items())
            ]
