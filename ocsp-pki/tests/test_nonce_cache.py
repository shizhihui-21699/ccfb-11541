#!/usr/bin/env python3
"""程序化校验：nonce 回显、nonce 响应不进缓存、缓存 key 按哈希算法隔离。"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

from ocspca.config import load_config
from ocspca.pki import load_cert
from ocspca.responder import OCSPResponder
from ocspca.store import CertStore

cfg = load_config()
store = CertStore(cfg.store_path)
ca = load_cert(cfg.ca_cert_path)
resp = OCSPResponder(cfg, store)
resp.start()

rec = store.list()[0]
cert = load_cert(Path(rec.pem_path))
cache_before = len(resp.cache_snapshot())

# 1) 带随机 nonce 的请求
nonce = os.urandom(16)
req = (ocsp.OCSPRequestBuilder()
       .add_certificate(cert, ca, hashes.SHA256())
       .add_extension(x509.OCSPNonce(nonce), critical=False)
       .build())
status, der = resp.handle_ocsp_request(
    req.public_bytes(serialization.Encoding.DER))
assert status == 200
parsed = ocsp.load_der_ocsp_response(der)
assert parsed.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL
nonce_ext = parsed.extensions.get_extension_for_class(x509.OCSPNonce)
echo_nonce = nonce_ext.value.nonce
assert echo_nonce == nonce, "nonce 未原样回显"
print("✅ nonce 原样回显，响应状态 successful")

# 2) nonce 响应不得写入预签名缓存
assert len(resp.cache_snapshot()) == cache_before, "nonce 响应污染了缓存"
print("✅ 带 nonce 响应不进预签名缓存（每次实时签名）")

# 3) 无 nonce 请求命中缓存，且 sha1/sha256 是不同条目
req2 = (ocsp.OCSPRequestBuilder()
        .add_certificate(cert, ca, hashes.SHA1()).build())
s2, d2 = resp.handle_ocsp_request(req2.public_bytes(serialization.Encoding.DER))
assert s2 == 200
hits = resp.stats["presigned_hits"]
assert hits >= 1, "无 nonce 请求未命中预签名缓存"
keys = {e["hash"] for e in resp.cache_snapshot() if e["serial_hex"] == rec.serial_hex}
assert keys == {"sha1", "sha256"}, f"缓存哈希算法隔离异常: {keys}"
print(f"✅ 无 nonce 请求命中缓存（presigned_hits={hits}），sha1/sha256 独立缓存")
resp.stop()
print("全部断言通过")
