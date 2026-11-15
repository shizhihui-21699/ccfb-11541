#!/usr/bin/env python3
"""生成一个不存在 serial 的 OCSP 请求（用于 unknown 验收）。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

from ocspca.config import load_config
from ocspca.pki import build_dummy_cert, load_cert

cfg = load_config()
ca = load_cert(cfg.ca_cert_path)
ghost = build_dummy_cert(0xdeadbeefcafe, ca)
req = (ocsp.OCSPRequestBuilder()
       .add_certificate(ghost, ca, hashes.SHA1())
       .build())
out = Path("/tmp/ghost.ocsp-req")
out.write_bytes(req.public_bytes(serialization.Encoding.DER))
print(f"ghost request -> {out} ({out.stat().st_size} bytes)")
