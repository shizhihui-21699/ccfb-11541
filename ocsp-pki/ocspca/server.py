"""HTTP 服务：OCSP 绑定、CRL/证书分发、管理 API、管理页面。"""
from __future__ import annotations

import base64
import json
import mimetypes
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import ocsp

from .config import Config
from .crl_publisher import CRLState
from .responder import OCSP_REQUEST_CONTENT_TYPE, OCSP_CONTENT_TYPE, OCSPResponder
from .store import CertStore

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


def _der_serial(cert: x509.Certificate) -> str:
    return format(cert.serial_number, "x")


class PKIHandler(BaseHTTPRequestHandler):
    server_version = "PyOCSP/1.0"

    # 由 ThreadingHTTPServer 注入
    cfg: Config
    responder: OCSPResponder
    store: CertStore
    crl_state: CRLState

    def log_message(self, fmt: str, *args) -> None:  # 简洁日志
        print(f"[{self.log_date_time_string()}] {self.address_string()} {fmt % args}")

    # ---------- 工具 ----------
    def _send(self, status: int, body: bytes,
              content_type: str = "application/octet-stream",
              extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # OCSP 响应明确禁止缓存（RFC 6960 §4.1 对 nonce 的语义；非 nonce 由 nextUpdate 控制）
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, obj, status: int = HTTPStatus.OK) -> None:
        self._send(status, json.dumps(obj, indent=2, ensure_ascii=False).encode(),
                   "application/json; charset=utf-8")

    def _send_file(self, path: Path, content_type: str | None = None) -> None:
        if not path.exists() or not path.is_file():
            self._send(HTTPStatus.NOT_FOUND, b"not found", "text/plain")
            return
        ctype = content_type or mimetypes.guess_type(str(path))[0] or "application/octet-stream"
        self._send(HTTPStatus.OK, path.read_bytes(), ctype)

    # ---------- 路由 ----------
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path, query = parsed.path, parse_qs(parsed.query)
        if path == "/" or path == "/index.html":
            self._send_file(STATIC_DIR / "index.html", "text/html; charset=utf-8")
        elif path.startswith("/static/"):
            self._send_file(STATIC_DIR / path.removeprefix("/static/"))
        elif path == "/health":
            self._send_json({"status": "ok",
                             "time": datetime.now(timezone.utc).isoformat()})
        elif path == "/api/certs":
            self._api_certs(query)
        elif path == "/api/crl":
            self._api_crl()
        elif path == "/api/stats":
            self._send_json({"responder": self.responder.stats,
                             "cache_entries": len(self.responder.cache_snapshot())})
        elif path == "/api/cache":
            self._send_json(self.responder.cache_snapshot())
        elif path == "/ocsp":
            self._ocsp_get(query)
        elif path == "/crl/ca.crl":
            self._send_file(self.cfg.full_crl_der, "application/pkix-crl")
        elif path == "/crl/ca-delta.crl":
            self._send_file(self.cfg.delta_crl_der, "application/pkix-crl")
        elif path == "/crl/ca.crl.pem":
            self._send_file(self.cfg.full_crl_pem, "application/x-pem-file")
        elif path == "/crl/ca-delta.crl.pem":
            self._send_file(self.cfg.delta_crl_pem, "application/x-pem-file")
        elif path == "/certs/ca.cert.pem":
            self._send_file(self.cfg.ca_cert_path, "application/x-pem-file")
        else:
            self._send(HTTPStatus.NOT_FOUND, b"not found", "text/plain")

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/ocsp":
            self._send(HTTPStatus.NOT_FOUND, b"not found", "text/plain")
            return
        ctype = self.headers.get("Content-Type", "")
        if OCSP_REQUEST_CONTENT_TYPE not in ctype:
            self._send(HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                       b"expected application/ocsp-request", "text/plain")
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b""
        status, body = self.responder.handle_ocsp_request(raw)
        self._send(status, body, OCSP_CONTENT_TYPE)

    # ---------- OCSP over GET（RFC 6960 A.1.1）----------
    def _ocsp_get(self, query: dict[str, list[str]]) -> None:
        encoded = query.get("request", [None])[0]
        if not encoded:
            self._send(HTTPStatus.BAD_REQUEST, b"missing request parameter", "text/plain")
            return
        try:
            # RFC 6960 §A.1.1：base64 编码，URL 安全字符，通常不带 padding
            s = (encoded.replace("-", "+").replace("_", "/").strip())
            s += "=" * (-len(s) % 4)
            raw = base64.b64decode(s)
            ocsp.load_der_ocsp_request(raw)
        except Exception:
            self._send(HTTPStatus.BAD_REQUEST, b"invalid request encoding", "text/plain")
            return
        status, body = self.responder.handle_ocsp_request(raw)
        self._send(status, body, OCSP_CONTENT_TYPE)

    # ---------- 管理 API ----------
    def _api_certs(self, query: dict[str, list[str]]) -> None:
        serial = (query.get("serial") or [None])[0]
        if serial:
            rec = self.store.get(serial.lower().removeprefix("0x"))
            if not rec:
                self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                return
            self._send_json(self._cert_detail(rec.serial_hex))
            return
        items = [self._cert_detail(r.serial_hex) for r in self.store.list()]
        self._send_json({"count": len(items), "certificates": items})

    def _cert_detail(self, serial_hex: str) -> dict:
        rec = self.store.get(serial_hex)
        assert rec is not None
        cert_path = Path(rec.pem_path)
        detail = rec.to_json()
        detail["ocsp_status"] = rec.status  # good / revoked
        if cert_path.exists():
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            detail["fingerprint_sha256"] = cert.fingerprint(hashes.SHA256()).hex()
            try:
                san = cert.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName).value
                detail["san"] = san.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                detail["san"] = []
        return detail

    def _api_crl(self) -> None:
        # CLI 可能在服务之外发布 CRL，每次请求重读状态与文件
        st = CRLState(self.cfg.crl_state_path)
        info = {
            "full_seq": st.full_seq,
            "delta_seq": st.delta_seq,
            "last_full_change_seq": st.last_full_change_seq,
            "full_crl_url": self.cfg.full_crl_url,
            "delta_crl_url": self.cfg.delta_crl_url,
        }
        for label, der_path, pem_path in (
                ("full", self.cfg.full_crl_der, self.cfg.full_crl_pem),
                ("delta", self.cfg.delta_crl_der, self.cfg.delta_crl_pem)):
            if der_path.exists():
                crl = x509.load_der_x509_crl(der_path.read_bytes())
                info[label] = {
                    "this_update": crl.last_update_utc.isoformat(),
                    "next_update": crl.next_update_utc.isoformat(),
                    "revoked_count": len(list(crl)),
                    "pem_url": str(pem_path).replace(str(self.cfg.home), ""),
                }
        self._send_json(info)


def build_server(cfg: Config, host: str = "127.0.0.1",
                 port: int = 8080) -> tuple[ThreadingHTTPServer, OCSPResponder]:
    store = CertStore(cfg.store_path)
    crl_state = CRLState(cfg.crl_state_path)
    responder = OCSPResponder(cfg, store)
    responder.start()

    handler = type("BoundHandler", (PKIHandler,), {
        "cfg": cfg, "responder": responder,
        "store": store, "crl_state": crl_state,
    })
    httpd = ThreadingHTTPServer((host, port), handler)
    return httpd, responder
