#!/usr/bin/env python3
"""PKI 管理 CLI：初始化 CA、签发、吊销、解冻、CRL 发布、启动服务。"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography import x509  # noqa: E402

from ocspca import crl_publisher, pki  # noqa: E402
from ocspca.config import load_config  # noqa: E402
from ocspca.crl_publisher import CRLState  # noqa: E402
from ocspca.server import build_server  # noqa: E402
from ocspca.store import REASON_MAP, CertRecord, CertStore  # noqa: E402


def _load_store(cfg) -> CertStore:
    return CertStore(cfg.store_path)


def _next_change_seq(store: CertStore) -> int:
    seqs = [r.change_seq or 0 for r in store.list()]
    unhold = [r.unhold_seq or 0 for r in store.list()]
    return max(seqs + unhold + [0]) + 1


def cmd_init(args) -> int:
    import shutil
    cfg = load_config(args.home, args.base_url)
    if cfg.ca_cert_path.exists() and not args.force:
        print(f"CA 已存在：{cfg.ca_cert_path}（--force 可覆盖）")
        return 1
    if args.force:
        # 彻底重建：清掉历史证书、CRL、数据库，避免旧序列号污染
        for d in (cfg.certs_dir, cfg.crl_dir, cfg.db_dir, cfg.ca_dir):
            if d.exists():
                shutil.rmtree(d)
        cfg.ensure_dirs()
        (cfg.db_dir / "base_url.txt").write_text(cfg.base_url)
    print("[1/3] 生成根 CA ...")
    pki.build_ca(cfg)
    print("[2/3] 生成委托 OCSP 响应者证书（id-kp-OCSPSigning + nocheck）...")
    pki.build_responder(cfg)
    print("[3/3] 发布初始全量 CRL（空 CRL）...")
    store = _load_store(cfg)
    state = CRLState(cfg.crl_state_path)
    crl_publisher.publish_full(cfg, store, state)
    print(f"完成。home={cfg.home}")
    print(f"  CA 证书     : {cfg.ca_cert_path}")
    print(f"  响应者证书  : {cfg.responder_cert_path}")
    print(f"  全量 CRL    : {cfg.full_crl_der}")
    print(f"  OCSP URL    : {cfg.ocsp_url}")
    return 0


def cmd_issue(args) -> int:
    cfg = load_config(args.home, args.base_url)
    store = _load_store(cfg)
    cert_path, key_path = pki.issue_leaf(cfg, args.cn)
    cert = pki.load_cert(cert_path)
    rec = CertRecord(
        serial_hex=format(cert.serial_number, "x"),
        subject=cert.subject.rfc4514_string(),
        pem_path=str(cert_path),
        key_path=str(key_path),
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=cert.not_valid_after_utc.isoformat(),
    )
    store.put(rec)
    store.save()
    print(f"已签发 CN={args.cn} serial={rec.serial_hex}")
    print(f"  cert={cert_path}\n  key ={key_path}")
    return 0


def _find(store: CertStore, serial_or_cn: str) -> CertRecord | None:
    key = serial_or_cn.lower().removeprefix("0x")
    rec = store.get(key)
    if rec:
        return rec
    for r in store.list():
        try:
            cert = pki.load_cert(Path(r.pem_path))
            cns = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if any(a.value == serial_or_cn for a in cns):
                return r
        except (OSError, ValueError):
            pass
        if serial_or_cn in r.subject:
            return r
    return None


def cmd_revoke(args) -> int:
    if args.reason not in REASON_MAP or args.reason == "remove_from_crl":
        print(f"非法原因：{args.reason}")
        return 2
    cfg = load_config(args.home, args.base_url)
    store = _load_store(cfg)
    rec = _find(store, args.target)
    if not rec:
        print(f"未找到证书：{args.target}")
        return 1
    if rec.status == "revoked":
        print(f"证书已吊销：{rec.serial_hex} reason={rec.reason}")
        return 1
    rec.status = "revoked"
    rec.reason = args.reason
    rec.revoked_at = datetime.now(timezone.utc).isoformat()
    rec.change_seq = _next_change_seq(store)
    # 新吊销未发布；清掉历史解冻标记
    rec.unhold_seq = None
    rec.unhold_at = None
    store.save()
    print(f"已吊销 serial={rec.serial_hex} reason={args.reason} "
          f"change_seq={rec.change_seq}（待发布 CRL）")
    return 0


def cmd_unhold(args) -> int:
    """certificate_hold 解冻（RFC 5280 remove_from_crl）。"""
    cfg = load_config(args.home, args.base_url)
    store = _load_store(cfg)
    rec = _find(store, args.target)
    if not rec:
        print(f"未找到证书：{args.target}")
        return 1
    if not (rec.status == "revoked" and rec.reason == "certificate_hold"):
        print(f"证书不是 certificate_hold 状态，无法解冻："
              f"status={rec.status} reason={rec.reason}")
        return 1
    rec.status = "good"
    rec.reason = None
    rec.revoked_at = None
    rec.unhold_at = datetime.now(timezone.utc).isoformat()
    rec.unhold_seq = _next_change_seq(store)
    store.save()
    print(f"已解冻 serial={rec.serial_hex} unhold_seq={rec.unhold_seq}"
          f"（下次增量 CRL 将带 remove_from_crl）")
    return 0


def cmd_publish_crl(args) -> int:
    cfg = load_config(args.home, args.base_url)
    store = _load_store(cfg)
    state = CRLState(cfg.crl_state_path)
    if args.kind == "full":
        crl = crl_publisher.publish_full(cfg, store, state)
        print(f"全量 CRL 已发布 CRLNumber={state.full_seq} "
              f"条目数={len(list(crl))} -> {cfg.full_crl_der}")
    else:
        crl = crl_publisher.publish_delta(cfg, store, state)
        print(f"增量 CRL 已发布 CRLNumber={state.delta_seq} "
              f"DeltaCRLIndicator={state.full_seq} "
              f"条目数={len(list(crl))} -> {cfg.delta_crl_der}")
    return 0


def cmd_list(args) -> int:
    cfg = load_config(args.home, args.base_url)
    store = _load_store(cfg)
    if not store.list():
        print("（无证书）")
        return 0
    for r in store.list():
        reason = f" reason={r.reason}" if r.reason else ""
        print(f"{r.serial_hex:>34}  {r.status:<7}{reason}  {r.subject}")
    return 0


def cmd_serve(args) -> int:
    cfg = load_config(args.home, args.base_url)
    httpd, responder = build_server(cfg, host=args.host, port=args.port)
    print(f"OCSP/管理服务监听 http://{args.host}:{args.port}")
    print(f"  OCSP      : POST/GET {cfg.ocsp_url}")
    print(f"  管理页面  : http://{args.host}:{args.port}/")
    print(f"  全量 CRL  : {cfg.full_crl_url}")
    print(f"  增量 CRL  : {cfg.delta_crl_url}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n关闭中 ...")
    finally:
        responder.stop()
        httpd.server_close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="内部 PKI / OCSP 管理工具")
    p.add_argument("--home", help="PKI 数据目录（默认 $OCSPCA_HOME 或 ./pki）")
    p.add_argument("--base-url", help="对外基础 URL（写进 AIA/CDP）")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="初始化 CA / 响应者 / 初始 CRL")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("issue", help="签发叶子证书")
    s.add_argument("cn")
    s.set_defaults(func=cmd_issue)

    s = sub.add_parser("revoke", help="吊销证书")
    s.add_argument("target", help="序列号（hex）或 CN 关键字")
    s.add_argument("--reason", default="unspecified",
                   choices=[k for k in REASON_MAP if k != "remove_from_crl"])
    s.set_defaults(func=cmd_revoke)

    s = sub.add_parser("unhold", help="解冻 certificate_hold 证书")
    s.add_argument("target")
    s.set_defaults(func=cmd_unhold)

    s = sub.add_parser("publish-crl", help="发布 CRL")
    s.add_argument("kind", choices=["full", "delta"])
    s.set_defaults(func=cmd_publish_crl)

    s = sub.add_parser("list", help="列出证书状态")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("serve", help="启动 OCSP + 管理 HTTP 服务")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.set_defaults(func=cmd_serve)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
