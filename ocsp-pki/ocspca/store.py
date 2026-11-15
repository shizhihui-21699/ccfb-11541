"""证书状态存储。

store.json 记录每张证书的签发信息、吊销状态、吊销原因以及 CRL 发布序号；
管理 CLI 是唯一写者（fcntl 排他锁 + 原子替换），OCSP 服务只读并按 mtime 热加载。
"""
from __future__ import annotations

import fcntl
import json
import os
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography import x509

# 命令行短名 -> RFC 5280 ReasonFlags
REASON_MAP = {
    "unspecified": x509.ReasonFlags.unspecified,
    "key_compromise": x509.ReasonFlags.key_compromise,
    "ca_compromise": x509.ReasonFlags.ca_compromise,
    "affiliation_changed": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
    "certificate_hold": x509.ReasonFlags.certificate_hold,
    "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
    "aa_compromise": x509.ReasonFlags.aa_compromise,
    # remove_from_crl 不允许人工直接设置，只由 unhold 流程在增量 CRL 中产生
    "remove_from_crl": x509.ReasonFlags.remove_from_crl,
}
REASON_BY_FLAG = {v: k for k, v in REASON_MAP.items()}


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class CertRecord:
    serial_hex: str
    subject: str
    pem_path: str
    key_path: Optional[str] = None
    not_before: str = ""
    not_after: str = ""
    issued_at: str = field(default_factory=utcnow_iso)
    # good / revoked（certificate_hold 也是 revoked，靠 reason 区分）
    status: str = "good"
    revoked_at: Optional[str] = None
    reason: Optional[str] = None
    # 最近一次状态变更被发布到的 CRL 序号；None 表示尚未进任何 CRL（脏记录）
    change_seq: Optional[int] = None
    # 解冻（remove_from_crl）发布序号，用于增量 CRL 判定
    unhold_seq: Optional[int] = None
    unhold_at: Optional[str] = None

    @property
    def serial_int(self) -> int:
        return int(self.serial_hex, 16)

    def to_json(self) -> dict:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict) -> "CertRecord":
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in known})


class CertStore:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()
        self._records: dict[str, CertRecord] = {}
        self._fingerprint: tuple = ()
        self.load()

    def _stat_fp(self) -> tuple:
        st = self.path.stat()
        # mtime + inode + size：os.replace 换文件必改 inode，同秒多次写也能区分
        return (st.st_mtime, st.st_ino, st.st_size)

    # ---------- 持久化 ----------
    def load(self) -> None:
        with self._lock:
            if not self.path.exists():
                self._records, self._fingerprint = {}, ()
                return
            raw = json.loads(self.path.read_text())
            self._records = {
                item["serial_hex"]: CertRecord.from_json(item)
                for item in raw.get("certificates", [])
            }
            self._fingerprint = self._stat_fp()

    def reload_if_changed(self) -> bool:
        """服务端轮询用：外部 CLI 改写后自动热加载，返回是否发生变化。"""
        try:
            fp = self._stat_fp()
        except FileNotFoundError:
            return False
        if fp != self._fingerprint:
            self.load()
            return True
        return False

    def save(self) -> None:
        """CLI 写路径：进程间 fcntl 加锁，tmp 文件原子替换。"""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_suffix(".lock")
        with open(lock_path, "a+") as lk:
            fcntl.flock(lk.fileno(), fcntl.LOCK_EX)
            payload = {
                "version": 1,
                "updated_at": utcnow_iso(),
                "certificates": [r.to_json() for r in self._records.values()],
            }
            tmp = self.path.with_name(self.path.name + ".tmp")
            tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
            os.replace(tmp, self.path)
            self._fingerprint = self._stat_fp()

    # ---------- 查询 ----------
    def list(self) -> list[CertRecord]:
        with self._lock:
            return sorted(self._records.values(), key=lambda r: r.serial_hex)

    def get(self, serial_hex: str) -> Optional[CertRecord]:
        with self._lock:
            return self._records.get(serial_hex.lower())

    def put(self, record: CertRecord) -> None:
        with self._lock:
            self._records[record.serial_hex.lower()] = record

    def serials(self) -> list[str]:
        with self._lock:
            return sorted(self._records.keys())
