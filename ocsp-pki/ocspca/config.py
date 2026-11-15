"""全局配置：目录布局、发布 URL、缓存与 CRL 时效参数。"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# 缓存策略取舍（详见 README“缓存策略”一节）：
# - OCSP 响应 nextUpdate = 4h，后台每 1h 预签名刷新一次，保证对外响应始终带 >=3h 有效期
# - store.json 每 5s 轮询 mtime，吊销/解冻发生后最多 5s 内缓存整体失效重建
# - 带 nonce 的请求不查缓存，每次实时签名
OCSP_TTL_SECONDS = 4 * 3600
OCSP_REFRESH_INTERVAL = 3600
STORE_POLL_INTERVAL = 5
# 距离 next_update 不足该余量即视为缓存过期，防止时钟偏差导致客户端拒绝
OCSP_SKEW_GUARD = 60

FULL_CRL_TTL_SECONDS = 24 * 3600
DELTA_CRL_TTL_SECONDS = 4 * 3600


@dataclass(frozen=True)
class Config:
    home: Path
    base_url: str = "http://127.0.0.1:8080"

    # ---- 目录 ----
    @property
    def ca_dir(self) -> Path:
        return self.home / "ca"

    @property
    def certs_dir(self) -> Path:
        return self.home / "certs"

    @property
    def crl_dir(self) -> Path:
        return self.home / "crl"

    @property
    def db_dir(self) -> Path:
        return self.home / "db"

    # ---- CA / 委托响应者素材 ----
    @property
    def ca_cert_path(self) -> Path:
        return self.ca_dir / "ca.cert.pem"

    @property
    def ca_key_path(self) -> Path:
        return self.ca_dir / "ca.key.pem"

    @property
    def responder_cert_path(self) -> Path:
        return self.ca_dir / "ocsp-responder.cert.pem"

    @property
    def responder_key_path(self) -> Path:
        return self.ca_dir / "ocsp-responder.key.pem"

    # ---- 数据库 ----
    @property
    def store_path(self) -> Path:
        return self.db_dir / "store.json"

    @property
    def crl_state_path(self) -> Path:
        return self.db_dir / "crl_state.json"

    # ---- CRL 文件（DER 为主，PEM 便于 openssl 验收）----
    @property
    def full_crl_der(self) -> Path:
        return self.crl_dir / "ca.crl"

    @property
    def full_crl_pem(self) -> Path:
        return self.crl_dir / "ca.crl.pem"

    @property
    def delta_crl_der(self) -> Path:
        return self.crl_dir / "ca-delta.crl"

    @property
    def delta_crl_pem(self) -> Path:
        return self.crl_dir / "ca-delta.crl.pem"

    # ---- 对外 URL（写进证书 AIA / CDP / FreshestCRL）----
    @property
    def ocsp_url(self) -> str:
        return f"{self.base_url}/ocsp"

    @property
    def full_crl_url(self) -> str:
        return f"{self.base_url}/crl/ca.crl"

    @property
    def delta_crl_url(self) -> str:
        return f"{self.base_url}/crl/ca-delta.crl"

    @property
    def ca_cert_url(self) -> str:
        return f"{self.base_url}/certs/ca.cert.pem"

    def ensure_dirs(self) -> None:
        for d in (self.ca_dir, self.certs_dir, self.crl_dir, self.db_dir):
            d.mkdir(parents=True, exist_ok=True)


def load_config(home: str | os.PathLike[str] | None = None,
                base_url: str | None = None) -> Config:
    home = Path(home or os.environ.get("OCSPCA_HOME") or Path.cwd() / "pki")
    home = home.resolve()
    # base-url 解析优先级：显式参数 > 环境变量 > home 内持久化的 base_url > 默认值
    persisted: str | None = None
    marker = home / "db" / "base_url.txt"
    if marker.exists():
        persisted = marker.read_text().strip() or None
    url = (base_url or os.environ.get("OCSPCA_BASE_URL")
           or persisted or "http://127.0.0.1:8080")
    cfg = Config(home=home, base_url=url.rstrip("/"))
    cfg.ensure_dirs()
    if base_url:
        marker.write_text(cfg.base_url)
    return cfg
