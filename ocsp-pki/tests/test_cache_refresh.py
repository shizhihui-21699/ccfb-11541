#!/usr/bin/env python3
"""验证预签名缓存的后台过期刷新（不依赖真实 4h 等待）。"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ocspca import responder as rmod
from ocspca.config import load_config
from ocspca.store import CertStore

# 缩短时效与轮询，便于测试
rmod.OCSP_TTL_SECONDS = 4
rmod.OCSP_REFRESH_INTERVAL = 1
rmod.STORE_POLL_INTERVAL = 1

cfg = load_config()
store = CertStore(cfg.store_path)
resp = rmod.OCSPResponder(cfg, store)
resp.start()

key = next(iter(resp._cache))
first = resp._cache[key]
print(f"初始 next_update: {first.next_update.isoformat()}")
time.sleep(6)  # 超过 TTL，后台线程应已重签
second = resp._cache[key]
print(f"刷新后 next_update: {second.next_update.isoformat()}")
assert second.next_update > first.next_update, "缓存未在过期前刷新!"
assert second.der != first.der, "响应字节应随重签变化"
print("✅ 后台过期刷新生效：缓存条目在 next_update 前被自动重签")
resp.stop()
