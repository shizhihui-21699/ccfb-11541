# 内部 PKI：OCSP 响应器 + 全量/增量 CRL + 管理台

纯 Python（`cryptography` 库，无第三方 Web 框架）实现的内部 PKI 组件，替代“只发几十兆 CRL、客户端全量拉取”的模式：

- **RFC 6960 OCSP 响应器**：实时/预签名应答，支持 nonce、委托响应者证书签名
- **全量 + 增量 CRL（RFC 5280）**：增量 CRL 正确引用基准全量，支持全部吊销原因与 `certificate_hold` 冻结/解冻
- **管理页面**：查证书状态、CRL 序号、预签名缓存、响应统计
- 全程用 `openssl ocsp` / `openssl crl` 验收（见 `tests/acceptance.sh`，21 项断言）

## 目录结构

```
ocsp-pki/
├── ocspca/
│   ├── config.py          # 目录/URL/时效配置，base-url 持久化
│   ├── store.py           # 证书状态存储（JSON + fcntl 锁 + 原子替换 + 指纹热加载）
│   ├── pki.py             # CA、委托 OCSP 响应者证书、叶子证书生成
│   ├── crl_publisher.py   # 全量/增量 CRL 发布与序号水位模型
│   ├── responder.py       # RFC 6960 响应器：nonce、预签名缓存、后台刷新
│   └── server.py          # HTTP：OCSP 绑定、CRL/证书分发、管理 API、页面
├── bin/ca.py              # 管理 CLI
├── static/index.html      # 管理台（原生 JS，深浅色自适应）
├── tests/                 # openssl 验收脚本 + 程序化单测
└── requirements.txt
```

## 快速开始

```bash
python3 -m venv .venv && . .venv/bin/activate   # 或用项目根的 .venv
pip install -r requirements.txt

export OCSPCA_HOME=$PWD/pki
PY=python

# 1. 初始化 CA、委托 OCSP 响应者、初始空全量 CRL
$PY bin/ca.py --base-url http://127.0.0.1:8088 init

# 2. 起服务（OCSP + 管理台 + CRL 分发）
$PY bin/ca.py serve --port 8088
#   管理台     http://127.0.0.1:8088/
#   OCSP       http://127.0.0.1:8088/ocsp
#   全量 CRL   http://127.0.0.1:8088/crl/ca.crl
#   增量 CRL   http://127.0.0.1:8088/crl/ca-delta.crl

# 3. 签发 / 吊销 / 冻结 / 解冻 / 发布 CRL
$PY bin/ca.py issue app.example.com
$PY bin/ca.py revoke app.example.com --reason key_compromise
$PY bin/ca.py publish-crl full
$PY bin/ca.py revoke other.example.com --reason certificate_hold
$PY bin/ca.py publish-crl delta
$PY bin/ca.py unhold other.example.com
$PY bin/ca.py publish-crl delta
```

`--base-url` 只在 `init` 时给一次，会写入 `$OCSPCA_HOME/db/base_url.txt`，后续所有子命令自动读取，保证写进证书 AIA/CDP 的 URL 一致。

## 验收（全部基于 openssl）

```bash
bash tests/acceptance.sh 8088        # 21 项端到端断言
python tests/test_cache_refresh.py   # 预签名缓存后台过期刷新
python tests/test_nonce_cache.py     # nonce 回显与缓存隔离
```

典型手工命令：

```bash
CA=pki/ca/ca.cert.pem
# OCSP 查询（默认带 nonce 实时签名；-no_nonce 走预签名缓存）
openssl ocsp -url http://127.0.0.1:8088/ocsp -issuer $CA -CAfile $CA \
        -cert pki/certs/app.example.com.cert.pem -resp_text
# 全量 / 增量 CRL 解析
openssl crl -in pki/crl/ca.crl.pem       -noout -text
openssl crl -in pki/crl/ca-delta.crl.pem -noout -text
```

## 关键设计

### 1. 签名委托（RFC 6960 §2.6 / §4.2.2.2.1）

CA 不直接签 OCSP，而是签发一张独立的 **OCSP 响应者证书**：

- EKU = `id-kp-OCSPSigning`（critical），KeyUsage 仅 Digital Signature
- 带 `id-pkix-ocsp-nocheck`，客户端不再对响应者证书本身递归做 OCSP
- OCSP 响应内嵌该证书，客户端用 CA 证书即可验证签名与 EKU 链
- 响应者 ID 用 Name 形式（Subject DN）

### 2. 缓存策略（取舍说明）

| 场景 | 策略 | 理由 |
|---|---|---|
| 无 nonce 请求 | **预签名缓存**，按 `(serial, hash算法)` 缓存 DER | 占绝大多数流量；命中即纯内存返回，零签名开销，可抗高 QPS |
| 带 nonce 请求 | **强制实时签名，不读不写缓存** | nonce 的意义就是抗重放，缓存会让其失效 |
| 未知 serial | 实时返回 `unknown`，不缓存 | 未知集合无界，缓存无收益且易被打满 |
| 缓存时效 | `nextUpdate = 4h`，后台每 1h 巡检，临近过期（含 60s 时钟余量）自动重签 | 对外响应始终带 ≥3h 有效期，避免客户端因时钟偏差拒绝 |
| 吊销生效 | store 文件 `mtime+inode+size` 指纹每 5s 轮询，变更后整体重建缓存 | 吊销是低频管理动作；整体重建简单正确，避免增量修补的状态机 bug。最坏 5s 生效，对内部 PKI 可接受 |
| 哈希算法 | sha1 / sha256 两套 CertID 各缓存一份 | 兼容默认 sha1 的老客户端与要求 sha256 的新客户端 |

**为什么不用“每次请求实时签名”**：RSA 2048 签名 CPU 成本不低，高并发下响应器会成为瓶颈，且无 nonce 的可缓存响应本就是 RFC 6960 允许且推荐的做法。
**为什么不用更长 TTL**：TTL 越长，吊销后客户端可能继续信任的窗口越大；4h + 5s 缓存重建是“性能”与“吊销及时性”的折中。需要更强及时性时，可把 `STORE_POLL_INTERVAL` 调小，或改为文件变更事件触发。

### 3. 全量 / 增量 CRL 序号模型

状态保存在 `db/crl_state.json`：

- `full_seq`：全量 CRL 的 CRLNumber，每次发全量 +1
- `delta_seq`：增量 CRL 的独立 CRLNumber，每次发增量 +1
- `last_full_change_seq`：全量已覆盖的最大变更水位

正确性要点（RFC 5280 §5.2.4）：

1. 增量 CRL 带 **critical `DeltaCRLIndicator`**，值 = 基准全量的 CRLNumber；
2. 全量 CRL 带 `FreshestCRL` 指向增量 URL；叶子证书的 CDP 指全量、FreshestCRL 指增量；
3. 增量重复包含基准之后所有仍有效变更（不依赖客户端已看过上一份增量）；
4. **冻结/解冻**：`certificate_hold` 是带 hold 原因的 revoked；解冻时记录状态回 good，并在增量里发 `remove_from_crl` 条目；
5. **基准重置**：重发全量后，所有记录水位推进、`unhold` 标记清除，增量从空集重新开始，避免 remove_from_crl 残留。

### 4. 存储与并发

- 管理 CLI 是唯一写者：`fcntl` 排他锁 + tmp 文件 `os.replace` 原子替换
- OCSP 服务只读，按文件指纹热加载，无需停机即可让吊销生效
- HTTP 用标准库 `ThreadingHTTPServer`，OCSP 签名在请求线程内完成（nonce）或直接返回缓存字节

## 支持的吊销原因

`unspecified / key_compromise / ca_compromise / affiliation_changed /
superseded / cessation_of_operation / certificate_hold / privilege_withdrawn /
aa_compromise`，外加解冻流程内部使用的 `remove_from_crl`。

## 生产化建议（当前未含）

- 前置 Nginx/负载均衡做 TLS 与多实例；多实例共享同一存储卷或换成数据库
- 响应者私钥接入 HSM/KMS，而不是落盘 PEM
- 管理 API 加认证（mTLS 或 token），当前默认只监听 127.0.0.1
- CRL/OCSP 时效按合规要求调整；增加 Prometheus 指标与告警
