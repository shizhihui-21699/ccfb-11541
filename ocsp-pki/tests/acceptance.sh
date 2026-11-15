#!/usr/bin/env bash
# 端到端验收：OCSP（RFC 6960）+ 全量/增量 CRL，全部用 openssl 断言。
# 用法：tests/acceptance.sh [port]
set -euo pipefail

PORT="${1:-8088}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="$ROOT/../.venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"
export OCSPCA_HOME="$ROOT/pki"
BASE="http://127.0.0.1:$PORT"
CA="$OCSPCA_HOME/ca/ca.cert.pem"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0; fail=0
check() { # check <描述> <条件命令...>
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "  ✅ $desc"; pass=$((pass+1));
  else echo "  ❌ $desc"; fail=$((fail+1)); fi
}
# ocsp_q <cert> <输出文件> [extra openssl args...]
# 注意：openssl 4.x 要求 -sha256 等摘要参数出现在 -cert 之前，这里统一前置。
ocsp_q() {
  local cert="$1" out="$2"; shift 2
  local pre=() post=()
  for a in "$@"; do
    case "$a" in -sha1|-sha256|-sha384|-sha512) pre+=("$a");; *) post+=("$a");; esac
  done
  openssl ocsp ${pre[@]+"${pre[@]}"} -url "$BASE/ocsp" -issuer "$CA" -CAfile "$CA" \
    ${post[@]+"${post[@]}"} -cert "$cert" >"$out" 2>&1
}

echo "== 重建干净环境 =="
"$PY" -I "$ROOT/bin/ca.py" --base-url "$BASE" init --force >/dev/null
"$PY" -I "$ROOT/bin/ca.py" issue good.example.com   >/dev/null
"$PY" -I "$ROOT/bin/ca.py" issue hold.example.com   >/dev/null
"$PY" -I "$ROOT/bin/ca.py" issue revoke.example.com >/dev/null
GOOD="$OCSPCA_HOME/certs/good.example.com.cert.pem"
HOLD="$OCSPCA_HOME/certs/hold.example.com.cert.pem"
REV="$OCSPCA_HOME/certs/revoke.example.com.cert.pem"

# 起服务（若端口已有实例则复用）
SRV=""
if ! curl -sf "$BASE/health" >/dev/null; then
  nohup "$PY" -I "$ROOT/bin/ca.py" serve --port "$PORT" >/tmp/ocsp-accept.log 2>&1 &
  SRV=$!
  for _ in $(seq 1 40); do curl -sf "$BASE/health" >/dev/null 2>&1 && break; sleep 0.5; done
fi
curl -sf "$BASE/health" >/dev/null || { echo "服务启动失败"; cat /tmp/ocsp-accept.log; exit 1; }

echo "== 1. OCSP good / nonce / 缓存 =="
ocsp_q "$GOOD" "$TMP/g1" -no_nonce
check "good 证书返回 good(no_nonce,预签名缓存)" grep -q ": good" "$TMP/g1"
ocsp_q "$GOOD" "$TMP/g2"
check "good 证书返回 good(默认带 nonce,实时签名)" grep -q ": good" "$TMP/g2"
check "响应签名由委托响应者证书验证通过" grep -q "Response verify OK" "$TMP/g1"
ocsp_q "$GOOD" "$TMP/g3" -resp_text
check "nonce 请求回显 nonce" grep -qi "OCSP Nonce" "$TMP/g3"
ocsp_q "$GOOD" "$TMP/g4" -sha256 -no_nonce
check "SHA-256 CertID 正常" grep -q ": good" "$TMP/g4"
check "统计中预签名命中计数增长" bash -c "curl -s $BASE/api/stats | grep -q '\"presigned_hits\": [1-9]'"

echo "== 2. 吊销原因实时反映（OCSP）=="
"$PY" -I "$ROOT/bin/ca.py" revoke revoke.example.com --reason key_compromise >/dev/null
sleep 9   # 等待 store 指纹轮询(5s)+重建
ocsp_q "$REV" "$TMP/r1" -no_nonce
check "key_compromise 吊销后 OCSP=revoked" grep -q ": revoked" "$TMP/r1"
ocsp_q "$REV" "$TMP/r2" -no_nonce -resp_text
check "OCSP 回传 revocationReason=keyCompromise" grep -qi "keyCompromise" "$TMP/r2"

echo "== 3. 全量 CRL =="
"$PY" -I "$ROOT/bin/ca.py" publish-crl full >/dev/null
check "全量 CRL 含吊销原因 Key Compromise" bash -c "openssl crl -in '$OCSPCA_HOME/crl/ca.crl.pem' -noout -text | grep -qi 'Key Compromise'"
check "全量 CRL 带 FreshestCRL 指向增量" bash -c "openssl crl -in '$OCSPCA_HOME/crl/ca.crl.pem' -noout -text | grep -q 'ca-delta.crl'"
FULL_NUM=$(openssl crl -in "$OCSPCA_HOME/crl/ca.crl.pem" -noout -text | awk '/CRL Number/{getline; print $1}' | tr -d ' ')
echo "    全量 CRLNumber=$FULL_NUM"

echo "== 4. 冻结(certificate_hold) + 增量 CRL =="
"$PY" -I "$ROOT/bin/ca.py" revoke hold.example.com --reason certificate_hold >/dev/null
"$PY" -I "$ROOT/bin/ca.py" publish-crl delta >/dev/null
check "增量带 critical DeltaCRLIndicator" bash -c "openssl crl -in '$OCSPCA_HOME/crl/ca-delta.crl.pem' -noout -text | grep -qi 'Delta CRL Indicator: critical'"
check "DeltaCRLIndicator 引用基准全量 CRLNumber=$FULL_NUM" bash -c "openssl crl -in '$OCSPCA_HOME/crl/ca-delta.crl.pem' -noout -text | grep -A1 'Delta CRL' | grep -q '$FULL_NUM'"
check "增量含 Certificate Hold 条目" bash -c "openssl crl -in '$OCSPCA_HOME/crl/ca-delta.crl.pem' -noout -text | grep -qi 'Certificate Hold'"
sleep 9
ocsp_q "$HOLD" "$TMP/h1" -no_nonce
check "冻结状态 OCSP=revoked" grep -q ": revoked" "$TMP/h1"

echo "== 5. 解冻(remove_from_crl) =="
HOLD_SERIAL=$("$PY" -I "$ROOT/bin/ca.py" list | awk '/hold.example.com/{print $1}')
"$PY" -I "$ROOT/bin/ca.py" unhold "$HOLD_SERIAL" >/dev/null
"$PY" -I "$ROOT/bin/ca.py" publish-crl delta >/dev/null
check "新增量含 Remove From CRL" bash -c "openssl crl -in '$OCSPCA_HOME/crl/ca-delta.crl.pem' -noout -text | grep -qi 'Remove From CRL'"
sleep 9
ocsp_q "$HOLD" "$TMP/h2" -no_nonce
check "解冻后 OCSP 恢复 good" grep -q ": good" "$TMP/h2"

echo "== 6. 全量重发后基准重置 =="
"$PY" -I "$ROOT/bin/ca.py" publish-crl full >/dev/null
"$PY" -I "$ROOT/bin/ca.py" publish-crl delta >/dev/null
# 空增量：Revoked Certificates 段落下没有任何 Serial Number
check "重置后增量无吊销条目" bash -c "[ \"\$(openssl crl -in '$OCSPCA_HOME/crl/ca-delta.crl.pem' -noout -text | grep -c 'Serial Number')\" -eq 0 ]"

echo "== 7. 边界：unknown / 错误 issuer / 畸形请求 / GET 绑定 =="
"$PY" -I "$ROOT/tests/make_ghost.py" >/dev/null
curl -s -X POST --data-binary @/tmp/ghost.ocsp-req -H "Content-Type: application/ocsp-request" "$BASE/ocsp" -o "$TMP/g.resp"
check "未知 serial 返回 unknown" bash -c "openssl ocsp -respin '$TMP/g.resp' -resp_text -CAfile '$CA' 2>&1 | grep -qi 'Cert Status: unknown'"
"$PY" -I "$ROOT/tests/make_foreign.py" >/dev/null
check "外部 CA 请求被拒(HTTP 404)" bash -c "test \"\$(curl -s -o /dev/null -w '%{http_code}' -X POST --data-binary @/tmp/foreign.ocsp-req -H 'Content-Type: application/ocsp-request' $BASE/ocsp)\" = 404"
check "畸形请求返回 400" bash -c "test \"\$(printf 'junk' | curl -s -o /dev/null -w '%{http_code}' -X POST --data-binary @- -H 'Content-Type: application/ocsp-request' $BASE/ocsp)\" = 400"
B64=$(openssl base64 -A </tmp/ghost.ocsp-req | tr '+/' '-_' | tr -d '=')
curl -s "$BASE/ocsp?request=$B64" -o "$TMP/gg.resp"
check "GET 绑定(RFC6960 A.1.1)返回可解析响应" bash -c "openssl ocsp -respin '$TMP/gg.resp' -resp_text -CAfile '$CA' 2>&1 | grep -qi 'unknown'"

echo
echo "结果：PASS=$pass FAIL=$fail"
[ -n "$SRV" ] && kill "$SRV" 2>/dev/null || true
[ "$fail" -eq 0 ]
