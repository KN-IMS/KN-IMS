#!/bin/bash
# bench_agent.sh — agent + LKM 오버헤드 측정
#
# 비교 구조:
#   ① 베이스라인  : agent/LKM 없이 파일 오퍼레이션
#   ② agent + LKM : 동일 오퍼레이션 반복
#   → 처리량 감소율 / sy% 증가 / 메모리 증가 비율 출력
#
# 사용법:
#   ./bench_agent.sh --agent <path> --lkm <path> [옵션]
#
# 옵션:
#   --agent <path>    agent 바이너리      (기본: ../build/agent)
#   --conf  <path>    설정 파일           (기본: ../configs/test.conf)
#   --lkm   <path>    im_lkm.ko 경로    (필수)
#   --files <n>       파일 수             (기본: 1000)
#   --out   <path>    결과 파일           (기본: ./bench_result_<ts>.txt)
#
# 판단 기준:
#   처리량 감소율  < 10% 양호 / 10~30% 주의 / > 30% 위험
#   sy% 증가       < 3%p 양호 / 3~10%p 주의  / > 10%p 위험
#   RSS 증가       < 10MB 양호 / 10~50MB 주의 / > 50MB 위험

set -euo pipefail

# ── 기본값 ────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT_BIN="$SCRIPT_DIR/../build/agent"
CONF_FILE="$SCRIPT_DIR/../configs/test.conf"
LKM_KO=""
FILE_COUNT=1000
WATCH_DIR="/tmp/im_bench_$$"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUT_FILE="$SCRIPT_DIR/bench_result_${TIMESTAMP}.txt"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --agent)  AGENT_BIN="$2"; shift 2 ;;
        --conf)   CONF_FILE="$2"; shift 2 ;;
        --lkm)    LKM_KO="$2";   shift 2 ;;
        --files)  FILE_COUNT="$2"; shift 2 ;;
        --out)    OUT_FILE="$2";  shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ -z "$LKM_KO" ]]; then
    echo "ERROR: --lkm <im_lkm.ko> 필수"
    exit 1
fi

# ── 유틸 ──────────────────────────────────────────────────────
log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$OUT_FILE"; }
sep() { printf '%.0s─' {1..50} | tee -a "$OUT_FILE"; echo | tee -a "$OUT_FILE"; }

get_rss_kb() {
    local pid=$1
    grep VmRSS /proc/$pid/status 2>/dev/null | awk '{print $2}' || echo 0
}

# vmstat 1회 샘플 → sy 컬럼 평균 (N초)
sample_sy() {
    local sec=$1
    vmstat 1 "$sec" 2>/dev/null | awk 'NR>2 {sum+=$15; n++} END {printf "%.1f", (n>0 ? sum/n : 0)}'
}

# ── 파일 오퍼레이션 (REPEAT회 반복 평균, ms 반환) ─────────────
REPEAT=3

run_ops() {
    local dir=$1 n=$2

    local result
    result=$(python3 - "$dir" "$n" "$REPEAT" <<'EOF'
import os, sys, time

d, n, repeat = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
buf = b'\x00' * 4096

w_list, r_list, del_list = [], [], []

for _ in range(repeat):
    t0 = time.monotonic()
    for i in range(n):
        with open(os.path.join(d, "f%d" % i), "wb") as f:
            f.write(buf)
    w_list.append(time.monotonic() - t0)

    t0 = time.monotonic()
    for i in range(n):
        os.rename(os.path.join(d, "f%d" % i), os.path.join(d, "r%d" % i))
    r_list.append(time.monotonic() - t0)

    t0 = time.monotonic()
    for i in range(n):
        os.unlink(os.path.join(d, "r%d" % i))
    del_list.append(time.monotonic() - t0)

write_ms  = int(sum(w_list)   / repeat * 1000)
rename_ms = int(sum(r_list)   / repeat * 1000)
delete_ms = int(sum(del_list) / repeat * 1000)

print("%d %d %d" % (write_ms, rename_ms, delete_ms))
EOF
)
    WRITE_MS=$(echo "$result"  | awk '{print $1}')
    RENAME_MS=$(echo "$result" | awk '{print $2}')
    DELETE_MS=$(echo "$result" | awk '{print $3}')
}

# ── 비율 계산 (소수점 1자리, % 단위) ─────────────────────────
pct_change() {
    local base=$1 cur=$2
    awk "BEGIN {if($base==0) print \"N/A\"; else printf \"%.1f\", ($cur-$base)*100/$base}"
}

judge_throughput() {   # 감소율 (음수가 나쁜 것)
    local pct=$1
    awk "BEGIN {
        v=$pct+0
        if (v >= -10) print \"[양호]\";
        else if (v >= -30) print \"[주의]\";
        else print \"[위험]\";
    }"
}

judge_sy() {           # sy% 증가폭
    local diff=$1
    awk "BEGIN {
        v=$diff+0
        if (v < 3)  print \"[양호]\";
        else if (v < 10) print \"[주의]\";
        else print \"[위험]\";
    }"
}

judge_rss() {          # RSS 증가 (KB)
    local diff_kb=$1
    awk "BEGIN {
        v=$diff_kb+0
        if (v < 10240)  print \"[양호]\";
        else if (v < 51200) print \"[주의]\";
        else print \"[위험]\";
    }"
}

# ── cleanup ───────────────────────────────────────────────────
AGENT_PID=""
cleanup() {
    [[ -n "$AGENT_PID" ]] && kill "$AGENT_PID" 2>/dev/null || true
    lsmod | grep -q im_lkm 2>/dev/null && sudo rmmod im_lkm 2>/dev/null || true
    rm -rf "$WATCH_DIR"
    rm -f /tmp/im_bench_$$.conf
}
trap cleanup EXIT

# ══════════════════════════════════════════════════════════════
# ① 베이스라인
# ══════════════════════════════════════════════════════════════
mkdir -p "$WATCH_DIR"
: > "$OUT_FILE"

sep
log "▶ 베이스라인 측정 (agent/LKM 없음, files=$FILE_COUNT, ${REPEAT}회 평균)"
sep

BASE_SY=$(sample_sy 3)
log "  sy% (idle): ${BASE_SY}%"

# 캐시 드롭 — 두 측정을 동일 조건으로 맞춤
sync
echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
log "  페이지 캐시 드롭 완료"

VMSTAT_TMP=$(mktemp)
vmstat 1 30 > "$VMSTAT_TMP" &
VMSTAT_PID=$!

run_ops "$WATCH_DIR" "$FILE_COUNT"
BASE_WRITE_MS=$WRITE_MS
BASE_RENAME_MS=$RENAME_MS
BASE_DELETE_MS=$DELETE_MS

kill "$VMSTAT_PID" 2>/dev/null || true
wait "$VMSTAT_PID" 2>/dev/null || true
BASE_SY_LOAD=$(awk 'NR>2 {sum+=$15; n++} END {printf "%.1f", (n>0 ? sum/n : 0)}' "$VMSTAT_TMP")
rm -f "$VMSTAT_TMP"

log "  write  : ${BASE_WRITE_MS}ms  ($(( FILE_COUNT * 1000 / (BASE_WRITE_MS+1) )) files/sec)"
log "  rename : ${BASE_RENAME_MS}ms  ($(( FILE_COUNT * 1000 / (BASE_RENAME_MS+1) )) files/sec)"
log "  delete : ${BASE_DELETE_MS}ms  ($(( FILE_COUNT * 1000 / (BASE_DELETE_MS+1) )) files/sec)"
log "  sy% (during load): ${BASE_SY_LOAD}%"
BASE_RSS_KB=0

sep

# ══════════════════════════════════════════════════════════════
# ② agent + LKM
# ══════════════════════════════════════════════════════════════
log "▶ LKM 적재: $LKM_KO"
sudo insmod "$LKM_KO"
LKM_SIZE=$(cat /proc/modules | grep "^im_lkm " | awk '{print $2}')
log "  im_lkm 모듈 크기: ${LKM_SIZE} bytes"

# test.conf 의 watch 경로를 WATCH_DIR 로 교체
TMP_CONF="/tmp/im_bench_$$.conf"
sed "s|/tmp/im_test/|$WATCH_DIR/|g" "$CONF_FILE" > "$TMP_CONF"

log "▶ agent 시작: $AGENT_BIN"
"$AGENT_BIN" -c "$TMP_CONF" &
AGENT_PID=$!
sleep 1

if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    log "ERROR: agent 시작 실패"
    exit 1
fi
log "  agent PID: $AGENT_PID"

IDLE_RSS=$(get_rss_kb "$AGENT_PID")
log "  RSS (idle): ${IDLE_RSS}kB"

sep
log "▶ agent + LKM 부하 측정 (files=$FILE_COUNT, ${REPEAT}회 평균)"

# 캐시 드롭 — 베이스라인과 동일 조건
sync
echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
log "  페이지 캐시 드롭 완료"

# vmstat을 파일로 수집 (백그라운드) — wait으로 agent까지 대기하는 버그 방지
VMSTAT_TMP=$(mktemp)
vmstat 1 30 > "$VMSTAT_TMP" &
VMSTAT_PID=$!

run_ops "$WATCH_DIR" "$FILE_COUNT"

kill "$VMSTAT_PID" 2>/dev/null || true
wait "$VMSTAT_PID" 2>/dev/null || true
IM_SY_LOAD=$(awk 'NR>2 {sum+=$15; n++} END {printf "%.1f", (n>0 ? sum/n : 0)}' "$VMSTAT_TMP")
rm -f "$VMSTAT_TMP"

IM_WRITE_MS=$WRITE_MS
IM_RENAME_MS=$RENAME_MS
IM_DELETE_MS=$DELETE_MS
IM_LOAD_RSS=$(get_rss_kb "$AGENT_PID")

log "  write  : ${IM_WRITE_MS}ms  ($(( FILE_COUNT * 1000 / (IM_WRITE_MS+1) )) files/sec)"
log "  rename : ${IM_RENAME_MS}ms  ($(( FILE_COUNT * 1000 / (IM_RENAME_MS+1) )) files/sec)"
log "  delete : ${IM_DELETE_MS}ms  ($(( FILE_COUNT * 1000 / (IM_DELETE_MS+1) )) files/sec)"
log "  sy% (during load): ${IM_SY_LOAD}%"
log "  RSS (load): ${IM_LOAD_RSS}kB"

# ══════════════════════════════════════════════════════════════
# 결과 비교표
# ══════════════════════════════════════════════════════════════
sep
log "▶ 결과 비교 (베이스라인 vs agent+LKM)"
sep

WRITE_PCT=$(pct_change  $BASE_WRITE_MS  $IM_WRITE_MS)
RENAME_PCT=$(pct_change $BASE_RENAME_MS $IM_RENAME_MS)
DELETE_PCT=$(pct_change $BASE_DELETE_MS $IM_DELETE_MS)
SY_DIFF=$(awk "BEGIN {printf \"%.1f\", $IM_SY_LOAD - $BASE_SY_LOAD}")
RSS_DIFF=$(( IM_LOAD_RSS - BASE_RSS_KB ))

printf "%-20s %10s %10s %10s %s\n" \
    "항목" "베이스라인" "im+LKM" "변화율" "판정" | tee -a "$OUT_FILE"
printf "%-20s %10s %10s %10s %s\n" \
    "write (ms)"  "${BASE_WRITE_MS}"  "${IM_WRITE_MS}"  "${WRITE_PCT}%"  "$(judge_throughput $WRITE_PCT)"  | tee -a "$OUT_FILE"
printf "%-20s %10s %10s %10s %s\n" \
    "rename (ms)" "${BASE_RENAME_MS}" "${IM_RENAME_MS}" "${RENAME_PCT}%" "$(judge_throughput $RENAME_PCT)" | tee -a "$OUT_FILE"
printf "%-20s %10s %10s %10s %s\n" \
    "delete (ms)" "${BASE_DELETE_MS}" "${IM_DELETE_MS}" "${DELETE_PCT}%" "$(judge_throughput $DELETE_PCT)" | tee -a "$OUT_FILE"
printf "%-20s %10s %10s %10s %s\n" \
    "sy% (load)"  "${BASE_SY_LOAD}"   "${IM_SY_LOAD}"  "+${SY_DIFF}%p" "$(judge_sy $SY_DIFF)"            | tee -a "$OUT_FILE"
printf "%-20s %10s %10s %10s %s\n" \
    "RSS (kB)"    "0"                 "${IM_LOAD_RSS}" "+${RSS_DIFF}kB" "$(judge_rss $RSS_DIFF)"          | tee -a "$OUT_FILE"
printf "%-20s %10s\n" \
    "im_lkm size" "${LKM_SIZE}B" | tee -a "$OUT_FILE"

sep
log "결과 저장: $OUT_FILE"
