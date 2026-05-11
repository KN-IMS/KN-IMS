#!/usr/bin/env bash
# setup_agent.sh — Agent 통합 셋업 (Ubuntu 24.04.4 LTS / x86_64).
#   1) Runtime 설치 (eBPF deps + libssl/libsystemd + LSM bpf GRUB 자동 활성화)
#   2) LSM bpf 확인 (미포함이면 재부팅 안내 후 종료 — 재실행 시 이어서 진행)
#   3) cmake 빌드 (Agent/build/agent)
#   4) /etc/ig_monitor 구성 + systemd 등록 + start
#
# 인증서(ca.crt/agent.crt/agent.key)가 Agent/certs/ 에 미리 배치되어 있어야 한다.

set -euo pipefail

# ── 환경별로 직접 수정 ────────────────────────────
BACKEND_HOST="192.168.64.10"
BACKEND_PORT=9000
# ──────────────────────────────────────────────────

log() { printf '[*] %s\n' "$*"; }
die() { printf '[x] %s\n' "$*" >&2; exit 1; }

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
AGENT_DIR="${ROOT_DIR}/Agent"
CERT_SRC="${AGENT_DIR}/certs"
BIN_SRC="${AGENT_DIR}/build/agent"
CONF_SRC="${AGENT_DIR}/configs/ig.conf"
UNIT_SRC="${AGENT_DIR}/integrityguard.service"

# ── 사전 검증 ─────────────────────────────────────
[[ "$(uname -s)" == "Linux" ]]   || die "Linux 전용 — 현재: $(uname -s)"
[[ "$(uname -m)" == "x86_64" ]]  || die "x86_64 전용 — 현재: $(uname -m)"
command -v apt-get >/dev/null    || die "apt-get 필요"
command -v sudo    >/dev/null    || die "sudo 필요"
[[ -x "${AGENT_DIR}/scripts/setup_ebpf_deps.sh" ]] || die "Agent/scripts/setup_ebpf_deps.sh 없음"
[[ -f "${AGENT_DIR}/CMakeLists.txt"             ]] || die "Agent/CMakeLists.txt 없음"

if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "24.04" ]]; then
        log "경고: Ubuntu 24.04를 가정하지만 현재 ${PRETTY_NAME:-unknown}"
    fi
fi

# ── 1. Runtime 설치 ───────────────────────────────
install_runtime() {
    log "eBPF 의존성 설치 (clang/llvm/libbpf/headers + LSM GRUB 활성화)"
    sudo "${AGENT_DIR}/scripts/setup_ebpf_deps.sh"

    log "OpenSSL/libsystemd 헤더 설치"
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
        libssl-dev libsystemd-dev pkg-config
}

# ── 2. LSM bpf 확인 (미포함이면 재부팅 필요) ──────
check_lsm_bpf() {
    if grep -q '\bbpf\b' /sys/kernel/security/lsm 2>/dev/null; then
        log "LSM stack에 bpf 포함 확인"
        return 0
    fi
    cat <<'MSG'

[!] LSM stack에 bpf 미포함.
    setup_ebpf_deps.sh가 /etc/default/grub을 갱신했으니 재부팅 후 이 스크립트를 다시 실행하세요.

      sudo reboot

    재부팅 후에는 이미 설치된 의존성/GRUB 변경은 스킵되고 빌드·init 단계로 이어집니다.
MSG
    exit 0
}

# ── 3. 빌드 ───────────────────────────────────────
build_agent() {
    command -v cmake >/dev/null || die "cmake 없음"
    log "cmake configure + build"
    (
        cd "$AGENT_DIR"
        rm -rf build
        cmake -S . -B build
        cmake --build build -j"$(nproc)"
    )
    [[ -x "$BIN_SRC" ]] || die "agent 바이너리 빌드 실패: $BIN_SRC"
    ls -lh "$BIN_SRC"
}

# ── 4. init (등록 + start) ────────────────────────
init_agent() {
    [[ -f "${CERT_SRC}/ca.crt"    ]] || die "ca.crt 없음 — Server에서 인증서 전달 먼저 (Section 2)"
    [[ -f "${CERT_SRC}/agent.crt" ]] || die "agent.crt 없음"
    [[ -f "${CERT_SRC}/agent.key" ]] || die "agent.key 없음"
    [[ -f "$CONF_SRC"             ]] || die "ig.conf 없음: $CONF_SRC"
    [[ -f "$UNIT_SRC"             ]] || die "integrityguard.service 없음"

    log "/etc/ig_monitor 구성"
    sudo mkdir -p /etc/ig_monitor/certs
    sudo cp "${CERT_SRC}/ca.crt"    /etc/ig_monitor/certs/
    sudo cp "${CERT_SRC}/agent.crt" /etc/ig_monitor/certs/
    sudo cp "${CERT_SRC}/agent.key" /etc/ig_monitor/certs/
    sudo chown -R root:root /etc/ig_monitor
    sudo chmod 644 /etc/ig_monitor/certs/ca.crt /etc/ig_monitor/certs/agent.crt
    sudo chmod 600 /etc/ig_monitor/certs/agent.key

    sudo tee /etc/ig_monitor/ig.env >/dev/null <<EOF
IG_SERVER_HOST=${BACKEND_HOST}
IG_SERVER_PORT=${BACKEND_PORT}
IG_CA_CRT=/etc/ig_monitor/certs/ca.crt
IG_AGENT_CRT=/etc/ig_monitor/certs/agent.crt
IG_AGENT_KEY=/etc/ig_monitor/certs/agent.key
EOF
    sudo chmod 640 /etc/ig_monitor/ig.env

    sudo cp "$CONF_SRC" /etc/ig_monitor/ig.conf
    sudo chmod 640 /etc/ig_monitor/ig.conf

    log "agent 바이너리 설치"
    sudo install -m 755 "$BIN_SRC" /usr/local/bin/agent

    log "systemd 등록 (unit이 /etc/ig_monitor/ig.env를 직접 읽음)"
    sudo cp "$UNIT_SRC" /etc/systemd/system/integrityguard.service
    sudo systemctl daemon-reload
    sudo systemctl enable --now integrityguard.service
    sleep 2
    sudo systemctl is-active integrityguard.service
}

# ── 실행 순서 ─────────────────────────────────────
install_runtime
check_lsm_bpf
build_agent
init_agent

log "Agent setup 완료"
log "  바이너리   : /usr/local/bin/agent"
log "  설정       : /etc/ig_monitor/{ig.env, ig.conf, certs/}"
log "  systemd    : integrityguard.service (active)"
log ""
log "상태 확인:"
log "  sudo systemctl status integrityguard.service"
log "  sudo journalctl -u integrityguard.service -n 30 --no-pager"
