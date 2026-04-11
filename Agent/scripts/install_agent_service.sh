#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

SERVICE_NAME="fileguard.service"
BINARY_SRC="${AGENT_DIR}/build/agent"
BINARY_DST="/usr/local/bin/agent"
CONFIG_SRC="${AGENT_DIR}/configs/im.conf"
CONFIG_DST="/etc/im_monitor/im.conf"
SERVICE_SRC="${AGENT_DIR}/fileguard.service"
SERVICE_DST="/etc/systemd/system/${SERVICE_NAME}"
LOG_LINES="100"

usage() {
    cat <<'EOF'
Usage:
  ./scripts/install_agent_service.sh [options]

Options:
  --binary-src PATH     Agent binary source path
  --config-src PATH     Agent config source path
  --service-src PATH    systemd unit source path
  --service-name NAME   systemd service name (default: fileguard.service)
  --log-lines N         journal tail line count (default: 100)
  -h, --help            Show help

Behavior:
  - stop existing service if present
  - kill stray agent processes
  - install binary, config, service unit
  - daemon-reload
  - enable and start service again
  - print status and recent journal logs
EOF
}

log() {
    printf '[*] %s\n' "$*"
}

die() {
    printf '[x] %s\n' "$*" >&2
    exit 1
}

require_file() {
    local path="$1"
    [[ -f "$path" ]] || die "파일이 없습니다: ${path}"
}

if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    SUDO=""
else
    command -v sudo >/dev/null 2>&1 || die "sudo 명령이 필요합니다."
    SUDO="sudo"
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary-src)
            BINARY_SRC="${2:-}"
            shift 2
            ;;
        --config-src)
            CONFIG_SRC="${2:-}"
            shift 2
            ;;
        --service-src)
            SERVICE_SRC="${2:-}"
            shift 2
            ;;
        --service-name)
            SERVICE_NAME="${2:-}"
            SERVICE_DST="/etc/systemd/system/${SERVICE_NAME}"
            shift 2
            ;;
        --log-lines)
            LOG_LINES="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "알 수 없는 옵션입니다: $1"
            ;;
    esac
done

require_file "$BINARY_SRC"
require_file "$CONFIG_SRC"
require_file "$SERVICE_SRC"
[[ "$LOG_LINES" =~ ^[0-9]+$ ]] || die "--log-lines 는 숫자여야 합니다: ${LOG_LINES}"

log "기존 service 중지"
${SUDO} systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
${SUDO} systemctl kill --kill-who=all "${SERVICE_NAME}" 2>/dev/null || true

log "남아 있는 agent 프로세스 정리"
${SUDO} pkill -TERM -f "${BINARY_DST}" 2>/dev/null || true
${SUDO} pkill -TERM -f "${BINARY_SRC}" 2>/dev/null || true
sleep 1
${SUDO} pkill -KILL -f "${BINARY_DST}" 2>/dev/null || true
${SUDO} pkill -KILL -f "${BINARY_SRC}" 2>/dev/null || true

log "설치 경로 준비"
${SUDO} mkdir -p /etc/im_monitor

log "binary 설치 -> ${BINARY_DST}"
${SUDO} install -m 0755 "$BINARY_SRC" "$BINARY_DST"

log "config 설치 -> ${CONFIG_DST}"
${SUDO} install -m 0640 "$CONFIG_SRC" "$CONFIG_DST"

log "service 설치 -> ${SERVICE_DST}"
${SUDO} install -m 0644 "$SERVICE_SRC" "$SERVICE_DST"

log "systemd reload"
${SUDO} systemctl daemon-reload
${SUDO} systemctl reset-failed "${SERVICE_NAME}" 2>/dev/null || true

log "service enable/start"
${SUDO} systemctl enable --now "${SERVICE_NAME}"

log "service status"
${SUDO} systemctl status "${SERVICE_NAME}" --no-pager

log "recent journal"
${SUDO} journalctl -u "${SERVICE_NAME}" -n "${LOG_LINES}" --no-pager
